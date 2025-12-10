#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define LISTEN_PORT_COMMAND 5000 //random number > 1024
#define SERVER_DATA_PORT = LISTEN_PORT_COMMAND + 1
#define BACKLOG 5 //number of clients that can be waiting at the same time
#define MAX_CMD_LEN 1024
#define LOG_FILE "server.log"

// Global log file pointer
FILE *log_fp = NULL;

void initialize_server_address(struct sockaddr_in* server_address);
ssize_t recv_line(int fd, SSL* ssl, char *buf, size_t max_len);
void handle_client(int client_fd, SSL* ssl);
void server_log(const char *format, ...);
int is_path_safe(const char *path);


// Global SSL context for data connections
SSL_CTX *data_ctx = NULL;

int main(void)
{
    // Ignore SIGPIPE to prevent crash when writing to closed sockets
    signal(SIGPIPE, SIG_IGN);
    
    // Open log file
    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp)
    {
        perror("Could not open log file");
        log_fp = stderr; // Fall back to stderr
    }
    server_log("Server started");
    printf("Server started\n");
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *server_ctx = SSL_CTX_new(method);
    if (!server_ctx)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_certificate_file(server_ctx, "../server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(server_ctx, "../server.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(server_ctx))
    {
        fprintf(stderr, "Private key does not match the public key\n");
        exit(EXIT_FAILURE);
    }
    
    // Create SSL context for data connections (uses same certs)
    data_ctx = SSL_CTX_new(TLS_server_method());
    if (!data_ctx)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_certificate_file(data_ctx, "../server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(data_ctx, "../server.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    //AF_INET = IPv4
    //SOCK_STREAM = TCP
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_address;
    if (listen_fd < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    printf("Server socket created, fd = %d\n", listen_fd);
    initialize_server_address(&server_address);
    const struct sockaddr* const_server_address = (const struct sockaddr*) &server_address;
    //bind attaches socket to local ip address and port
    if (bind(listen_fd, const_server_address, sizeof(server_address)) < 0)
    {
        perror("bind");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }
    printf("Bound to port %d\n", LISTEN_PORT_COMMAND);
    //listen() tells the socket to listen to clients
    if (listen(listen_fd, BACKLOG) < 0)
    {
        perror("listen");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }
    printf("Server listening to port %d\n", LISTEN_PORT_COMMAND);

    // Signal handler to reap zombie child processes
    signal(SIGCHLD, SIG_IGN);

    while (1)
    {
        struct sockaddr_in client_address;
        socklen_t client_len = sizeof(client_address);
        struct sockaddr* generic_client_address = (struct sockaddr*) &client_address;
        int client_fd = accept(listen_fd, generic_client_address, &client_len);
        if (client_fd < 0)
        {
            perror("accept");
            continue;  // Don't exit, just continue accepting
        }
        printf("Client connected, fd = %d\n", client_fd);
        
        // Fork a child process to handle this client
        pid_t pid = fork();
        if (pid < 0)
        {
            perror("fork");
            close(client_fd);
            continue;
        }
        
        if (pid == 0)
        {
            // Child process - handle the client
            close(listen_fd);  // Child doesn't need the listening socket
            
            SSL *ssl = SSL_new(server_ctx);
            if (!ssl)
            {
                fprintf(stderr, "SSL_new failed\n");
                close(client_fd);
                exit(EXIT_FAILURE);
            }
            if (!SSL_set_fd(ssl, client_fd))
            {
                fprintf(stderr, "SSL_set_fd failed\n");
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                close(client_fd);
                exit(EXIT_FAILURE);
            }
            // TLS handshake
            if (SSL_accept(ssl) <= 0)
            {
                fprintf(stderr, "SSL_accept failed\n");
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                close(client_fd);
                exit(EXIT_FAILURE);
            }
            printf("TLS handshake completed (server, pid=%d)\n", getpid());
            handle_client(client_fd, ssl);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
            printf("Client disconnected, fd = %d (pid=%d)\n", client_fd, getpid());
            exit(EXIT_SUCCESS);  // Child exits after handling client
        }
        else
        {
            // Parent process - close client fd and continue accepting
            close(client_fd);
            printf("Spawned child process %d for client\n", pid);
        }
    }

    close(listen_fd);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(data_ctx);
    return 0;
}

void initialize_server_address(struct sockaddr_in* server_address)
{
    memset(server_address, 0, sizeof(*server_address));
    //AF_INET refers to ipv4
    server_address->sin_family = AF_INET;
    //INADDR_ANY means any local IP address
    server_address->sin_addr.s_addr = htonl(INADDR_ANY);
    server_address->sin_port = htons(LISTEN_PORT_COMMAND);
}

// Logging function with timestamp
#include <stdarg.h>
void server_log(const char *format, ...)
{
    if (!log_fp) return;
    
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);
    
    fprintf(log_fp, "[%s] ", timestamp);
    
    va_list args;
    va_start(args, format);
    vfprintf(log_fp, format, args);
    va_end(args);
    
    fprintf(log_fp, "\n");
    fflush(log_fp);
}

// Path traversal protection - blocks ".." and absolute paths
int is_path_safe(const char *path)
{
    if (path == NULL) return 0;
    if (strlen(path) == 0) return 0;
    if (path[0] == '/') return 0;           // Block absolute paths
    if (strstr(path, "..") != NULL) return 0; // Block parent directory traversal
    return 1;
}

ssize_t recv_line(int fd, SSL* ssl, char *buf, size_t max_len)
{
    size_t i = 0;
    while (i < max_len-1)
    {
        char c;
        ssize_t n = SSL_read(ssl, &c, 1);
        if (n < 0)
        {
            if (errno == EINTR){
                continue;
            }
            perror("recv");
            return -1;
        }
        if (n == 0)
        {
            if (i == 0)
            {
                return 0; //connection closed, no data read
            }
            break; //connection closed
        }
        if (c == '\n')
        {
            break;
        }
        buf[i++] = c;
    }
    buf[i] = '\0';
    return (ssize_t)i;
}

void handle_client(int client_fd, SSL *ssl)
{
    char cmd[MAX_CMD_LEN];
    int authenticated = 0;  // Track if user is logged in
    char username[64] = "";  // Store logged-in username
    
    server_log("Client connected, fd=%d", client_fd);
    
    // Send welcome message to client
    const char *welcome = "Welcome to FTP Server (use AUTH <user> <pass> to login)\n";
    SSL_write(ssl, welcome, strlen(welcome));
    
    while (1)
    {
        ssize_t n = recv_line(client_fd, ssl, cmd, MAX_CMD_LEN);
        if (n <= 0)
        {
            if (n == 0)
            {
                printf("Connection closed by client\n");
                server_log("Connection closed by client");
            }
            break; //connection closed or error
        }
        
        char* command = strtok(cmd, " \n");
        char* argument_one = strtok(NULL, " \n");
        char* argument_two = strtok(NULL, " \n");
        
        if (command == NULL)
        {
            // Empty command, skip
            continue;
        }

        printf("Received command: %s\n", cmd);
        server_log("Command: %s %s %s", command, argument_one ? argument_one : "", argument_two ? argument_two : "");
        if (strcmp(command, "PING") == 0)
        {
            const char *resp = "PONG\n";
            SSL_write(ssl, resp, strlen(resp));
        }
        else if (strcmp(command, "QUIT") == 0)
        {
            const char * resp = "Goodbye!\n";
            SSL_write(ssl, resp, strlen(resp));
            printf("Closing connection on client request\n");
            server_log("Client requested disconnect");
            break;
        }
        else if (strcmp(command, "AUTH") == 0)
        {
            // Simple hardcoded auth for testing
            // TODO: Replace with proper user database
            if (argument_one && argument_two &&
                strcmp(argument_one, "admin") == 0 &&
                strcmp(argument_two, "password") == 0)
            {
                authenticated = 1;
                strncpy(username, argument_one, sizeof(username) - 1);
                username[sizeof(username) - 1] = '\0';
                const char *resp = "AUTH OK - You now have full access\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("AUTH OK for user: %s", argument_one);
            }
            else
            {
                authenticated = 0;
                username[0] = '\0';
                const char *resp = "AUTH FAILED\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("AUTH FAILED for user: %s", argument_one ? argument_one : "NULL");
            }
        }
        else if (strcmp(command, "LOGOUT") == 0)
        {
            if (authenticated)
            {
                server_log("User %s logged out", username);
                authenticated = 0;
                username[0] = '\0';
                const char *resp = "LOGOUT OK - You now have read-only access\n";
                SSL_write(ssl, resp, strlen(resp));
            }
            else
            {
                const char *resp = "You are not logged in\n";
                SSL_write(ssl, resp, strlen(resp));
            }
        }
        else if (strcmp(command, "WHOAMI") == 0)
        {
            char resp[128];
            if (authenticated)
            {
                snprintf(resp, sizeof(resp), "Logged in as: %s\n", username);
            }
            else
            {
                snprintf(resp, sizeof(resp), "Not logged in (read-only access)\n");
            }
            SSL_write(ssl, resp, strlen(resp));
        }
        else if (strcmp(command, "HELP") == 0)
        {
            const char *help_msg = 
                "Available commands:\n"
                "  PING              - Test connection\n"
                "  AUTH <user> <pass>- Login for write access\n"
                "  LOGOUT            - Logout\n"
                "  WHOAMI            - Show current user\n"
                "  LIST [dir]        - List directory contents\n"
                "  PWD               - Print working directory\n"
                "  GET <file>        - Download file\n"
                "  PUT <file> [dest] - Upload file (requires login)\n"
                "  CWD <dir>         - Change directory (requires login)\n"
                "  DELE <file>       - Delete file (requires login)\n"
                "  MKDIR <dir>       - Create directory (requires login)\n"
                "  RMDIR <dir>       - Remove directory (requires login)\n"
                "  QUIT              - Disconnect\n"
                "  HELP              - Show this help\n";
            SSL_write(ssl, help_msg, strlen(help_msg));
        }
        else if (strcmp(command, "GET") == 0)
        {
            // Check for required argument
            if (!argument_one)
            {
                const char *resp = "ERROR: GET requires filename\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("GET failed - missing filename");
                continue;
            }
            
            // Path safety check
            if (!is_path_safe(argument_one))
            {
                const char *resp = "ERROR: Invalid path\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("GET blocked - unsafe path: %s", argument_one ? argument_one : "NULL");
                continue;
            }
            

            FILE* file_added = fopen(argument_one, "rb");
            if (!file_added)
            {
                const char *resp = "ERROR: File not found\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("GET failed - file not found: %s", argument_one);
                continue;
            }
            //fseek and ftell used here to determine file size
            fseek(file_added, 0, SEEK_END);
            long file_size = ftell(file_added);
            fseek(file_added, 0, SEEK_SET);

            //OPEN DATA CHANNEL
            int data_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (data_listen_fd < 0)
            {
                perror("socket(data) not opened");
                fclose(file_added);
                continue;
            }

            struct sockaddr_in data_address;
            initialize_server_address(&data_address);
            data_address.sin_port=htons(0);
            
            const struct sockaddr *const_data_address = 
                (const struct  sockaddr *)&data_address;
            
            if ((bind(data_listen_fd, const_data_address, sizeof(data_address)) < 0))
            {
                perror("bind(data) failed");
                close(data_listen_fd);
                fclose(file_added);
                continue;
            }

            if (listen(data_listen_fd, 1) < 0)
            {
                perror("listening failed (data)");
                close(data_listen_fd);
                fclose(file_added);
                continue;
            }
            socklen_t addrlen = sizeof(data_address);
            if ((getsockname(data_listen_fd,(struct sockaddr *) &data_address,&addrlen) < 0))
            {
                perror("getsockname(data)");
                close(data_listen_fd);
                fclose(file_added);
                continue;
            }

            int assigned_port = ntohs(data_address.sin_port);
            char header[256];
            snprintf(header, sizeof(header), "DATA %d %s %ld\n", assigned_port, argument_one, file_size);
            SSL_write(ssl, header, strlen(header));

            int data_fd = accept(data_listen_fd, NULL, NULL);
            if ((data_fd < 0))
            {
                perror("accept(data)");
                close(data_listen_fd);
                fclose(file_added);
                continue;
            }
            close(data_listen_fd);
            
            // Set up TLS on data channel
            SSL *data_ssl = SSL_new(data_ctx);
            if (!data_ssl)
            {
                fprintf(stderr, "SSL_new failed for data channel\n");
                close(data_fd);
                fclose(file_added);
                continue;
            }
            SSL_set_fd(data_ssl, data_fd);
            if (SSL_accept(data_ssl) <= 0)
            {
                fprintf(stderr, "SSL_accept failed for data channel\n");
                ERR_print_errors_fp(stderr);
                SSL_free(data_ssl);
                close(data_fd);
                fclose(file_added);
                continue;
            }
            
            //Sending file contents over new data connection
            int buffer_size = 4096;                                             
            char file_data[4096];                                               
            int current_length = 0;                                             

            while (current_length < file_size)
            {
                printf("current_length is %d\n", current_length);               

                int bytes_to_read = buffer_size;
                int remaining_bytes = (int)(file_size - current_length);
                if (remaining_bytes < buffer_size)
                {
                    bytes_to_read = remaining_bytes;
                }
                size_t bytes_read = fread(file_data, sizeof(char),
                                  bytes_to_read, file_added);
                if (bytes_read == 0)
                {
                    break;                                                   
                }

                int bytes_sent = SSL_write(data_ssl, file_data, bytes_read);
                if (bytes_sent <= 0)
                {
                    // TODO: implement error handling
                    break;                                                     
                }

                current_length += (int)bytes_read;
            }
            fclose(file_added);
            //CLOSE DATA CHANNEL
            SSL_shutdown(data_ssl);
            SSL_free(data_ssl);
            close(data_fd);
            
            const char *resp = "GET OK\n";
            SSL_write(ssl, resp, strlen(resp));

            server_log("GET success: %s (%ld bytes)", argument_one, file_size);
        }
        else if (strcmp(command, "PUT") == 0)
        {
            // Requires authentication
            if (!authenticated)
            {
                const char *resp = "ERROR: Permission denied - login required (AUTH <user> <pass>)\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("PUT denied - not authenticated");
                continue;
            }
            
            // Parse: PUT <dest_path> <size> [src_basename]
            // argument_one = dest_path, argument_two = size, argument_three = src_basename (optional)
            char *argument_three = strtok(NULL, " \n");
            
            // Check for required arguments
            if (!argument_one || !argument_two)
            {
                const char *resp = "ERROR: PUT requires filename and size\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("PUT failed - missing arguments");
                continue;
            }
            
            // Path safety check
            if (!is_path_safe(argument_one))
            {
                const char *resp = "ERROR: Invalid path\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("PUT blocked - unsafe path: %s", argument_one ? argument_one : "NULL");
                // Drain the incoming file data
                int file_length = atoi(argument_two ? argument_two : "0");
                char drain[4096];
                int drained = 0;
                while (drained < file_length)
                {
                    int to_read = (file_length - drained > 4096) ? 4096 : (file_length - drained);
                    int r = SSL_read(ssl, drain, to_read);
                    if (r <= 0) break;
                    drained += r;
                }
                continue;
            }
            
            // Build final path - if destination is a directory, append the source filename
            char final_path[PATH_MAX];
            struct stat path_stat;
            if (stat(argument_one, &path_stat) == 0 && S_ISDIR(path_stat.st_mode))
            {
                // It's an existing directory - append source basename
                if (argument_three && strlen(argument_three) > 0)
                {
                    snprintf(final_path, PATH_MAX, "%s/%s", argument_one, argument_three);
                }
                else
                {
                    // No basename provided, use destination as-is (will fail)
                    const char *resp = "ERROR: Destination is a directory, specify filename\n";
                    SSL_write(ssl, resp, strlen(resp));
                    server_log("PUT failed - destination is directory: %s", argument_one);
                    continue;
                }
            }
            else
            {
                strncpy(final_path, argument_one, PATH_MAX - 1);
                final_path[PATH_MAX - 1] = '\0';
            }
            
            FILE* new_file = fopen(final_path, "wb");
            if (!new_file)
            {
                const char *resp = "ERROR: Cannot create file\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("PUT failed - cannot create: %s", final_path);
                continue;
            }
            int file_length = atoi(argument_two);
            int data_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (data_listen_fd < 0)
            {
                perror("socket(data PUT)");
                fclose(new_file);
                const char *resp = "ERROR: cannot open data socket\n";
                SSL_write(ssl, resp, strlen(resp));
                continue;
            }
            struct sockaddr_in data_address;
            initialize_server_address(&data_address);
            data_address.sin_port = htons(0);
            const struct sockaddr *const_data_address = (const struct sockaddr *)&data_address;

            if (bind(data_listen_fd, const_data_address, sizeof(data_address)) < 0)
            {
                perror("bind(data PUT) failed");
                close(data_listen_fd);
                fclose(new_file);
                const char *resp = "ERROR: cannot bind data socket\n";
                SSL_write(ssl, resp, strlen(resp));
                continue;
            }

            if (listen(data_listen_fd, 1) < 0)
            {
                perror("listen(data PUT) failed");
                close(data_listen_fd);
                fclose(new_file);
                const char *resp = "ERROR: cannot listen on data socket\n";
                SSL_write(ssl, resp, strlen(resp));
                continue;
            }
            socklen_t addrlen = sizeof(data_address);
            if (getsockname(data_listen_fd, (struct sockaddr *)&data_address, &addrlen) < 0)
            {
                perror("getsockname(data PUT)");
                close(data_listen_fd);
                fclose(new_file);
                const char *resp = "ERROR: getsockname failed\n";
                SSL_write(ssl, resp, strlen(resp));
                continue;
            }
            int assigned_port = ntohs(data_address.sin_port);
            char header[256];
            snprintf(header, sizeof(header), "DATA %d %s %ld\n", assigned_port, argument_one, file_length);
            SSL_write(ssl, header, strlen(header));
            int data_fd = accept(data_listen_fd, NULL, NULL);
            if (data_fd < 0)
            {
                perror("accept(data PUT)");
                close(data_listen_fd);
                fclose(new_file);
                const char *resp = "ERROR: cannot accept data connection\n";
                SSL_write(ssl, resp, strlen(resp));
                continue;
            }
            close(data_listen_fd);
            
            // Set up TLS on data channel
            SSL *data_ssl = SSL_new(data_ctx);
            if (!data_ssl)
            {
                fprintf(stderr, "SSL_new failed for data channel (PUT)\n");
                close(data_fd);
                fclose(new_file);
                const char *resp = "ERROR: SSL setup failed\n";
                SSL_write(ssl, resp, strlen(resp));
                continue;
            }
            SSL_set_fd(data_ssl, data_fd);
            if (SSL_accept(data_ssl) <= 0)
            {
                fprintf(stderr, "SSL_accept failed for data channel (PUT)\n");
                ERR_print_errors_fp(stderr);
                SSL_free(data_ssl);
                close(data_fd);
                fclose(new_file);
                const char *resp = "ERROR: SSL handshake failed\n";
                SSL_write(ssl, resp, strlen(resp));
                continue;
            }
            
            int buffer_size = 4096;
            char file_data[buffer_size];
            int current_length = 0;
            int read_error = 0;
            while(current_length < file_length)
            {
                int remaining_bytes = file_length - current_length;
                int to_read = (remaining_bytes < buffer_size) ? remaining_bytes : buffer_size;
                int bytes_read = SSL_read(data_ssl, file_data, to_read);
                if (bytes_read <= 0)
                {
                    int ssl_err = SSL_get_error(data_ssl, bytes_read);
                    fprintf(stderr, "PUT SSL_read error: bytes_read=%d, ssl_err=%d\n", bytes_read, ssl_err);
                    ERR_print_errors_fp(stderr);
                    read_error = 1;
                    break;
                }
                fwrite(file_data, sizeof(char), bytes_read, new_file);
                current_length = current_length + bytes_read;
            }
            SSL_shutdown(data_ssl);
            SSL_free(data_ssl);
            close(data_fd);
            fclose(new_file);
            
            if (read_error || current_length < file_length)
            {
                fprintf(stderr, "PUT incomplete: received %d of %d bytes\n", current_length, file_length);
                const char *resp = "ERROR: File transfer incomplete\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("PUT failed - incomplete: %s (%d of %d bytes)", argument_one, current_length, file_length);
            }
            else
            {
                const char *resp = "PUT OK\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("PUT success: %s (%d bytes)", argument_one, file_length);
            }
        }
        else if (strcmp(command, "LIST") == 0)
        {
            // List directory contents
            const char *path = argument_one ? argument_one : ".";
            if (!is_path_safe(path) && strcmp(path, ".") != 0)
            {
                const char *resp = "ERROR: Invalid path\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("LIST blocked - unsafe path: %s", path);
                continue;
            }
            
            DIR *dir = opendir(path);
            if (!dir)
            {
                char resp[256];
                snprintf(resp, sizeof(resp), "ERROR: Cannot open directory: %s\n", strerror(errno));
                SSL_write(ssl, resp, strlen(resp));
                continue;
            }
            
            char listing[4096] = "";
            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL)
            {
                struct stat st;
                char fullpath[PATH_MAX];
                snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
                
                char line[512];
                if (stat(fullpath, &st) == 0)
                {
                    char type = S_ISDIR(st.st_mode) ? 'd' : '-';
                    snprintf(line, sizeof(line), "%c %10ld %s\n", type, st.st_size, entry->d_name);
                }
                else
                {
                    snprintf(line, sizeof(line), "? %10d %s\n", 0, entry->d_name);
                }
                
                if (strlen(listing) + strlen(line) < sizeof(listing) - 1)
                {
                    strcat(listing, line);
                }
            }
            closedir(dir);
            
            if (strlen(listing) == 0)
            {
                strcpy(listing, "(empty directory)\n");
            }
            SSL_write(ssl, listing, strlen(listing));
            server_log("LIST: %s", path);
        }
        else if (strcmp(command, "PWD") == 0)
        {
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd)) != NULL)
            {
                char resp[PATH_MAX + 16];
                snprintf(resp, sizeof(resp), "%s\n", cwd);
                SSL_write(ssl, resp, strlen(resp));
            }
            else
            {
                const char *resp = "ERROR: Cannot get current directory\n";
                SSL_write(ssl, resp, strlen(resp));
            }
        }
        else if (strcmp(command, "CWD") == 0)
        {
            // Requires authentication
            if (!authenticated)
            {
                const char *resp = "ERROR: Permission denied - login required\n";
                SSL_write(ssl, resp, strlen(resp));
                continue;
            }
            if (!argument_one)
            {
                const char *resp = "ERROR: CWD requires directory path\n";
                SSL_write(ssl, resp, strlen(resp));
                continue;
            }
            if (!is_path_safe(argument_one))
            {
                const char *resp = "ERROR: Invalid path\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("CWD blocked - unsafe path: %s", argument_one);
                continue;
            }
            
            if (chdir(argument_one) == 0)
            {
                const char *resp = "CWD OK\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("CWD: %s", argument_one);
            }
            else
            {
                char resp[256];
                snprintf(resp, sizeof(resp), "CWD FAILED: %s\n", strerror(errno));
                SSL_write(ssl, resp, strlen(resp));
            }
        }
        else if (strcmp(command, "DELE") == 0)
        {
            // Requires authentication
            if (!authenticated)
            {
                const char *resp = "ERROR: Permission denied - login required\n";
                SSL_write(ssl, resp, strlen(resp));
                continue;
            }
            if (!argument_one)
            {
                const char *resp = "ERROR: DELE requires filename\n";
                SSL_write(ssl, resp, strlen(resp));
                continue;
            }
            if (!is_path_safe(argument_one))
            {
                const char *resp = "ERROR: Invalid path\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("DELE blocked - unsafe path: %s", argument_one);
                continue;
            }
            
            if (unlink(argument_one) == 0)
            {
                const char *resp = "DELE OK\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("DELE: %s", argument_one);
            }
            else
            {
                char resp[256];
                snprintf(resp, sizeof(resp), "DELE FAILED: %s\n", strerror(errno));
                SSL_write(ssl, resp, strlen(resp));
            }
        }
        else if (strcmp(command, "MKDIR") == 0)
        {
            // Requires authentication
            if (!authenticated)
            {
                const char *resp = "ERROR: Permission denied - login required\n";
                SSL_write(ssl, resp, strlen(resp));
                continue;
            }
            if (!argument_one)
            {
                const char *resp = "ERROR: MKDIR requires directory name\n";
                SSL_write(ssl, resp, strlen(resp));
                continue;
            }
            // Path safety check
            if (!is_path_safe(argument_one))
            {
                const char *resp = "ERROR: Invalid path\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("MKDIR blocked - unsafe path: %s", argument_one);
                continue;
            }
            if (mkdir(argument_one, 0755) == 0)
            {
                const char *resp = "MKDIR OK\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("MKDIR: %s", argument_one);
            }
            else
            {
                char resp[256];
                snprintf(resp, sizeof(resp), "MKDIR FAILED: %s\n", strerror(errno));
                SSL_write(ssl, resp, strlen(resp));
            }
        }
        else if (strcmp(command, "RMDIR") == 0)
        {
            // Requires authentication
            if (!authenticated)
            {
                const char *resp = "ERROR: Permission denied - login required\n";
                SSL_write(ssl, resp, strlen(resp));
                continue;
            }
            if (!argument_one)
            {
                const char *resp = "ERROR: RMDIR requires directory name\n";
                SSL_write(ssl, resp, strlen(resp));
                continue;
            }
            if (!is_path_safe(argument_one))
            {
                const char *resp = "ERROR: Invalid path\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("RMDIR blocked - unsafe path: %s", argument_one);
                continue;
            }
            if (rmdir(argument_one) == 0)
            {
                const char *resp = "RMDIR OK\n";
                SSL_write(ssl, resp, strlen(resp));
                server_log("RMDIR: %s", argument_one);
            }
            else
            {
                char resp[256];
                snprintf(resp, sizeof(resp), "RMDIR FAILED: %s\n", strerror(errno));
                SSL_write(ssl, resp, strlen(resp));
            }
        }
        else
        {
            //unrecognized command name
            const char *resp = "ERROR: unrecognized command\n";
            SSL_write(ssl, resp, strlen(resp));
        }
    }
    
    
}

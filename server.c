#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>

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
ssize_t recv_line(int fd, char *buf, size_t max_len);
void handle_client(int client_fd);
void server_log(const char *format, ...);
int is_path_safe(const char *path);


int main(void)
{
    // Open log file
    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp)
    {
        perror("Could not open log file");
        log_fp = stderr; // Fall back to stderr
    }
    server_log("Server started");
    
    printf("Server started\n");
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

    while (1)
    {
        struct sockaddr_in client_address;
        socklen_t client_len = sizeof(client_address);
        struct sockaddr* generic_client_address = (struct sockaddr*) &client_address;
        //accept() takes a client out of the queue to listen
        int client_fd = accept(listen_fd, generic_client_address, &client_len);
        if (client_fd < 0)
        {
            perror("accept");
            close(listen_fd);
            exit(EXIT_FAILURE);
        }
        printf("Client connected, fd = %d\n", client_fd);
        
        handle_client(client_fd);

        close(client_fd);
        printf("Client disconnected, fd = %d\n", client_fd);
    }

    close(listen_fd);
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

ssize_t recv_line(int fd, char *buf, size_t max_len)
{
    size_t i = 0;
    while (i < max_len-1)
    {
        char c;
        ssize_t n = recv(fd, &c, 1, 0);
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

void handle_client(int client_fd)
{
    char cmd[MAX_CMD_LEN];
    server_log("Client connected, fd=%d", client_fd);
    
    // Send welcome message to client
    const char *welcome = "Welcome to FTP Server\n";
    send(client_fd, welcome, strlen(welcome), 0);
    
    while (1)
    {
        ssize_t n = recv_line(client_fd, cmd, MAX_CMD_LEN);
        char* command = strtok(cmd, " \n");
        char* argument_one = strtok(NULL, " \n");
        char* argument_two = strtok(NULL, " \n");
        if (n <= 0)
        {
            break; //connection closed or error
        }
        
        if (n==0)
        {
            printf("Connection closed by client\n");
            server_log("Connection closed by client");
            break;
        }

        printf("Received command: %s\n", cmd);
        server_log("Command: %s %s %s", command, 
                   argument_one ? argument_one : "", 
                   argument_two ? argument_two : "");

        if (strcmp(command, "PING") == 0)
        {
            const char *resp = "PONG\n";
            send(client_fd, resp, strlen(resp), 0);
        }
        else if (strcmp(command, "QUIT") == 0)
        {
            const char * resp = "Goodbye!\n";
            send(client_fd, resp, strlen(resp), 0);
            printf("Closing connection on client request\n");
            server_log("Client requested disconnect");
            break;
        }
        else if (strcmp(command, "AUTH") == 0)
        {
            // Simple hardcoded auth for testing
            if (argument_one && argument_two &&
                strcmp(argument_one, "admin") == 0 &&
                strcmp(argument_two, "password") == 0)
            {
                const char *resp = "AUTH OK\n";
                send(client_fd, resp, strlen(resp), 0);
                server_log("AUTH OK for user: %s", argument_one);
            }
            else
            {
                const char *resp = "AUTH FAILED\n";
                send(client_fd, resp, strlen(resp), 0);
                server_log("AUTH FAILED for user: %s", argument_one ? argument_one : "NULL");
            }
        }
        else if (strcmp(command, "GET") == 0)
        {
            // Path safety check
            if (!is_path_safe(argument_one))
            {
                const char *resp = "ERROR: Invalid path\n";
                send(client_fd, resp, strlen(resp), 0);
                server_log("GET blocked - unsafe path: %s", argument_one ? argument_one : "NULL");
                continue;
            }
            

            FILE* file_added = fopen(argument_one, "rb");
            if (!file_added)
            {
                const char *resp = "ERROR: File not found\n";
                send(client_fd, resp, strlen(resp), 0);
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
            send(client_fd, header, strlen(header), 0);

            int data_fd = accept(data_listen_fd, NULL, NULL);
            if ((data_fd < 0))
            {
                perror("accept(data)");
                close(data_listen_fd);
                fclose(file_added);
                continue;
            }
            close(data_listen_fd);
            
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

                int bytes_sent = send(data_fd, file_data, bytes_read, 0);
                if (bytes_sent <= 0)
                {
                    // TODO: implement error handling
                    break;                                                     
                }

                current_length += (int)bytes_read;
            }
            fclose(file_added);
            //CLOSE DATA CHANNEL
            close(data_fd);
            
            const char *resp = "GET OK\n";
            send(client_fd, resp, strlen(resp), 0);

            server_log("GET success: %s (%ld bytes)", argument_one, file_size);
        }
        else if (strcmp(command, "PUT") == 0)
        {
            // Path safety check
            if (!is_path_safe(argument_one))
            {
                const char *resp = "ERROR: Invalid path\n";
                send(client_fd, resp, strlen(resp), 0);
                server_log("PUT blocked - unsafe path: %s", argument_one ? argument_one : "NULL");
                // Drain the incoming file data
                int file_length = atoi(argument_two ? argument_two : "0");
                char drain[4096];
                int drained = 0;
                while (drained < file_length)
                {
                    int to_read = (file_length - drained > 4096) ? 4096 : (file_length - drained);
                    int r = recv(client_fd, drain, to_read, 0);
                    if (r <= 0) break;
                    drained += r;
                }
                continue;
            }
            
            FILE* new_file = fopen(argument_one, "wb");
            if (!new_file)
            {
                const char *resp = "ERROR: Cannot create file\n";
                send(client_fd, resp, strlen(resp), 0);
                server_log("PUT failed - cannot create: %s", argument_one);
                continue;
            }
            int file_length = atoi(argument_two);
            int data_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (data_listen_fd < 0)
            {
                perror("socket(data PUT)");
                fclose(new_file);
                const char *resp = "ERROR: cannot open data socket\n";
                send(client_fd, resp, strlen(resp), 0);
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
                send(client_fd, resp, strlen(resp), 0);
                continue;
            }

            if (listen(data_listen_fd, 1) < 0)
            {
                perror("listen(data PUT) failed");
                close(data_listen_fd);
                fclose(new_file);
                const char *resp = "ERROR: cannot listen on data socket\n";
                send(client_fd, resp, strlen(resp), 0);
                continue;
            }
            socklen_t addrlen = sizeof(data_address);
            if (getsockname(data_listen_fd, (struct sockaddr *)&data_address, &addrlen) < 0)
            {
                perror("getsockname(data PUT)");
                close(data_listen_fd);
                fclose(new_file);
                const char *resp = "ERROR: getsockname failed\n";
                send(client_fd, resp, strlen(resp), 0);
                continue;
            }
            int assigned_port = ntohs(data_address.sin_port);
            char header[256];
            snprintf(header, sizeof(header), "DATA %d %s %ld\n", assigned_port, argument_one, file_length);
            send(client_fd, header, strlen(header), 0);
            int data_fd = accept(data_listen_fd, NULL, NULL);
            if (data_fd < 0)
            {
                perror("accept(data PUT)");
                close(data_listen_fd);
                fclose(new_file);
                const char *resp = "ERROR: cannot accept data connection\n";
                send(client_fd, resp, strlen(resp), 0);
                continue;
            }
            close(data_listen_fd);
            int buffer_size = 4096;
            char file_data[buffer_size];
            int current_length = 0;
            while(current_length < file_length)
            {
                int remaining_bytes = file_length - current_length;
                int to_read = (remaining_bytes < buffer_size) ? remaining_bytes : buffer_size;
                int bytes_read = recv(data_fd, file_data, to_read, 0);
                if (bytes_read <= 0)
                {
                    break;
                }
                fwrite(file_data, sizeof(char), bytes_read, new_file);
                current_length = current_length + bytes_read;
            }
            close(data_fd);
            fclose(new_file);
            const char *resp = "PUT OK\n";
            send(client_fd, resp, strlen(resp), 0);
            server_log("PUT success: %s (%d bytes)", argument_one, file_length);
        }
        else if (strcmp(command, "LIST") == 0)
        {
            // List directory contents
            const char *path = argument_one ? argument_one : ".";
            if (!is_path_safe(path) && strcmp(path, ".") != 0)
            {
                const char *resp = "ERROR: Invalid path\n";
                send(client_fd, resp, strlen(resp), 0);
                server_log("LIST blocked - unsafe path: %s", path);
                continue;
            }
            
            DIR *dir = opendir(path);
            if (!dir)
            {
                char resp[256];
                snprintf(resp, sizeof(resp), "ERROR: Cannot open directory: %s\n", strerror(errno));
                send(client_fd, resp, strlen(resp), 0);
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
            send(client_fd, listing, strlen(listing), 0);
            server_log("LIST: %s", path);
        }
        else if (strcmp(command, "PWD") == 0)
        {
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd)) != NULL)
            {
                char resp[PATH_MAX + 16];
                snprintf(resp, sizeof(resp), "%s\n", cwd);
                send(client_fd, resp, strlen(resp), 0);
            }
            else
            {
                const char *resp = "ERROR: Cannot get current directory\n";
                send(client_fd, resp, strlen(resp), 0);
            }
        }
        else if (strcmp(command, "CWD") == 0)
        {
            if (!is_path_safe(argument_one))
            {
                const char *resp = "ERROR: Invalid path\n";
                send(client_fd, resp, strlen(resp), 0);
                server_log("CWD blocked - unsafe path: %s", argument_one ? argument_one : "NULL");
                continue;
            }
            
            if (chdir(argument_one) == 0)
            {
                const char *resp = "CWD OK\n";
                send(client_fd, resp, strlen(resp), 0);
                server_log("CWD: %s", argument_one);
            }
            else
            {
                char resp[256];
                snprintf(resp, sizeof(resp), "CWD FAILED: %s\n", strerror(errno));
                send(client_fd, resp, strlen(resp), 0);
            }
        }
        else if (strcmp(command, "DELE") == 0)
        {
            if (!is_path_safe(argument_one))
            {
                const char *resp = "ERROR: Invalid path\n";
                send(client_fd, resp, strlen(resp), 0);
                server_log("DELE blocked - unsafe path: %s", argument_one ? argument_one : "NULL");
                continue;
            }
            
            if (unlink(argument_one) == 0)
            {
                const char *resp = "DELE OK\n";
                send(client_fd, resp, strlen(resp), 0);
                server_log("DELE: %s", argument_one);
            }
            else
            {
                char resp[256];
                snprintf(resp, sizeof(resp), "DELE FAILED: %s\n", strerror(errno));
                send(client_fd, resp, strlen(resp), 0);
            }
        }
        else if (strcmp(command, "MKDIR") == 0)
        {
            // Path safety check
            if (!is_path_safe(argument_one))
            {
                const char *resp = "ERROR: Invalid path\n";
                send(client_fd, resp, strlen(resp), 0);
                server_log("MKDIR blocked - unsafe path: %s", argument_one ? argument_one : "NULL");
            }
            else if (mkdir(argument_one, 0755) == 0)
            {
                const char *resp = "MKDIR OK\n";
                send(client_fd, resp, strlen(resp), 0);
                server_log("MKDIR: %s", argument_one);
            }
            else
            {
                char resp[256];
                snprintf(resp, sizeof(resp), "MKDIR FAILED: %s\n", strerror(errno));
                send(client_fd, resp, strlen(resp), 0);
            }
        }
        else if (strcmp(command, "RMDIR") == 0)
        {
            if (!is_path_safe(argument_one))
            {
                const char *resp = "ERROR: Invalid path\n";
                send(client_fd, resp, strlen(resp), 0);
                server_log("RMDIR blocked - unsafe path: %s", argument_one ? argument_one : "NULL");
            }
            else if (rmdir(argument_one) == 0)
            {
                const char *resp = "RMDIR OK\n";
                send(client_fd, resp, strlen(resp), 0);
                server_log("RMDIR: %s", argument_one);
            }
            else
            {
                char resp[256];
                snprintf(resp, sizeof(resp), "RMDIR FAILED: %s\n", strerror(errno));
                send(client_fd, resp, strlen(resp), 0);
            }
        }
        else
        {
            //unrecognized command name
            const char *resp = "ERROR: unrecognized command\n";
            send(client_fd, resp, strlen(resp), 0);
        }
    }
    
    
}

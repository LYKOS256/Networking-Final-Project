#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define SERVER_PORT 5000  //matches server's listening port

void initialize_server_address(struct sockaddr_in* server_address);

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    const char *server_ip = argv[1];
    printf("Client started\n");
    //AF_INET = ipv4
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    printf("Client socket created, fd = %d\n", sock_fd);
    struct sockaddr_in server_address;
    initialize_server_address(&server_address);
    //AF_INET = ipv4
    if (inet_pton(AF_INET, server_ip, &server_address.sin_addr) <= 0)
    {
        perror("inet_pton");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server address prepared\n");
    struct sockaddr* generic_server_address = (struct sockaddr*)&server_address;
    //connect() connects socket to server
    if (connect(sock_fd, generic_server_address, sizeof(server_address)) < 0)
    {
        perror("connect");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server %s:%d\n", server_ip, SERVER_PORT);
    
    // Receive and display server welcome message
    char welcome[1024];
    ssize_t w = recv(sock_fd, welcome, sizeof(welcome)-1, 0);
    if (w > 0)
    {
        welcome[w] = '\0';
        printf("Server: %s", welcome);
    }
    
    //Single-User Command Channel Loop
    char input[1024];
    char response[1024];
    while (1)
    {
        printf("> ");
        if (fgets(input, sizeof(input), stdin) == NULL)
        {
            printf("EOF or input error, exit.\n");
            break;
        }
        char input_copy[1024];
        strncpy(input_copy, input, 1024);
        char* input_command = strtok(input_copy, " \n");
        char* argument_one = strtok(NULL, " \n");
        char* argument_two = strtok(NULL, " \n");
        if (strcmp(input_command, "QUIT") == 0)
        {
            if (send(sock_fd, input, strlen(input), 0) < 0)
            {
                perror("send");
                break;
            }
            ssize_t n = recv(sock_fd, response, sizeof(response)-1, 0);
            if (n > 0)
            {
                response[n] = '\0';
                printf("Server: %s", response);
            }
            printf("Closing connection\n");
            break;
        }
        else if (strcmp(input_command, "GET") == 0)
        {
            // Send GET command to server
            if (send(sock_fd, input, strlen(input), 0) < 0)
            {
                perror("send");
                break;
            }
            // First receive the header: filename size or ERROR
            ssize_t n = recv(sock_fd, response, sizeof(response)-1, 0);
            if (n <= 0)
            {
                printf("Connection closed by server or error\n");
                break;
            }
            response[n] = '\0';
            
            // Check if it's an error response
            if (strncmp(response, "ERROR", 5) == 0)
            {
                printf("Server: %s", response);
                continue;
            }
            
            // Parse filename and size from response
            char *recv_filename = strtok(response, " \n");
            char *size_str = strtok(NULL, " \n");
            if (!recv_filename || !size_str)
            {
                printf("Invalid server response\n");
                continue;
            }
            long file_size = atol(size_str);
            
            // Create local file
            FILE *new_file = fopen(argument_one, "wb");
            if (!new_file)
            {
                printf("Could not create local file: %s\n", argument_one);
                // Still need to drain the incoming data
                char drain[4096];
                long drained = 0;
                while (drained < file_size)
                {
                    int to_read = (file_size - drained > 4096) ? 4096 : (file_size - drained);
                    int r = recv(sock_fd, drain, to_read, 0);
                    if (r <= 0) break;
                    drained += r;
                }
                continue;
            }
            
            // Receive file data
            int buffer_size = 4096;
            char file_data[buffer_size];
            long current_length = 0;
            while (current_length < file_size)
            {
                int bytes_to_read = buffer_size;
                long remaining = file_size - current_length;
                if (remaining < buffer_size)
                {
                    bytes_to_read = remaining;
                }
                int bytes_recv = recv(sock_fd, file_data, bytes_to_read, 0);
                if (bytes_recv <= 0)
                {
                    printf("Connection error while receiving file\n");
                    break;
                }
                fwrite(file_data, sizeof(char), bytes_recv, new_file);
                current_length += bytes_recv;
            }
            fclose(new_file);
            printf("Downloaded %s (%ld bytes)\n", argument_one, file_size);
            continue;
        }
        else if (strcmp(input_command, "PUT") == 0)
        {
            // Support destination path: PUT <src> <dest>
            const char *src_path = argument_one;
            const char *dest_path = argument_two ? argument_two : argument_one;

            FILE* file_added = fopen(src_path, "rb");
            if (!file_added)
            {
                printf("file not found error: %s\n", src_path);
                continue;
            }
            //fseek and ftell used here to determine file size
            fseek(file_added, 0, SEEK_END);
            long file_size = ftell(file_added);
            //converting file size into a string
            char file_size_string[32];
            sprintf(file_size_string, "%ld", file_size);
            //sending the input data but with the file size attached
            char send_data[strlen(input_command) + strlen(dest_path) + strlen(file_size_string) + 3];
            sprintf(send_data, "%s %s %s\n", input_command, dest_path, file_size_string);
            send(sock_fd, send_data, strlen(send_data), 0); //TODO: add error handling here
            int buffer_size = 4096;
            char file_data[buffer_size];
            fseek(file_added, 0, SEEK_SET);
            int current_length = 0;
            while(current_length < file_size)
            {
                int bytes_to_read = buffer_size;
                int remaining_bytes = file_size - current_length;
                if (remaining_bytes < buffer_size)
                {
                    bytes_to_read = remaining_bytes;
                }
                size_t bytes_read = fread(file_data, sizeof(char), bytes_to_read, file_added);
                int bytes_sent = send(sock_fd, file_data, bytes_read, 0);
                if (bytes_sent <= 0)
                {
                    //TODO: implement error handling
                }
                current_length = current_length + bytes_read;
            }
            fclose(file_added);
            
            // Wait for server response after PUT
            ssize_t n = recv(sock_fd, response, sizeof(response)-1, 0);
            if (n <= 0)
            {
                printf("Connection closed by server or error\n");
                break;
            }
            response[n] = '\0';
            printf("Server: %s", response);
            continue;
        }
        else if (send(sock_fd, input, strlen(input), 0) < 0)
        {
            perror("send");
            break;
        }
        ssize_t n = recv(sock_fd, response, sizeof(response)-1, 0);
        if (n <= 0)
        {
            printf("Connection closed by server or error\n");
            break;
        }
        response[n] = '\0';
        printf("Server: %s", response);
    }


    close(sock_fd);
    return 0;
}

void initialize_server_address(struct sockaddr_in* server_address)
{
    memset(server_address, 0, sizeof(*server_address));
    server_address->sin_family = AF_INET; //AF_INET = ipv4
    server_address->sin_port = htons(SERVER_PORT);
}
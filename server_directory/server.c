#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#define LISTEN_PORT 5000 //random number > 1024
#define BACKLOG 5 //number of clients that can be waiting at the same time
#define MAX_CMD_LEN 1024

void initialize_server_address(struct sockaddr_in* server_address);
ssize_t recv_line(int fd, char *buf, size_t max_len);
void handle_client(int client_fd);


int main(void)
{
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
    printf("Bound to port %d\n", LISTEN_PORT);
    //listen() tells the socket to listen to clients
    if (listen(listen_fd, BACKLOG) < 0)
    {
        perror("listen");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }
    printf("Server listening to port %d\n", LISTEN_PORT);

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
    server_address->sin_port = htons(LISTEN_PORT);
}

ssize_t recv_line(int fd, char *buf, size_t max_len)
{
    size_t i = 0;
    printf("max length is %d\n", max_len);
    while (i < max_len-1)
    {
        //printf("i is %d recv_line while loop\n", i);
        char c;
        printf("before recv\n");
        ssize_t n = recv(fd, &c, 1, 0);
        printf("after recv\n");
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
    printf("exited while loop\n");
    buf[i] = '\0';
    return (ssize_t)i;
}

void handle_client(int client_fd)
{
    char cmd[MAX_CMD_LEN];
    while (1)
    {
        printf("very beggining of the loop\n");
        ssize_t n = recv_line(client_fd, cmd, MAX_CMD_LEN);
        printf("before chopping up input\n");
        char* command = strtok(cmd, " \n");
        char* argument_one = strtok(NULL, " \n");
        char* argument_two = strtok(NULL, " \n");
        printf("after chopping up input\n");
        if (n <= 0)
        {
            break; //connection closed or error
        }
        
        if (n==0)
        {
            printf("Connection closed by client\n");
            break;
        }

        printf("Received command: %s\n", cmd);

        if (strcmp(command, "PING") == 0)
        {
            const char *resp = "PONG\n";
            send(client_fd, resp, strlen(resp), 0);
        }
        else if (strcmp(command, "CLOSE") == 0)
        {
            const char * resp = "Goodbye!\n";
            send(client_fd, resp, strlen(resp), 0);
            printf("Closing connection on client request\n");
            break;
        }
        else if (strcmp(command, "AUTH") == 0)
        {
            
        }
        else if (strcmp(command, "GET") == 0)
        {
    
        }
        else if (strcmp(command, "PUT") == 0)
        {
            //TODO: allow the user to add the file to any path
            FILE* new_file = fopen(argument_one, "wb");
            int file_length = atoi(argument_two);
            int buffer_size = 4096; //arbitrariy chosen number
            char file_data[buffer_size];
            int current_length = 0;
            while(current_length < file_length)
            {
                int remaining_bytes = file_length - current_length;
                if (remaining_bytes < buffer_size)
                {
                    buffer_size = remaining_bytes;
                }
                int bytes_read = recv(client_fd, file_data, buffer_size, 0);
                if (bytes_read <= 0)
                {
                    //TODO: impelment error handling
                }
                fwrite(file_data, sizeof(char), buffer_size, new_file);
                current_length = current_length + bytes_read;
            }
            fclose(new_file);
            const char *resp = "PUT returned succesfully\n";
            send(client_fd, resp, strlen(resp), 0);
        }
        else if (strcmp(command, "MKDIR") == 0)
        {
            
        }
        else if (strcmp(command, "RMDIR") == 0)
        {
            
        }
        else
        {
            //unrecognized command name
            const char *resp = "ERROR: unrecognized command\n";
            send(client_fd, resp, strlen(resp), 0);
        }
    }
    
    
}

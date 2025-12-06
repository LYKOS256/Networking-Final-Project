#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define SERVER_PORT 4000  //matches server's listening port

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

        if (send(sock_fd, input, strlen(input), 0) < 0)
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
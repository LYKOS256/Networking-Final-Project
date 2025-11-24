#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#define LISTEN_PORT 4000 //random number > 1024
#define BACKLOG 5 //number of clients that can be waiting at the same time

void initialize_server_address(struct sockaddr_in* server_address);

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

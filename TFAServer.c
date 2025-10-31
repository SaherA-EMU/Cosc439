#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MAX 5
#define BUFFSIZE 256

int main(int argc, char *argv[]) {
    if(argc != 2) {
        fprintf(stderr, "Usage: %s <Port Number>\n", argv[0]);
        exit(1);
    }
    printf("TFAServer module loaded.\n");
    unsigned short portNumber = atoi(argv[1]);
    int serverSock, clientSock;
    struct sockaddr_in serverAddr, clientAddr;
    unsigned int clientLen;
    char buffer[BUFFSIZE];

    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0) {
        perror("Socket() failed");
        exit(1);
    }
    printf("Socket created successfully.\n");

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;                /* IPv4*/
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming connection*/
    serverAddr.sin_port = htons(portNumber);        /* convert host to network short(Local port) */

    if (bind(serverSock, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
        perror("Bind() failed");
        exit(1);
    }
    printf("Bind completed successfully.\n");
    if(listen(serverSock, MAX) < 0) {
        perror("Listen() failed");
        exit(1);
    }
    printf("TFA Server listening on port %u...\n", portNumber);
    clientLen = sizeof(clientAddr);
    clientSock = accept(serverSock, (struct sockaddr *) &clientAddr, &clientLen);
    if (clientSock < 0) {
        perror("Accept() failed");
        exit(1);
    }
    printf("Client connected: %s\n", inet_ntoa(clientAddr.sin_addr));
    accept();

    int bytesReceived = recv(clientSock, buffer, BUFFSIZE - 1, 0);
    if (bytesReceived < 0) {
        perror("Recv() failed");
        exit(1);
    }
    buffer[bytesReceived] = '\0'; // Null-terminate the received string
    printf("Received from client: %s\n", buffer);
    char *ackMessage = "Acknowledged by TFAServer";
    send(clientSock, ackMessage, strlen(ackMessage), 0);
    close(clientSock);
    close(serverSock);
    return 0;
}
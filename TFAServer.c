#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MAX 5
#define BUFFSIZE 256

// message structures
typedef struct {
    enum { registerTFA, ackRegTFA, ackPushTFA, requestAuth} messageType;
    unsigned int userID;
    unsigned long timestamp;
    unsigned long digitalSig;
} TFAClientOrLodiServerToTFAServer;

// response structure
typedef struct {
    enum { confirmTFA, pushTFA} messageType;
    unsigned int userID;
} TFAServerToClient;

int main(int argc, char *argv[]) {
    if(argc != 2) {
        fprintf(stderr, "Usage: %s <Port Number>\n", argv[0]);
        exit(1);
    }
// Initialize server
    printf("TFAServer module loaded.\n");

    unsigned short serverPort = (unsigned short)atoi(argv[1]);
    int serverSock;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t clientLen = sizeof(clientAddr);
// Create socket
    serverSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (serverSock < 0) {
        perror("Socket() failed");
        exit(1);
    }
    printf("[TFA Server] Socket created successfully.\n");
// Configure server address structure
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;                /* IPv4*/
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming connection*/
    serverAddr.sin_port = htons(serverPort);        /* convert host to network short(Local port) */
// Bind, listen, and receive
    if (bind(serverSock, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
        perror("Bind() failed");
        exit(1);
    }
    printf("[TFA Server] Bind completed successfully.\n");
    printf("[TFA Server] Listening on port %u...\n", serverPort);
    while(1) {
    TFAClientOrLodiServerToTFAServer recvMessage;
    ssize_t recvLength = recvfrom(serverSock, &recvMessage, sizeof(recvMessage), 0,
                                  (struct sockaddr *) &clientAddr, &clientLen);
    if (recvLength < 0) {
        perror("Recvfrom() failed");
        close(serverSock);
        exit(1);
    }
    printf("\n[TFA Server] Received message from %s:%u\n",inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
    printf("[TFA Server] messageType=%d userID=%u timestamp=%lu digitalSig=%lu \n", recvMessage.messageType, recvMessage.userID, recvMessage.timestamp, recvMessage.digitalSig);
// Process message
    if(recvMessage.messageType == registerTFA) {
    TFAServerToClient responseMessage;
    responseMessage.messageType = confirmTFA;
    responseMessage.userID = recvMessage.userID;

// Send response to client
    ssize_t sentBytes = sendto(serverSock, &responseMessage, sizeof(responseMessage), 0,
                               (struct sockaddr *) &clientAddr, clientLen);
    if (sentBytes < 0) {
        perror("Sendto() failed");
        close(serverSock);
        exit(1);
    }
    printf("[TFA Server] Received messageType=%d userID=%u timestamp=%lu digitalSig=%lu \n",
    recvMessage.messageType, recvMessage.userID, recvMessage.timestamp, recvMessage.digitalSig);

    if(recvMessage.messageType == registerTFA) {
        TFAServerToClient responseMessage;
        responseMessage.messageType = confirmTFA;
        responseMessage.userID = recvMessage.userID;
// Send response to client
     ssize_t sentBytes = sendto(serverSock, &responseMessage, sizeof(responseMessage), 0,
                                (struct sockaddr *) &clientAddr, clientLen);
        if (sentBytes != sizeof(responseMessage)) {
            perror("Sendto() failed");
            close(serverSock);
            exit(1);
        }else {
            printf("[TFA Server] Sent confirmTFA response to %s:%d for user %u\n",
                   inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port), recvMessage.userID);
        }
        close(serverSock);
        return 0;
    }
}}}
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
    int serverSock = -1, clientSock = -1;
    struct sockaddr_in serverAddr, clientAddr;
    unsigned int clientLen;
    ssize_t numBytes;
// Create socket
    serverSock = socket(AF_INET, SOCK_STREAM, 0);
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
// Bind, listen, and accept
    if (bind(serverSock, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
        perror("Bind() failed");
        exit(1);
    }
    printf("[TFA Server] Bind completed successfully.\n");
    if(listen(serverSock, MAX) < 0) {
        perror("Listen() failed");
        exit(1);
    }
    printf("[TFA Server] Listening on port %u...\n", serverPort);
    clientLen = sizeof(clientAddr);
    clientSock = accept(serverSock, (struct sockaddr *) &clientAddr, &clientLen);
    if (clientSock < 0) {
        perror("Accept() failed");
        close(serverSock);
        exit(1);
    }
// Connect to client
    printf("[TFA Server] Client connected: %s:%u\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
// Receive message from client
    TFAClientOrLodiServerToTFAServer recvMessage;
    numBytes = recv(clientSock, &recvMessage, sizeof(recvMessage), 0);
    if (numBytes < 0) {
        perror("Recv() failed");
        close(clientSock);
        close(serverSock);
        exit(1);
    }
    printf("[TFA Server] Received messageType=%d userID=%u timestamp=%lu digitalSig=%lu (bytes=%zd)\n",
    recvMessage.messageType, recvMessage.userID, recvMessage.timestamp, recvMessage.digitalSig, numBytes);

    if(recvMessage.messageType == registerTFA) {
        TFAServerToClient responseMessage;
        responseMessage.messageType = confirmTFA;
        responseMessage.userID = recvMessage.userID;
// Send response to client
     ssize_t sentBytes = send(clientSock, &responseMessage, sizeof(responseMessage), 0);
        if (sentBytes < 0) {
            perror("Send() failed");
            close(clientSock);
            close(serverSock);
            exit(1);
        }
        printf("[TFA Server] Sent response  userID=%u (bytes=%zd)\n",
        responseMessage.userID, sentBytes);
        close(clientSock);
        close(serverSock);
        return 0;
    }
}
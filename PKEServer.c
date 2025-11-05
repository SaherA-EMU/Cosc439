#include <stdio.h>      // for printf() and fprintf()
#include <sys/socket.h> // for recvfrom() and sendto()
#include <unistd.h>     // for close()
#include <stdlib.h>     // just for rand(), really
#include <string.h>     // for memset()
#include <arpa/inet.h>  // for inet_addr() and htons()

// structs to be sent and received
typedef struct {
    enum { registerKey, requestKey} messageType;
    unsigned int userID;
    unsigned long publicKey;
} PClientOrLodiServertoPKEServer;
typedef struct {
    enum {ackRegisterKey, responsePublicKey} messageType;
    unsigned int userID;
    unsigned int publicKey;
} PKServerToPClientOrLodiClient;

int main() {
    // variable declaration and initialization
    struct sockaddr_in serverAddress, clientAddress;
    unsigned int clientLen;
    PClientOrLodiServertoPKEServer recMessage;
    PKServerToPClientOrLodiClient sendMessage;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    unsigned int clientAddressLength;
    printf("PKEServer module loaded.\n");
    // Check  if socket is made
    if (sock < 0) {
        perror("Socket() failed");
        return 1;
    }
    // Configure server address structure
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY); // I had to look at the ip.7 manual for this
    serverAddress.sin_port = htons(5050); //I picked this at random

    // Bind socket
    if (bind(sock, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
        perror("bind() failed");
        close(sock);
        return 1;
    }
    printf("[PKE Server]: listening on port 5050...\n");

    clientAddressLength =sizeof(clientAddress);
    while (1){
        memset(&recMessage, 0, sizeof(recMessage));
        ssize_t recvLength = recvfrom(sock, &recMessage, sizeof(recMessage), 0,
                                        (struct sockaddr *) &clientAddress, &clientAddressLength);
        if(recvLength < 0) {
            perror("recvfrom() failed");
            continue;
        }

        printf("\n[PKE Server]: Message received from %s:%d\n", inet_ntoa(clientAddress.sin_addr), ntohs(clientAddress.sin_port));
        printf("[PKE Server]: Message Type: %d \n", recMessage.messageType);
        printf("[PKE Server]: User ID: %u\n", recMessage.userID);
        printf("[PKE Server]: Public Key: %lu \n", recMessage.publicKey);

        sendMessage.messageType =0;
        sendMessage.userID =recMessage.userID;
        sendMessage.publicKey = recMessage.publicKey;

        if(sendto(sock, &sendMessage, sizeof(sendMessage), 0,
                    (struct sockaddr *) &clientAddress, clientAddressLength) != sizeof(sendMessage)){
                        perror("sendto() failed");
        } else {
            printf("Acknowledgement sent. \n");
        }
    }

    close(sock);
    return 0;
}
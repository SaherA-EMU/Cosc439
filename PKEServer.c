#include <stdio.h>      // for printf() and fprintf()
#include <sys/socket.h> // for recvfrom() and sendto()
#include <unistd.h>     // for close()
#include <stdlib.h>     // just for rand(), really
#include <string.h>     // for memset()
#include <arpa/inet.h>  // for inet_addr() and htons()


// structs to be sent stored or received
typedef struct {
    enum { registerKey, requestKey} messageType;
    unsigned int userID;
    unsigned long publicKey;
} PClientOrLodiServertoPKEServer;
typedef struct {
    enum { ackRegisterKey, responsePublicKey, responseAuth, login } messageType;
    unsigned int userID;
    unsigned int publicKey;
    unsigned int recipientID;
    unsigned long timestamp;
    unsigned long digitalSig;
} PKServerToPClientOrLodiClient;
typedef struct {
    unsigned int userID;
    unsigned long publicKey;
} RegisteredUser;


int main() {
    // variable declaration and initialization
    struct sockaddr_in serverAddress, clientAddress;
    PClientOrLodiServertoPKEServer recMessage;
    PKServerToPClientOrLodiClient sendMessage;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    unsigned int clientAddressLength;
    RegisteredUser users[20];
    int userCounter = 0;
    unsigned long keyFinder = 0;


    printf("[PKE Server] module loaded.\n");
    // Check  if socket is made
    if (sock < 0) {
        perror("Socket() failed");
        return 1;
    }
    // Configure server address structure
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress.sin_port = htons(5060); //I picked this at random

    // Bind socket
    if (bind(sock, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("bind() failed");
        close(sock);
        return 1;
    }
    printf("[PKE Server]: listening on port 5060...\n");

    clientAddressLength = sizeof(clientAddress);
    while (1) { // Shouldn't end
        memset(&recMessage, 0, sizeof(recMessage));
        ssize_t recvLength = recvfrom(sock, &recMessage, sizeof(recMessage), 0,
            (struct sockaddr*)&clientAddress, &clientAddressLength);
        if (recvLength < 0) {
            perror("recvfrom() failed");
            continue;
        }

        printf("[PKE Server]: Message received from %s:%d\n", inet_ntoa(clientAddress.sin_addr), ntohs(clientAddress.sin_port));
        printf("[PKE Server]: Message Type: %d \n", recMessage.messageType);
        printf("[PKE Server]: User ID: %u\n", recMessage.userID);
        printf("[PKE Server]: Public Key: %lu \n", recMessage.publicKey);

        if (recMessage.messageType == registerKey) {  //if messageType = 0 then enter here
            // store user info in an array
            users[userCounter].userID = recMessage.userID;
            users[userCounter].publicKey = recMessage.publicKey;
            printf("[PKE Server]: IDuser: %lu, IDrec: %lu, Keyuser: %lu, Keyrec: %lu, \n", users[userCounter].userID,
                users[userCounter].publicKey, recMessage.userID, recMessage.publicKey);

            // prep return info
            memset(&sendMessage, 0, sizeof(sendMessage));
            sendMessage.messageType = ackRegisterKey;
            sendMessage.userID = recMessage.userID;
            sendMessage.publicKey = recMessage.publicKey;

            printf("[PKE Server]: Registered user %u with key %lu\n", recMessage.userID, recMessage.publicKey);
            if (sendto(sock, &sendMessage, sizeof(sendMessage), 0,
                (struct sockaddr*)&clientAddress, clientAddressLength) != sizeof(sendMessage)) {
                perror("sendto() failed");

            }
            userCounter++; //increment counter of registered users
        }

        else if (recMessage.messageType == requestKey) {  //handle the case where the user is already registered messageType = 1
            //keyFinder = 0;
           // for (int i = 0; i < userCounter; i++) { //iterate up to the number of registered users
           //     if (users[i].userID == recMessage.userID) {
           //         keyFinder = users[i].publicKey;
           //         break;
           //     }
           // }
            //sendMessage.messageType = responsePublicKey;
            memset(&sendMessage, 0, sizeof(sendMessage));
            sendMessage.userID = recMessage.userID;
            sendMessage.publicKey = users[sendMessage.userID].publicKey;

            if (sendto(sock, &sendMessage, sizeof(sendMessage), 0,
                (struct sockaddr*)&clientAddress, clientAddressLength) != sizeof(sendMessage)) {
                perror("sendto() failed");
            }

            else {
                printf("[PKE Server]: Sent public key %lu for user %u\n", users[sendMessage.userID].publicKey, sendMessage.userID);
            }
        }
    }
    close(sock);
    return 0;
}
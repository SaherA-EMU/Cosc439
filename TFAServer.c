#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MAX 5
#define BUFFSIZE 256

typedef struct {
    int stat;
} AuthList;

// This will allow us to know if that user has activated TFA or not
AuthList authorized[20];


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

typedef struct {
    enum { registerKey, requestKey } messageType;
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

// RSA encryption, works for any power mod function assuming the given N is 299.
long RSAencrypt(long x, long y) {
    int result = x;
    int mod4 = (x * x * x * x) % 299;
    result = mod4 * mod4;
    result = result % 299;
    while (y > 11) {
        result = result * mod4;
        result = result % 299;
        y = y - 4;
    }
    int finish = 1;
    for (int i = 0; i < y - 8; i++) {
        finish = finish * x;
    }
    finish = finish % 299;
    result = result * finish;
    result = result % 299;
    return result;
}

int main(int argc, char *argv[]) {
    
    /*if (argc != 2) {
        fprintf(stderr, "Usage: %s <Port Number>\n", argv[0]);
        exit(1);
    } */
// Initialize server
    printf("TFAServer module loaded.\n");

    //initialize the list of authorized users
    for (int i = 0; i < 20; i++) {
        authorized[i].stat = 0;
    }

    //unsigned short serverPort = (unsigned short)atoi(argv[1]);
    int serverSock;
    struct sockaddr_in serverAddr, clientAddr;
    //socklen_t clientLen = sizeof(clientAddr);
// Create socket
    serverSock = socket(AF_INET, SOCK_DGRAM, 0);
    socklen_t clientLen = sizeof(clientAddr);
// Create socket
    serverSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (serverSock < 0) {
        perror("Socket() failed");
        exit(1);
    }
    printf("[TFA Server]: Socket created successfully.\n");
// Configure server address structure
    printf("[TFA Server]: Socket created successfully.\n");
// Configure server address structure
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;                /* IPv4*/
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming connection*/
    serverAddr.sin_port = htons(7000);        /* convert host to network short(Local port) */
// Bind, listen, and receive
    if (bind(serverSock, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
        perror("Bind() failed");
        exit(1);
    }
    printf("[TFA Server]: Bind completed successfully.\n");
    printf("[TFA Server]: Listening on port 7000");
    while(1) { // Server does not close.

        // receive timestamp and digital sig
        TFAClientOrLodiServerToTFAServer recvMessage;
        memset(&recvMessage, 0, sizeof(recvMessage));
        ssize_t recvLength = recvfrom(serverSock, &recvMessage, sizeof(recvMessage), 0,
                                    (struct sockaddr *) &clientAddr, &clientLen);
        if (recvLength < 0) {
            perror("Recvfrom() failed");
            close(serverSock);
            exit(1);
        }

        // ack received message
        printf("\n[TFA Server]: Received message from %s:%u\n",inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
        printf("[TFA Server]: messageType=%d userID=%u timestamp=%lu digitalSig=%lu \n", recvMessage.messageType, recvMessage.userID, recvMessage.timestamp, recvMessage.digitalSig);
        if(recvMessage.messageType == registerTFA){
            printf("[TFA Server]: Received RegRequest from user %u\n", recvMessage.userID);
            printf("[TFA Server]: Received timestamp: %u\n", recvMessage.timestamp);
            printf("[TFA Server]: Received digitalSig %u\n", recvMessage.digitalSig);

            // Create new socket. request key from the PKE server
            int PKEsock = socket(AF_INET, SOCK_DGRAM, 0);
            if (PKEsock < 0) {
                perror("Socket() failed");
                return 1;
            }

            //char IPAddress[16] = "127.0.0.1";

            // Connect to the PKEServer
            struct sockaddr_in PserverAddr;
            memset(&PserverAddr, 0, sizeof(PserverAddr));
            PserverAddr.sin_family = AF_INET;
            //PserverAddr.sin_addr.s_addr = inet_addr(IPAddress);
            PserverAddr.sin_addr.s_addr = INADDR_ANY;
            PserverAddr.sin_port = htons(5060);
            printf("[TFA Server]: serverAddr configured.\n");

            if (connect(PKEsock, (struct sockaddr*)&PserverAddr, sizeof(PserverAddr)) < 0) {
                perror("Connect() failed");
                close(PKEsock);
                return 1;
            }

            printf("[TFA Server]: Connected to [PKE server] successfully.\n");

            // Send the userID over to the pke server to get their publicKey
            PClientOrLodiServertoPKEServer userInfo;
            memset(&userInfo, 0, sizeof(userInfo));
            userInfo.messageType = requestKey;
            userInfo.userID = recvMessage.userID;
            if (sendto(PKEsock, &userInfo, sizeof(userInfo), 0,
                (struct sockaddr*)&PserverAddr, sizeof(PserverAddr)) != sizeof(userInfo)) {
                perror("Sendto() failed");
                close(PKEsock);
                return 1;
            }
            printf("[TFA Server]: Public key requested.\n");

            // receive the key
            socklen_t addrLen = sizeof(PserverAddr);
            memset(&userInfo, 0, sizeof(userInfo));
            if (recvfrom(PKEsock, &userInfo, sizeof(userInfo), 0, (struct sockaddr*)&PserverAddr, &addrLen) <= 0) {
                perror("Recv() failed");
                close(PKEsock);
                return 1;
            }


            printf("[TFA Server]: Public key received.\n");



        //check the digitalSig against the public key
            //printf("Key: %lu\n", userInfo.publicKey);
            //printf("Stamp: %lu\n", recvMessage.timestamp);
            //printf("DigSig: %lu\n", RSAencrypt(recvMessage.digitalSig, userInfo.publicKey));
            printf("Stamp: %lu, DigSig: %lu, Key: %lu\n", recvMessage.timestamp, recvMessage.digitalSig, userInfo.publicKey);
            if (recvMessage.timestamp != RSAencrypt(recvMessage.digitalSig, userInfo.publicKey)) {
                printf("[TFA Server]: Incorrect public key received.\n");
                perror("Recv() failed");
                close(PKEsock);
                return 1;
            }

            authorized[userInfo.userID].stat = 1;
            printf("[TFA Server]: Public key validated.\n");
            
            //Send confirmation back to client
            TFAServerToClient confirmMessage;
            memset(&confirmMessage, 0, sizeof(confirmMessage));
            confirmMessage.messageType = confirmTFA;


            sendto(serverSock, &confirmMessage, sizeof(confirmMessage), 0,(struct sockaddr*) &clientAddr, clientLen);
            printf("[TFA Server]: Sent confirmTFA to user %u\n", recvMessage.userID);

            //Wait for acknowledgment from client
            TFAClientOrLodiServerToTFAServer ackMessage;
            ssize_t ackLength = recvfrom(serverSock, &ackMessage, sizeof(ackMessage), 0,
                                        (struct sockaddr *) &clientAddr, &clientLen);
            if( ackLength > 0 && ackMessage.messageType == ackRegTFA) {
                printf("[TFA Server]: Received ackRegTFA from user %u\n", ackMessage.userID);
                printf("[TFA Server]: Registration process completed for user %u\n", ackMessage.userID);
            } else {
                printf("[TFA Server]: Failed to receive ackRegTFA from user %u\n", recvMessage.userID);
            }
            printf("[TFA Server]: TFA confirmed for user %u\n", recvMessage.userID);
        }
        if (recvMessage.messageType == requestAuth) {

            //set up sock to connect to TFAClient for ack push TFA
            printf("[TFA Server]: Received authRequest.\n");
            PKServerToPClientOrLodiClient responseAuth;
            memset(&responseAuth, 0, sizeof(responseAuth));

            TFAServerToClient pushAuth;
            memset(&pushAuth, 0, sizeof(pushAuth));
            pushAuth.messageType = ackPushTFA;
            if(authorized[recvMessage.userID].stat == 1){
                pushAuth.userID = recvMessage.userID;
            }
            else{
                pushAuth.userID = -1;
            }
            while (1){
                if(sendto(serverSock, &pushAuth, sizeof(pushAuth), 0, 
                    (struct sockaddr*)&clientAddr,clientLen) != sizeof(pushAuth)){
                    printf("[TFA Server]: TFAClient not ready to receive. waiting 5 seconds before trying again\n");
                    usleep(5000); // wait 5 seconds before trying again
                }else{
                    printf("[TFA Server]: TFA Client found. sent push to TFAClient\n");
                    break;
                }
            }
            if(recvfrom(serverSock, &pushAuth, sizeof(pushAuth), 0,
                        (struct sockaddr*) &clientAddr, &clientLen) <= 0){
                            perror("[TFA Server]: AckPushTFA not received. \n");
                            close(serverSock);
                         }    

            // 0 means the user does not yet have TFA active
            if (authorized[recvMessage.userID].stat == 0) {

                responseAuth.userID = -1;
                printf("[TFA Server]: user %u .\n", responseAuth.userID);
                ssize_t pushTFA = sendto(serverSock, &responseAuth, sizeof(responseAuth), 0,
                    (struct sockaddr*)&clientAddr, clientLen);
                printf("[TFA Server]: user %u does not have TFA activated.\n", recvMessage.userID);
            }
            // otherwise, TFA is considered active
            else {
                responseAuth.userID = recvMessage.userID;
                printf("[TFA Server]: user %u .\n", responseAuth.userID);
                ssize_t pushTFA = sendto(serverSock, &responseAuth, sizeof(responseAuth), 0,
                    (struct sockaddr*)&clientAddr, clientLen);
                printf("[TFA Server]: user %u does not have TFA activated.\n", recvMessage.userID);
            }
            // receive verification for the TFA client
            ssize_t recvLength = recvfrom(serverSock, &responseAuth, sizeof(responseAuth), 0,
                (struct sockaddr*)&clientAddr, &clientLen);
            printf("[TFA Server]: Received message from TFAClient\n", recvMessage.userID);
            close(serverSock);

            ssize_t pushTFA = sendto(serverSock, &responseAuth, sizeof(responseAuth), 0,
                (struct sockaddr*)&clientAddr, clientLen);
            printf("[TFA Server]: sent final auth to Lodi Server\n", recvMessage.userID);
        }
    }
}
    
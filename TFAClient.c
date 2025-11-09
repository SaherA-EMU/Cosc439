#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for recvfrom() and sendto() */
#include <sys/socket.h> /* for recvfrom() and sendto() */
#include <unistd.h>     /* for close() */
#include <string.h>     /* for memset() */
#include <arpa/inet.h>  /* for inet_addr() and htons() */
#include <time.h>       /* for timestamp/digitalSig -> time(&var) */
#include <stdbool.h>    // adds boolean operator
#include <stdlib.h>     // just for rand(), really

// structs to be sent and received
// structs to be sent and received
typedef struct {
    enum { registerTFA, ackRegTFA, ackPushTFA, requestAuth} messageType;
    unsigned int userID;
    unsigned long timestamp;
    unsigned long digitalSig;
} TFAClientOrLodiServerToTFAServer;

typedef struct {
    enum { confirmTFA, pushTFA } messageType;
    unsigned int userID;
} TFAServerToClient;

long privateKeys[20] = { 13,  17,  19, 23,  25,  29,  31, 35,  37,  41, 43,  47, 49,  59, 67,  71,  73,  79,  85, 89 };

// NOTE: this doesnt handle powers of y below 8, which is a bit of an oversight. Too late to fix directly so keys adjusted.
// RSA encryption, works for any power mod function assuming the given N is 299.
long RSAencrypt(long x, long y) {
    int result = 1;
    for(int i = 0; i < y; i++){
        result = result * x;
        result = result % 299;
    }
    return result;
}


int main() {
    printf("[TFA Client] module loaded.\n");

    struct sockaddr_in serverAddr;

    // Create socket and connect to server
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket() failed");
        return 1;
    }

    // Configure server address structure
    printf("[TFA Client]: Socket created successfully.\n");


    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    //serverAddr.sin_addr.s_addr = inet_addr(IPAddress);
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(7000);
    printf("[TFA Client]: serverAddr configured.\n");

    // Connect to server
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Connect() failed");
        close(sock);
        return 1;
    }
    printf("[TFA Client]: Connected to server successfully.\n");

    bool cont = true;
    while (cont) { // loop until told not to

        printf("[TFA Client]: Type 'A' to authorize TFA for a user. Enter anything else to verify a login, or 'Q' to exit.\n");
        // Ask user for input


        char query[16];
        scanf("%15s", query);
        if (strcmp(query, "A") == 0 || strcmp(query, "a") == 0) {

            /*printf("[TFA Client]: Please enter your IP Address: ");
            char IPAddress[16];
            scanf("%15s", IPAddress);*/
            //printf("[TFA Client]: Please enter your Port Number: ");
            //unsigned int portNumber;
            //scanf("%u", &portNumber);
            //printf("[TFA Client]: User ID: %u, IP Address: %s, Port Number: %u\n", userID, IPAddress, portNumber);

            printf("[TFA Client]: Please enter your User ID: ");
            unsigned int userID;
            scanf("%u", &userID);

            printf("[TFA Client]: User ID: %u\n", userID);

            // Send registration message to server
            TFAClientOrLodiServerToTFAServer regMessage;
            memset(&regMessage, 0, sizeof(regMessage));
            regMessage.messageType = registerTFA;
            regMessage.userID = userID;

            // get timestamp and then encrypt it.
            time_t timer = time(&timer);
            long CurTime = timer;
            CurTime = CurTime % 299;
            regMessage.timestamp = CurTime;
            regMessage.digitalSig = RSAencrypt(CurTime, privateKeys[userID]);
            printf("[TFA Client]: Timestamp: %lu, DigitalSig: %lu\n", CurTime, RSAencrypt(CurTime, privateKeys[userID]));

            // Send to TFA Server
            if (sendto(sock, &regMessage, sizeof(regMessage), 0,
                (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != sizeof(regMessage)) {
                perror("Sendto() failed");
                close(sock);
                return 1;
            }

            printf("[TFA Client]: Registration message sent to server.\n");
            // Receive response from server
            TFAServerToClient responseMessage;
            memset(&responseMessage, 0, sizeof(responseMessage));
            socklen_t addrLen = sizeof(serverAddr);

            if (recvfrom(sock, &responseMessage, sizeof(responseMessage), 0, (struct sockaddr*)&serverAddr, &addrLen) <= 0) {
                perror("Recv() failed");
                close(sock);
                return 1;
            }
            printf("[TFA Client]: Response received from server.\n");
            printf("[TFA Client]: Message Type: %d\n", responseMessage.messageType);
            printf("[TFA Client]: User ID: %u\n", responseMessage.userID);
            //printf("[TFA Client]: Timestamp: %lu\n", responseMessage.timestamp);
            //printf("[TFA Client]: Digital Signature: %lu\n", responseMessage.digitalSig);

            // Send acknowledgment back to server
            if (responseMessage.messageType == confirmTFA) {
                TFAClientOrLodiServerToTFAServer ackMessage;
                ackMessage.messageType = ackRegTFA;
                ackMessage.userID = userID;
                if (sendto(sock, &ackMessage, sizeof(ackMessage), 0,
                    (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != sizeof(ackMessage)) {
                    perror("Sendto() failed");
                    close(sock);
                    return 1;
                }
                printf("[TFA Client]: Acknowledgment message sent to server.\n");
            }
        }

        // verify a TFA login
        else if (strcmp(query, "Q") != 0 && strcmp(query, "q") != 0) {

            printf("[TFA Client]: Awaiting push notification.");

            // Await a push notification from TFA Server
            TFAServerToClient TFAVer;
            TFAClientOrLodiServerToTFAServer TFAResponse;
            memset(&TFAVer, 0, sizeof(TFAVer));
            memset(&TFAResponse, 0, sizeof(TFAResponse));
            TFAResponse.messageType = ackPushTFA;
            
            socklen_t AddrLen = sizeof(serverAddr);
            if (recvfrom(sock, &TFAVer, sizeof(TFAVer), 0, (struct sockaddr*)&serverAddr, &AddrLen) <= 0) {
                perror("Recv() failed");
                close(sock);
                return 1;
            }

            printf("[TFA Client]: Received message push from TFA Server.");
            printf("[TFA Client]: UserID: %lu.\n",TFAVer.userID);

            // cover Case where user doesn't have TFA activated
            if (TFAVer.userID == -1) {

                TFAResponse.userID = TFAVer.userID;
                if (sendto(sock, &TFAResponse, sizeof(TFAResponse), 0,
                    (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != sizeof(TFAResponse)) {
                    close(sock);
                    return 1;
                }
                printf("[TFA Client]: User TFA not set up.\n");
            }
            else {


                // Prompt Verification
                printf("[TFA Client]: Type 'Y' if this is you logging in.\n");
                char ver[16];
                scanf("%15s", ver);
                // if Y, then accepted, else denied
                if (strcmp(ver, "Y") == 0 || strcmp(query, "y") == 0) {
                    TFAResponse.userID = TFAVer.userID;
                    if (sendto(sock, &TFAResponse, sizeof(TFAResponse), 0,
                        (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != sizeof(TFAResponse)) {
                        perror("Sendto() failed");
                        close(sock);
                        return 1;
                    }
                    printf("[TFA Client]: User accepted TFA Verification.\n");
                }
                //denied case
                else {
                    TFAResponse.userID = 20;
                    if (sendto(sock, &TFAResponse, sizeof(TFAResponse), 0,
                        (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != sizeof(TFAResponse)) {
                        perror("Sendto() failed");
                        close(sock);
                        return 1;
                    }
                    printf("[TFA Client]: User denied TFA Verification.\n");
                }
            }
        }

        // quit process
        else {
            cont = false;
            printf("[Lodi Client]: Terminating process.\n");

        }
    }
    close(sock);
    return 0;
}
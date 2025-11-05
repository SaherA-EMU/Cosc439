#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for recvfrom() and sendto() */
#include <unistd.h>     /* for close() */
#include <string.h>     /* for memset() */
#include <arpa/inet.h>  /* for inet_addr() and htons() */

// structs to be sent and received
typedef struct {
    enum { registerTFA, ackRegTFA, ackPushTFA, requestAuth} messageType;
    unsigned int userID;
    unsigned long timestamp;
    unsigned long digitalSig;
} TFAClientOrLodiServerToTFAServer;

int main() {
// Ask user for input
    printf("TFAClient module loaded.\n");
    printf("[TFA Client]: Please enter your User ID: ");
    unsigned int userID;
    scanf("%u", &userID);
    printf("[TFA Client]: Please enter your IP Address: ");
    char IPAddress[16];
    scanf("%15s", IPAddress);
    printf("[TFA Client]: Please enter your Port Number: ");
    unsigned int portNumber;
    scanf("%u", &portNumber);
    printf("[TFA Client]: User ID: %u, IP Address: %s, Port Number: %u\n", userID, IPAddress, portNumber);
// Create socket and connect to server
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket() failed");
        return 1;
    }
// Configure server address structure
    printf("[TFA Client]: Socket created successfully.\n");
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(IPAddress);
    serverAddr.sin_port = htons(portNumber);
    printf("[TFA Client]: serverAddr configured.\n");
// Connect to server
    if (connect(sock, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
        perror("Connect() failed");
        close(sock);
        return 1;
    }
    printf("[TFA Client]: Connected to server successfully.\n");
// Send registration message to server
    TFAClientOrLodiServerToTFAServer regMessage;
    regMessage.messageType = registerTFA;
    regMessage.userID = userID;
    regMessage.timestamp =  123456789; // Example timestamp
    regMessage.digitalSig = 987654321; // Example digital signature
    if(sendto(sock, &regMessage, sizeof(regMessage), 0 ,
        (struct sockaddr *) &serverAddr, sizeof(serverAddr)) != sizeof(regMessage)) {
        perror("Sendto() failed");
        close(sock);
        return 1;
    }
    printf("[TFA Client]: Registration message sent to server.\n");
// Receive response from server
    TFAClientOrLodiServerToTFAServer responseMessage;
    socklen_t addrLen = sizeof(serverAddr);
    if(recvfrom(sock, &responseMessage, sizeof(responseMessage), 0, (struct sockaddr *) &serverAddr, &addrLen) <= 0) {
        perror("Recv() failed");
        close(sock);
        return 1;
    }
    printf("[TFA Client]: Response received from server.\n");
    printf("[TFA Client]: Message Type: %d\n", responseMessage.messageType);
    printf("[TFA Client]: User ID: %u\n", responseMessage.userID);
    printf("[TFA Client]: Timestamp: %lu\n", responseMessage.timestamp);
    printf("[TFA Client]: Digital Signature: %lu\n", responseMessage.digitalSig);
    //
    // Send acknowledgment back to server
    if(responseMessage.messageType == ackRegTFA) {
        TFAClientOrLodiServerToTFAServer ackMessage;
        ackMessage.messageType = ackRegTFA;
        ackMessage.userID = userID;
        ackMessage.timestamp =  0;
        ackMessage.digitalSig = 0;
        if(sendto(sock, &ackMessage, sizeof(ackMessage), 0 ,
            (struct sockaddr *) &serverAddr, sizeof(serverAddr)) != sizeof(ackMessage)) {
            perror("Sendto() failed");
            close(sock);
            return 1;
        }
        printf("[TFA Client]: Acknowledgment message sent to server.\n");
    }
    close(sock);
    return 0;
}
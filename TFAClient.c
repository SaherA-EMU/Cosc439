#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for recv() and send() */
#include <unistd.h>     /* for close() */
#include <string.h>     /* for memset() */
#include <arpa/inet.h>  /* for inet_addr() and htons() */

typedef struct {
    enum { registerTFA, ackRegTFA, ackPushTFA, requestAuth} messageType;
    unsigned int userID;
    unsigned long timestamp;
    unsigned long digitalSig;
} TFAClientOrLodiServerToTFAServer;

int main() {
    printf("TFAClient module loaded.\n");
    printf("Please enter your User ID: ");
    unsigned int userID;
    scanf("%u", &userID);
    printf("Please enter your IP Address: ");
    char IPAddress[16];
    scanf("%15s", IPAddress);
    printf("Please enter your Port Number: ");
    unsigned int portNumber;
    scanf("%u", &portNumber);
    printf("User ID: %u, IP Address: %s, Port Number: %u\n", userID, IPAddress, portNumber);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket() failed");
        return 1;
    }

    printf("Socket created successfully.\n");
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(IPAddress);
    serverAddr.sin_port = htons(portNumber);

    printf("serverAddr configured.\n");
    
}
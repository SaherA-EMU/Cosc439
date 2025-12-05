#include <stdio.h>      // for printf() and fprintf()
#include <sys/socket.h> // for recvfrom() and sendto()
#include <unistd.h>     // for close()
#include <stdlib.h>     // just for rand(), really
#include <string.h>     // for memset()
#include <arpa/inet.h>  // for inet_addr() and htons()

// privateKey to encrypt on login
// long privateKeys[20] = {  5,   7, 13,  17,  19, 23,  25,  29,  31, 35,  37,  41, 43,  47, 49,  59, 67,  71,  73,  79};
// send the associated public key when registering the key with the PKEServer.
// long publicKeys[20] =  { 53, 151, 61, 233, 139, 23, 169, 173, 247, 83, 157, 161, 43, 191, 97, 179, 67, 119, 217, 127};

typedef struct
{
    char name[16];
} NameList;

NameList Names[20];

typedef struct
{
    enum
    {
        registerTFA,
        ackRegTFA,
        ackPushTFA,
        requestAuth
    } messageType;
    unsigned int userID;
    unsigned long timestamp;
    unsigned long digitalSig;
} TFAClientOrLodiServerToTFAServer;

typedef struct
{
    enum
    {
        ackLogin
    } messageType;
    unsigned int userID;
} LodiServerToLodiClientAcks;

typedef struct
{
    enum
    {
        ackRegisterKey,
        responsePublicKey,
        responseAuth,
        login
    } messageType;
    unsigned int userID;
    unsigned int publicKey;
    unsigned int recipientID;
    unsigned long timestamp;
    unsigned long digitalSig;
} PKServerToPClientOrLodiClient;

/*typedef struct {
    enum {responseAuth} messageType;
    unsigned int userID;
} TFAServerToLodiServer; */

typedef struct
{
    enum
    {
        registerKey,
        requestKey
    } messageType;
    unsigned int userID;
    unsigned long publicKey;
} PClientOrLodiServertoPKEServer;

typedef struct
{
    enum
    {
        Login,
        Post,
        Feed,
        Follow,
        Unfollow,
        Logout
    } request_Type;      // same as an unsigned int
    unsigned int UserID; // unique client identifier
    unsigned int IdolID; // unique client identifier
    char message[100];   // text message
} LodiClientMessage;     // an unsigned int is 32 bits = 4 bytes

typedef struct
{
    enum
    {
        AckLogin,
        AckPost,
        AckFeed,
        AckFollow,
        AckUnfollow,
        AckLogout
    } message_Type;      // same as unsigned int
    unsigned int IdolID; // unique client identifier
    char message[100];   // text message
} LodiServerMessage;     // an unsigned int is 32 bits = 4 bytes

long RSAencrypt(long x, long y) {
    int result = 1;
    for (int i = 0; i < y; i++)
    {
        result = result * x;
        result = result % 299;
    }
    return result;
}

int main(int argc, char *argv[]) {
    // variable declaration and intialization for PKE
    int PKESock, lodiSock, TFASock, TCPSock;
    struct sockaddr_in pkeAddress, serverAddress, clientAddress, TFAAddress, TCPServer, TCPClient;
    socklen_t clientAddressLength = sizeof(pkeAddress);
    socklen_t pkeAddressLength = sizeof(pkeAddress);
    PClientOrLodiServertoPKEServer requestMsg, PKEKey;
    PKServerToPClientOrLodiClient responseMsg;
    TFAClientOrLodiServerToTFAServer authReq;
    LodiServerToLodiClientAcks loginAuth;
    LodiClientMessage clientMessage;
    LodiServerMessage serverMessage;
    char *AckMessage;

    printf("[Lodi Server]: Module Loaded. \n");

    //easy port shift
    int n = 0;
    if (argc >= 2) {
         n = atoi(argv[1]);
         printf("n: %u", n);
    }

    // Socket creation this server
    lodiSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (lodiSock < 0)
    {
        perror("Socket() failed");
        exit(1);
    }

    // Configure server address structure
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress.sin_port = htons(6670 + n); // I picked this at random

    // Bind socket
    if (bind(lodiSock, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        perror("bind() failed");
        close(lodiSock);
        return 1;
    }
    printf("[Lodi Server]: listening on port 6670...\n");

    while (1)
    { // Shouldn't end

        // Wait to receive response
        memset(&responseMsg, 0, sizeof(responseMsg));
        ssize_t recvLength = recvfrom(lodiSock, &responseMsg, sizeof(responseMsg), 0,
                                      (struct sockaddr *)&clientAddress, &clientAddressLength);
        if (recvLength < 0)
        {
            perror("recvfrom() failed");
            continue;
        }
        printf("[Lodi Server]: Login request received\n");

        if (responseMsg.messageType == login)
        {

            // Create new socket. request key from the PKE server
            PKESock = socket(AF_INET, SOCK_DGRAM, 0);
            if (PKESock < 0)
            {
                perror("Socket() failed");
                return 1;
            }

            // Set up for PKE Server Address
            memset(&pkeAddress, 0, sizeof(pkeAddress));
            pkeAddress.sin_family = AF_INET;
            pkeAddress.sin_addr.s_addr = INADDR_ANY;
            pkeAddress.sin_port = htons(5060 + n);

            printf("[Lodi Server]: PKE serverAddr configured.\n");

            // Connect to PKEServer
            if (connect(PKESock, (struct sockaddr *)&pkeAddress, sizeof(pkeAddress)) < 0)
            {
                perror("Connect() failed");
                close(PKESock);
                return 1;
            }

            memset(&requestMsg, 0, sizeof(requestMsg));
            requestMsg.messageType = requestKey;
            requestMsg.userID = responseMsg.userID;

            printf("[Lodi Server]: Connected to PKEserver successfully.\n");

            // Send request to the PKEServer
            if (sendto(PKESock, &requestMsg, sizeof(requestMsg), 0,
                       (struct sockaddr *)&pkeAddress, sizeof(pkeAddress)) != sizeof(requestMsg))
            {
                perror("Sendto() failed");
                close(PKESock);
                return 1;
            }

            printf("[Lodi Server]: Public key requested.\n");

            // receive the public key from the PKEServer
            memset(&PKEKey, 0, sizeof(PKEKey));
            if (recvfrom(PKESock, &PKEKey, sizeof(PKEKey), 0, (struct sockaddr *)&pkeAddress, &pkeAddressLength) <= 0)
            {
                perror("Recv() failed");
                close(PKESock);
                return 1;
            }

            printf("[Lodi Server]: Public key received.\n");

            // test if the public key matches
            printf("Stamp: %lu, DigSig: %lu, Key: %lu\n", responseMsg.timestamp, responseMsg.digitalSig, PKEKey.publicKey);
            if (responseMsg.timestamp != RSAencrypt(responseMsg.digitalSig, PKEKey.publicKey))
            {
                printf("[Lodi Server]: Incorrect public key received.\n");
                perror("Recv() failed");
                close(PKESock);
                return 1;
            }
            printf("[Lodi Server]: Public key validated.\n");
            printf("[Lodi Server]: Sending Request to TFA Server.\n");

            // Setup sock to connect to TFA Server
            TFASock = socket(AF_INET, SOCK_DGRAM, 0);
            if (TFASock < 0)
            {
                perror("Socket() failed");
                return 1;
            }

            // Set up for TFA Server Address
            memset(&TFAAddress, 0, sizeof(TFAAddress));
            TFAAddress.sin_family = AF_INET;
            TFAAddress.sin_addr.s_addr = INADDR_ANY;
            TFAAddress.sin_port = htons(7000 + n);

            printf("[Lodi Server]: TFA serverAddr configured.\n");

            // Connect to PKEServer

            if (connect(TFASock, (struct sockaddr *)&TFAAddress, sizeof(TFAAddress)) < 0)
            {
                perror("Connect() failed");
                close(PKESock);
                return 1;
            }
            printf("[Lodi Server]: Connected to TFA Server.\n");

            // set up reqMsg with userID and message type
            memset(&authReq, 0, sizeof(authReq));
            authReq.messageType = requestAuth;
            authReq.userID = responseMsg.userID;

            // send user auth to TFAServer
            if (sendto(TFASock, &authReq, sizeof(authReq), 0,
                       (struct sockaddr *)&TFAAddress, sizeof(TFAAddress)) != sizeof(authReq))
            {
                perror("Sendto() failed");
                close(PKESock);
                return 1;
            }
            printf("[Lodi Server]: Auth Request Sent.\n");

            // receive for user from the TFAServer
            memset(&authReq, 0, sizeof(authReq));
            socklen_t TFAAddressLength = sizeof(TFAAddress);
            if (recvfrom(TFASock, &authReq, sizeof(authReq), 0, (struct sockaddr *)&TFAAddress, &TFAAddressLength) <= 0)
            {
                perror("Recv() failed");
                close(TFASock);
                return 1;
            }

            printf("[Lodi Server]: Auth Request received. now Verifying.\n");

            // Setup loginAuth variable for final checks
            memset(&loginAuth, 0, sizeof(loginAuth));
            loginAuth.messageType = ackLogin;

            // Case: if ID is a match and TFA Server Verifies.
            if (authReq.userID == responseMsg.userID)
            {
                loginAuth.userID = authReq.userID;
                printf("[Lodi Server]: User %u Auth Request verified. Logging in.\n", authReq.userID);

                if (sendto(lodiSock, &loginAuth, sizeof(loginAuth), 0,
                           (struct sockaddr *)&clientAddress, sizeof(clientAddress)) != sizeof(loginAuth))
                {
                    perror("Sendto() failed");
                    close(lodiSock);
                    return 1;
                }
                printf("Check 1");
                // An accepted login will start a TCP connection with the LodiClient.
                // TCP STARTS HERE * TCP Socket set up.
                memset(&TCPServer, 0, sizeof(TCPServer));
                TCPServer.sin_family = AF_INET;
                printf("Check 2");
                TCPServer.sin_addr.s_addr = INADDR_ANY;
                TCPServer.sin_port = htons(7040 + n);
                TCPSock = socket(AF_INET, SOCK_STREAM, 0);
                // socklen_t TCPServerAddress = sizeof(TCPServer);
                printf("Check 3");
                memset(&TCPClient, 0, sizeof(TCPClient));
                socklen_t TCPClientLen = sizeof(TCPClient);
                printf("Check 4");

                // binding the socket
                if (bind(TCPSock, (struct sockaddr *)&TCPServer, sizeof(TCPServer)) < 0)
                {
                    perror("[Lodi Server]: bind failed");
                    return 0;
                }
                printf("Check 5");

                // listen for connections from the lodiClient.
                listen(TCPSock, 5);
                printf("Check 6");
                int clientSock = accept(TCPSock, (struct sockaddr *)&TCPClient, &TCPClientLen);
                if (clientSock < 0)
                {
                    perror("[Lodi Server]: accept error");
                }
                printf("Check 7");
                while (1)
                { // listen for input here
                    printf("[Lodi Server]: Listening for commands.");
                    

                    int incomingBytes = recv(clientSock, &clientMessage, sizeof(clientMessage), 0);
                    printf("Check 8");
                    if (incomingBytes <= 0)
                    {
                        break;
                    }
                    // filter by message_Type
                    switch (clientMessage.request_Type)
                    {
                    case 0:
                        memset(&serverMessage, 0, sizeof(serverMessage));
                        serverMessage.message_Type = clientMessage.request_Type;
                        strcpy(serverMessage.message, "Server: Login Acknowledged");
                        break;
                    case 1:
                        memset(&serverMessage, 0, sizeof(serverMessage));
                        serverMessage.message_Type = clientMessage.request_Type;
                        strcpy(serverMessage.message, "Server: Post Acknowledged");
                        break;
                    case 2:
                        memset(&serverMessage, 0, sizeof(serverMessage));
                        serverMessage.message_Type = clientMessage.request_Type;
                        strcpy(serverMessage.message, "Server: Feed Acknowledged");
                        break;
                    case 3:
                        memset(&serverMessage, 0, sizeof(serverMessage));
                        serverMessage.message_Type = clientMessage.request_Type;
                        strcpy(serverMessage.message, "Server: Follow Acknowledged");
                        break;
                    case 4:
                        memset(&serverMessage, 0, sizeof(serverMessage));
                        serverMessage.message_Type = clientMessage.request_Type;
                        strcpy(serverMessage.message, "Server: Unfollow Acknowledged");
                        break;
                    case 5:
                        memset(&serverMessage, 0, sizeof(serverMessage));
                        serverMessage.message_Type = clientMessage.request_Type;
                        strcpy(serverMessage.message, "[Lodi Server]: Logout Acknowledged");
                        send(clientSock, &serverMessage, sizeof(serverMessage), 0);
                        break;
                    }
                    send(clientSock, &serverMessage, sizeof(serverMessage), 0);
                } // end of innerTCPwhile loop
                close(clientSock);
                continue;
                // Case: ID does not currently have TFA set up.
                if (authReq.userID == -1)
                {

                    loginAuth.userID = authReq.userID;
                    printf("[Lodi Server]: Auth Request denied.\n");

                    if (sendto(lodiSock, &loginAuth, sizeof(loginAuth), 0,
                               (struct sockaddr *)&clientAddress, sizeof(clientAddress)) != sizeof(loginAuth))
                    {
                        perror("Sendto() failed");
                        close(lodiSock);
                        return 1;
                    }
                }
                // Case: User denies TFA Verification.
                if (authReq.userID == 20)
                {

                    loginAuth.userID = authReq.userID;
                    printf("[Lodi Server]: Auth Request denied.\n");

                    if (sendto(lodiSock, &loginAuth, sizeof(loginAuth), 0,
                               (struct sockaddr *)&clientAddress, sizeof(clientAddress)) != sizeof(loginAuth))
                    {
                        perror("Sendto() failed");
                        close(lodiSock);
                        return 1;
                    }
                }
            }
        }
    }
}
#include <stdio.h>      // for printf() and fprintf()
#include <sys/socket.h> // for recvfrom() and sendto()
#include <unistd.h>     // for close()
#include <stdlib.h>     // just for rand(), really
#include <string.h>     // for memset()
#include <arpa/inet.h>  // for inet_addr() and htons()
#include <time.h>       // for timestamp/digitalSig -> time(&var)
#include <stdbool.h>    // adds boolean operator

// NOTE: this doesnt handle powers of y below 8, which is a bit of an oversight. Too late to fix directly so keys adjusted.
// privateKey to encrypt on login
long privateKeys[20] = {13,  17,  19, 23,  25,  29,  31, 35,  37,  41, 43,  47, 49,  59, 67,  71,  73,  79,  85, 89};
// send the associated public key when registering the key with the PKEServer.
long publicKeys[20] =  {61, 233, 139, 23, 169, 173, 247, 83, 157, 161, 43, 191, 97, 179, 67, 119, 217, 127, 205, 89};

typedef struct
{
    char name[16];
} NameList;

NameList Names[20];
NameList Pass[20];

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

// RSA encryption, works for any power mod function assuming the given N is 299.
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
    int sock_PKE, sock_Lodi, TCPSock, user_Input;
    struct sockaddr_in pkeAddress, LodiAddress, TCPServer;
    socklen_t pkeAddressLength = sizeof(pkeAddress);
    socklen_t LodiAddressLength = sizeof(LodiAddress);
    PClientOrLodiServertoPKEServer requestMsg;
    PKServerToPClientOrLodiClient loginReq;
    PKServerToPClientOrLodiClient responseMsg;
    LodiClientMessage clientMessage;
    LodiServerMessage serverMessage;
    char *message_text;

    printf("[Lodi Client]: Module Loaded. \n");

    //easy port shift
    int n = 0;
    if (argc >= 2) {
         n = atoi(argv[1]);
         printf("n: %u", n);
    }

    bool cont = true;
    while (cont)
    {
        printf("[Lodi Client]: Type 'R' to register an acount. Enter anything else to login, or 'Q' to exit.\n");

        // Configuration to PKE Server
        memset(&pkeAddress, 0, sizeof(pkeAddress));
        pkeAddress.sin_family = AF_INET;
        pkeAddress.sin_port = htons(5060 + n); // same port as what I put in PKEServer
        // pkeAddress.sin_addr.s_addr = inet_addr("127.0.0.1"); // I just put this to simplify testing
        pkeAddress.sin_addr.s_addr = INADDR_ANY;

        // Configuration to Lodi Server
        memset(&LodiAddress, 0, sizeof(LodiAddress));
        LodiAddress.sin_family = AF_INET;
        LodiAddress.sin_port = htons(6670 + n); // same port as what I put in PKEServer
        // pkeAddress.sin_addr.s_addr = inet_addr("127.0.0.1"); // I just put this to simplify testing
        LodiAddress.sin_addr.s_addr = INADDR_ANY;

        // Determine whether the client wants to register, login, or quit
        char query[16];
        scanf("%15s", query);
        if (strcmp(query, "R") == 0 || strcmp(query, "r") == 0)
        {

            // Socket creation for PKE
            if ((sock_PKE = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
            {
                perror("[Lodi Client]: socket() for PKE failed");
                exit(1);
            }

            // Connect to server
            if (connect(sock_PKE, (struct sockaddr *)&pkeAddress, pkeAddressLength) < 0)
            {
                perror("Connect() failed");
                close(sock_PKE);
                return 1;
            }
            printf("[Lodi Client]: Ready to communicate with PKE Server\n");

            // Assign User ID and Key
            int newID;
            long newKey;
            for (int i = 0; i < 20; i++)
            {
                if (publicKeys[i] > 0)
                {
                    newID = i;
                    newKey = publicKeys[i];

                    // 'retires' that particular ID and Key upon use
                    publicKeys[i] = -1;
                    printf("[Lodi Client]: Please enter a name for your account: \n");
                    scanf("%15s", Names[i].name);
                    printf("[Lodi Client]: Please enter a password for your account: \n");
                    scanf("%15s", Pass[i].name);
                    i = i + 20;
                }
            }

            requestMsg.messageType = registerKey;
            requestMsg.userID = newID;
            requestMsg.publicKey = newKey;

            // sendto PKE server
            if (sendto(sock_PKE, &requestMsg, sizeof(requestMsg), 0, (struct sockaddr *)&pkeAddress, pkeAddressLength) != sizeof(requestMsg))
            {
                perror("{Lodi Client}: sendto() failed");
                close(sock_PKE);
                return 1;
            }
            printf("[Lodi Client]: User info sent \n");

            // recvfrom PKEServer
            memset(&responseMsg, 0, sizeof(responseMsg));
            ssize_t recvLength = recvfrom(sock_PKE, &responseMsg, sizeof(responseMsg), 0, (struct sockaddr *)&pkeAddress, &pkeAddressLength);

            printf("[Lodi Client]: Public key %lu for userID %u: %s has been approved.\n", responseMsg.publicKey, responseMsg.userID, Names[responseMsg.userID].name);
            close(sock_PKE);
        }

        // check loop exit.
        else if (strcmp(query, "Q") != 0 && strcmp(query, "q") != 0)
        {

            char userN[16];
            char passW[16];

            // prompting login. Cycle through to see if any of them match.
            printf("[Lodi Client]: Please enter you username:\n");
            scanf("%15s", userN);
            printf("[Lodi Client]: Please enter you password:\n");
            scanf("%15s", passW);

            // loop through Names[i] for a match.
            for (int i = 0; i < 20; i++)
            {
                if (strcmp(userN, Names[i].name) == 0 && strcmp(passW, Pass[i].name) == 0)
                {
                    // Socket creation for LodiServer.
                    if ((sock_Lodi = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
                    {
                        perror("[Lodi Client]: socket() for Lodi failed");
                        exit(1);
                    }

                    if (connect(sock_Lodi, (struct sockaddr *)&LodiAddress, LodiAddressLength) < 0)
                    {
                        perror("Connect() failed");
                        close(sock_Lodi);
                        return 1;
                    }
                    printf("[Lodi Client]: Ready to communicate with Lodi Server\n");

                    // set userID, get timestamp and appropriate private key
                    loginReq.userID = i;
                    time_t timer = time(&timer);
                    long CurTime = timer % 299;

                    // filling in loginReq data
                    loginReq.messageType = login;
                    loginReq.timestamp = CurTime;
                    loginReq.digitalSig = RSAencrypt(CurTime, privateKeys[i]);

                    if (sendto(sock_Lodi, &loginReq, sizeof(loginReq), 0,
                               (struct sockaddr *)&LodiAddress, sizeof(LodiAddress)) != sizeof(loginReq))
                    {
                        perror("Sendto() failed");
                        close(sock_Lodi);
                        return 1;
                    }
                    printf("[Lodi Client]: User: %u, Stamp: %lu, Sig: %lu\n", loginReq.userID, loginReq.timestamp, loginReq.digitalSig);
                    printf("[Lodi Client]: Login details sent.\n");

                    // recv message here

                    memset(&responseMsg, 0, sizeof(responseMsg));
                    ssize_t recvLength = recvfrom(sock_PKE, &responseMsg, sizeof(responseMsg), 0, (struct sockaddr *)&LodiAddress, &LodiAddressLength);

                    printf("[Lodi Client]: Auth ID: %u", responseMsg.userID);
                    if (responseMsg.userID == -1)
                    {
                        printf("[Lodi Client]: Login for user %u denied.\n", i);
                    }
                    if (responseMsg.userID == 20)
                    {
                        printf("[Lodi Client]: User TFA not set up.\nLogin for user %u denied", i);
                    }
                    if (responseMsg.userID == 21)
                    {
                        printf("[Lodi Client]: User denied verification.\nLogin for user %u denied", i);
                    }
                    // todo: implement TCP HERE
                    TCPSock = socket(AF_INET, SOCK_STREAM, 0);
                    TCPServer.sin_family = AF_INET;
                    TCPServer.sin_addr.s_addr = INADDR_ANY;
                    TCPServer.sin_port = htons(7040 + n);
                    if (connect(TCPSock, (struct sockaddr *)&TCPServer, sizeof(TCPServer)) < 0)
                    {
                        perror("[Lodi Client]: connect failed");
                        return 0;
                    }

                    i = 20;
                    while (1)
                    {
                        // listen for input here
                        printf("----------------------------------\n");
                        printf("[Lodi Client]: Connected to server\n");
                        printf("Please enter 1 to Login, 2 to post a message, 3 to request an idol feed, 4 to follow an idol, 5 to unfollow an idol, or 6 to logout\n");
                        scanf("%d", &user_Input);
                        if (user_Input == 1)
                        {
                            // just asking for Ack Login,really
                            memset(&clientMessage, 0, sizeof(clientMessage));
                            clientMessage.request_Type = 0;
                            send(TCPSock, &clientMessage, sizeof(clientMessage), 0);
                            recv(TCPSock, &serverMessage, sizeof(serverMessage), 0);
                            printf("[Lodi Client]: %s\n", serverMessage.message);
                        }
                        else if (user_Input == 2)
                        {
                            // todo Post() implementation
                            memset(&clientMessage, 0, sizeof(clientMessage));
                            clientMessage.request_Type = 1;
                            send(TCPSock, &clientMessage, sizeof(clientMessage), 0);
                            recv(TCPSock, &serverMessage, sizeof(serverMessage), 0);
                        }
                        else if (user_Input == 3)
                        {
                            // todo requesFeed() implementation
                            memset(&clientMessage, 0, sizeof(clientMessage));
                            clientMessage.request_Type = 2;
                            send(TCPSock, &clientMessage, sizeof(clientMessage), 0);
                            recv(TCPSock, &serverMessage, sizeof(serverMessage), 0);
                        }
                        else if (user_Input == 4)
                        {
                            // todo follow(idol) implementation
                            memset(&clientMessage, 0, sizeof(clientMessage));
                            clientMessage.request_Type = 3;
                            send(TCPSock, &clientMessage, sizeof(clientMessage), 0);
                            recv(TCPSock, &serverMessage, sizeof(serverMessage), 0);
                        }
                        else if (user_Input == 5)
                        {
                            memset(&clientMessage, 0, sizeof(clientMessage));
                            clientMessage.request_Type = 4;
                            send(TCPSock, &clientMessage, sizeof(clientMessage), 0);
                            recv(TCPSock, &serverMessage, sizeof(serverMessage), 0);
                        }
                        else if (user_Input == 6)
                        {
                            // todo logout() and quit
                            memset(&clientMessage, 0, sizeof(clientMessage));
                            clientMessage.request_Type = 5;
                            send(TCPSock, &clientMessage, sizeof(clientMessage), 0);
                            recv(TCPSock, &serverMessage, sizeof(serverMessage), 0);
                            close(TCPSock);
                            break;
                        }
                        else
                        {
                            // todo account for invalid input
                        }
                    }
                }
                else if (i >= 19)
                {
                    printf("[Lodi Client]: The username and/or password are incorrect.\n");
                }
            }
            close(sock_Lodi);
        }

        // quit process
        else
        {
            cont = false;
            printf("[Lodi Client]: Terminating process.\n");
        }
    }
}
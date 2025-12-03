#include <stdio.h>      // for printf() and fprintf()
#include <sys/socket.h> // for recvfrom() and sendto()
#include <unistd.h>     // for close()
#include <stdlib.h>     // just for rand(), really
#include <string.h>     // for memset()
#include <arpa/inet.h>  // for inet_addr() and htons()

// privateKey to encrypt on login
//long privateKeys[20] = {  5,   7, 13,  17,  19, 23,  25,  29,  31, 35,  37,  41, 43,  47, 49,  59, 67,  71,  73,  79};
// send the associated public key when registering the key with the PKEServer.
//long publicKeys[20] =  { 53, 151, 61, 233, 139, 23, 169, 173, 247, 83, 157, 161, 43, 191, 97, 179, 67, 119, 217, 127};

typedef struct {
    char name[16];
} NameList;

NameList Names[20];

typedef struct {
    enum {registerTFA, ackRegTFA, ackPushTFA, requestAuth} messageType;
    unsigned int userID;
    unsigned long timestamp;
    unsigned long digitalSig;
}TFAClientOrLodiServerToTFAServer;

typedef struct {
    enum {ackLogin} messageType;
    unsigned int userID;
} LodiServerToLodiClientAcks;

typedef struct {
    enum { ackRegisterKey, responsePublicKey, responseAuth, login } messageType;
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

typedef struct{
    enum {registerKey, requestKey} messageType;
    unsigned int userID;
    unsigned long publicKey;
} PClientOrLodiServertoPKEServer;

typedef struct{
    enum{Login, Post, Feed, Follow, Unfollow, Logout}
        request_Type;                                   //same as an unsigned int
        unsigned int UserID;                            //unique client identifier
        unsigned int IdolID;                            //unique client identifier
        char message[100];                               //text message
}LodiClientMessage;                                     //an unsigned int is 32 bits = 4 bytes

typedef struct{
    enum{AckLogin, AckPost, AckFeed, AckFollow, AckUnfollow, AckLogout}
    message_Type;                                       //same as unsigned int
    unsigned int IdolID;                                //unique client identifier
    char message[100];                                  //text message
}LodiServerMessage;                                     //an unsigned int is 32 bits = 4 bytes

long RSAencrypt(long x, long y) {
    int result = 1;
    for(int i = 0; i < y; i++){
        result = result * x;
        result = result % 299;
    }
    return result;
}


int main(){
    //variable declaration and intialization for PKE
    int PKESock, lodiSock, TFASock, TCPSock;
    struct sockaddr_in pkeAddress, serverAddress, clientAddress, TFAAddress, TCPServer;
    socklen_t clientAddressLength = sizeof(pkeAddress);
    socklen_t pkeAddressLength = sizeof(pkeAddress);
    PClientOrLodiServertoPKEServer requestMsg, PKEKey;
    PKServerToPClientOrLodiClient responseMsg;
    TFAClientOrLodiServerToTFAServer authReq;
    LodiServerToLodiClientAcks loginAuth;
    LodiClientMessage clientMessage;
    LodiServerMessage serverMessage;
    char* AckMessage;

    printf("[Lodi Server]: Module Loaded. \n");
  
    // Socket creation this server
    lodiSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (lodiSock < 0) {
        perror("Socket() failed");
        exit(1);
    }

    // Configure server address structure
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress.sin_port = htons(6670); //I picked this at random

    // Bind socket
    if (bind(lodiSock, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
        perror("bind() failed");
        close(lodiSock);
        return 1;
    }
    printf("[Lodi Server]: listening on port 6670...\n");

    while (1) { // Shouldn't end

        // Wait to receive response
        memset(&responseMsg, 0, sizeof(responseMsg));
        ssize_t recvLength = recvfrom(lodiSock, &responseMsg, sizeof(responseMsg), 0,
            (struct sockaddr*)&clientAddress, &clientAddressLength);
        if (recvLength < 0) {
            perror("recvfrom() failed");
            continue;
        }
        printf("[Lodi Server]: Login request received\n");

        if (responseMsg.messageType == login) {

            // Create new socket. request key from the PKE server
            PKESock = socket(AF_INET, SOCK_DGRAM, 0);
            if (PKESock < 0) {
                perror("Socket() failed");
                return 1;
            }

            // Set up for PKE Server Address
            memset(&pkeAddress, 0, sizeof(pkeAddress));
            pkeAddress.sin_family = AF_INET;
            pkeAddress.sin_addr.s_addr = INADDR_ANY;
            pkeAddress.sin_port = htons(5060);

            printf("[Lodi Server]: PKE serverAddr configured.\n");

            // Connect to PKEServer
            if (connect(PKESock, (struct sockaddr*)&pkeAddress, sizeof(pkeAddress)) < 0) {
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
                (struct sockaddr*)&pkeAddress, sizeof(pkeAddress)) != sizeof(requestMsg)) {
                perror("Sendto() failed");
                close(PKESock);
                return 1;
            }

            printf("[Lodi Server]: Public key requested.\n");

            // receive the public key from the PKEServer
            memset(&PKEKey, 0, sizeof(PKEKey));
            if (recvfrom(PKESock, &PKEKey, sizeof(PKEKey), 0, (struct sockaddr*)&pkeAddress, &pkeAddressLength) <= 0) {
                perror("Recv() failed");
                close(PKESock);
                return 1;
            }

            printf("[Lodi Server]: Public key received.\n");


            // test if the public key matches
            printf("Stamp: %lu, DigSig: %lu, Key: %lu\n", responseMsg.timestamp, responseMsg.digitalSig, PKEKey.publicKey);
            if (responseMsg.timestamp != RSAencrypt(responseMsg.digitalSig, PKEKey.publicKey)) {
                printf("[Lodi Server]: Incorrect public key received.\n");
                perror("Recv() failed");
                close(PKESock);
                return 1;
            }
            printf("[Lodi Server]: Public key validated.\n");
            printf("[Lodi Server]: Sending Request to TFA Server.\n");

            
            // Setup sock to connect to TFA Server
            TFASock = socket(AF_INET, SOCK_DGRAM, 0);
            if (TFASock < 0) {
                perror("Socket() failed");
                return 1;
            }

            // Set up for TFA Server Address
            memset(&TFAAddress, 0, sizeof(TFAAddress));
            TFAAddress.sin_family = AF_INET;
            TFAAddress.sin_addr.s_addr = INADDR_ANY;
            TFAAddress.sin_port = htons(7000);

            printf("[Lodi Server]: TFA serverAddr configured.\n");

            // Connect to PKEServer

            if (connect(TFASock, (struct sockaddr*)&TFAAddress, sizeof(TFAAddress)) < 0) {
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
                (struct sockaddr*)&TFAAddress, sizeof(TFAAddress)) != sizeof(authReq)) {
                perror("Sendto() failed");
                close(PKESock);
                return 1;
            }
            printf("[Lodi Server]: Auth Request Sent.\n");

            // receive for user from the TFAServer
            memset(&authReq, 0, sizeof(authReq));
            socklen_t TFAAddressLength = sizeof(TFAAddress);
            if (recvfrom(TFASock, &authReq, sizeof(authReq), 0, (struct sockaddr *) &TFAAddress, &TFAAddressLength ) <= 0) {
                perror("Recv() failed");
                close(TFASock);
                return 1;
            }

            printf("[Lodi Server]: Auth Request received. now Verifying.\n");

            // Setup loginAuth variable for final checks
            memset(&loginAuth, 0, sizeof(loginAuth));
            loginAuth.messageType = ackLogin;

            // Case: if ID is a match and TFA Server Verifies.
            if (authReq.userID == responseMsg.userID) {
                loginAuth.userID = authReq.userID;
                printf("[Lodi Server]: Auth Request verified. Logging in.\n");

                if (sendto(lodiSock, &loginAuth, sizeof(loginAuth), 0,
                    (struct sockaddr *)&clientAddress, sizeof(clientAddress)) != sizeof(loginAuth)) {
                    perror("Sendto() failed");
                    close(lodiSock);
                    return 1;
                }
                //TCP STARTS HERE
               int counter=0;
               memset(&TCPServer, 0, sizeof(TCPServer));
               TCPServer.sin_family=AF_INET;
               TCPServer.sin_addr.s_addr=INADDR_ANY;
               TCPServer.sin_port=htons(7002);
               TCPSock = socket(AF_INET, SOCK_STREAM, 0);
               socklen_t TCPServerAddress = sizeof(TCPServer);
                while(counter!=0){
                //listen for input here
                if(bind(TCPSock,(struct sockaddr *) &TCPServer, sizeof(TCPServer))< 0){
                listen(TCPSock, 5);
                }
                accept(TCPSock,(struct sockaddr *) &TCPServer, &TCPServerAddress);
                recv(TCPSock, &clientMessage, sizeof(clientMessage), 0);
                //filter by message_Type
                if(clientMessage.request_Type == 0){
                //Send Ack login
                memset(&serverMessage, 0, sizeof(serverMessage));
                serverMessage.message_Type = clientMessage.request_Type;
                serverMessage.IdolID = clientMessage.IdolID;
                AckMessage = "[LodiServer]: Login Acknowledged";
                strcpy(serverMessage.message, AckMessage);
                send(TCPSock,&serverMessage,sizeof(serverMessage), 0);
                }
                if(clientMessage.request_Type == 1){
                //Send Ack Post
                memset(&serverMessage, 0, sizeof(serverMessage));
                serverMessage.message_Type = clientMessage.request_Type;
                serverMessage.IdolID = clientMessage.IdolID;
                AckMessage = "[LodiServer]: Post Acknowledged";
                strcpy(serverMessage.message, AckMessage);
                send(TCPSock,&serverMessage,sizeof(serverMessage), 0);
                }

                if(clientMessage.request_Type == 2){
                //Send Ack Feed
                memset(&serverMessage, 0, sizeof(serverMessage));
                serverMessage.message_Type = clientMessage.request_Type;
                serverMessage.IdolID = clientMessage.IdolID;
                AckMessage = "[LodiServer]: Feed Acknowledged";
                strcpy(serverMessage.message, AckMessage);
                send(TCPSock,&serverMessage,sizeof(serverMessage), 0);
                }

                if(clientMessage.request_Type == 3){
                //Send Ack Follow
                memset(&serverMessage, 0, sizeof(serverMessage));
                serverMessage.message_Type = clientMessage.request_Type;
                serverMessage.IdolID = clientMessage.IdolID;
                AckMessage = "[LodiServer]: Follow Acknowledged";
                strcpy(serverMessage.message, AckMessage);
                send(TCPSock,&serverMessage,sizeof(serverMessage), 0);
                }

                if(clientMessage.request_Type == 4){
                //Send Unfollow
                memset(&serverMessage, 0, sizeof(serverMessage));
                serverMessage.message_Type = clientMessage.request_Type;
                serverMessage.IdolID = clientMessage.IdolID;
                AckMessage = "[LodiServer]: Unfollow Acknowledged";
                strcpy(serverMessage.message, AckMessage);
                send(TCPSock,&serverMessage,sizeof(serverMessage), 0);
                }

                if(clientMessage.request_Type == 5){
                //logout message here and send AckLogout
                memset(&serverMessage, 0, sizeof(serverMessage));
                serverMessage.message_Type = clientMessage.request_Type;
                serverMessage.IdolID = clientMessage.IdolID;
                AckMessage = "[LodiServer]: Logout Acknowledged";
                strcpy(serverMessage.message, AckMessage);
                send(TCPSock,&serverMessage,sizeof(serverMessage), 0);
                counter++;
                }
                } //end of while loop
            }
            // Case: ID does not currently have TFA set up.
            if (authReq.userID == -1) {

                loginAuth.userID = authReq.userID;
                printf("[Lodi Server]: Auth Request denied.\n");

                if (sendto(lodiSock, &loginAuth, sizeof(loginAuth), 0,
                    (struct sockaddr*)&clientAddress, sizeof(clientAddress)) != sizeof(loginAuth)) {
                    perror("Sendto() failed");
                    close(lodiSock);
                    return 1;
                }
            }
            // Case: User denies TFA Verification.
            if (authReq.userID == 20) {

                loginAuth.userID = authReq.userID;
                printf("[Lodi Server]: Auth Request denied.\n");

                if (sendto(lodiSock, &loginAuth, sizeof(loginAuth), 0,
                    (struct sockaddr*)&clientAddress, sizeof(clientAddress)) != sizeof(loginAuth)) {
                    perror("Sendto() failed");
                    close(lodiSock);
                    return 1;
                }
            }

            //verification is currently going to be based on whether userID matches. cases outside the allotted user amount are various errors

           /* // sendto PKE server
            if (sendto(PKESock, &requestMsg, sizeof(requestMsg), 0, (struct sockaddr*)&pkeAddress, pkeAddressLength) != sizeof(requestMsg)) {
                perror("{Lodi Server}: sendto() failed");
                close(PKESock);
                return 1;
            }

            // recvfrom PKEServer
            recvLength = recvfrom(PKESock, &responseMsg, sizeof(responseMsg), 0, (struct sockaddr*)&pkeAddress, &pkeAddressLength);

            if (recvLength < 0) {
                perror("[Lodi Server]: recvfrom() failed");
                close(PKESock);
                return 1;
            } */

            //printf("[Lodi Server]: Response recieved from PKE Server \n");
            //printf("                Message Type: %d\n", responseMsg.messageType);
            //printf("                UserID: %u\n", responseMsg.userID);
            //printf("                Public Key: %lu\n", responseMsg.publicKey);
            /*

            //variable decalaration for TFA
            int sock_TFA;
            struct sockaddr_in tfaAddress;
            socklen_t tfaAddressLength = sizeof(tfaAddress);
            TFAClientOrLodiServerToTFAServer authRequest;
            TFAServerToLodiServer authResponse;

            // socket creation for TFA
            if ((sock_TFA = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
                perror("[Lodi Server]: socket() for TFA failed");
                close(PKESock);
                return 1;
            }
            memset(&tfaAddress, 0, sizeof(tfaAddress));
            tfaAddress.sin_family = AF_INET;
            tfaAddress.sin_port = htons(6060); //also random
            tfaAddress.sin_addr.s_addr = inet_addr("127.0.0.1"); //just local for testing

            printf("[Lodi Server]: Ready to communicate with the TFA Server\n");

            authRequest.messageType = requestAuth;
            authRequest.userID = 2;
            authRequest.timestamp = 12345678; //test value
            authRequest.digitalSig = 987654321; //test value

            printf("[Lodi Server]: Sending authentication request for user %u\n", authRequest.userID);

            //send to TFA Server
            if (sendto(sock_TFA, &authRequest, sizeof(authRequest), 0, (struct sockaddr*)&tfaAddress, tfaAddressLength) != sizeof(authRequest)) {
                perror("[Lodi Server]: sendto() to TFA failed");
                close(sock_TFA);
                close(PKESock);
                return 1;
            }

            //recive response
            ssize_t recvLengthTFA = recvfrom(sock_TFA, &authResponse, sizeof(authResponse), 0, (struct sockaddr*)&tfaAddress, &tfaAddressLength);

            if (recvLengthTFA < 0) {
                perror("[Lodi Server]: recvfrom() from TFA failed");
                close(PKESock);
                close(sock_TFA);
                return 1;
            }
            else {
                printf("[Lodi Server]: Received TFA response: \n");
                printf("                Message Type: %d\n", authResponse.messageType);
                printf("                User ID: %u\n", authResponse.userID);
            }

            close(PKESock);
            close(sock_TFA);
            return 0; */
        }
    }
}
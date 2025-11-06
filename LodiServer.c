#include <stdio.h>      // for printf() and fprintf()
#include <sys/socket.h> // for recvfrom() and sendto()
#include <unistd.h>     // for close()
#include <stdlib.h>     // just for rand(), really
#include <string.h>     // for memset()
#include <arpa/inet.h>  // for inet_addr() and htons()


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

typedef struct{
    enum {ackRegisterKey, responsePublicKey} messageType;
    unsigned int userID;
    unsigned long publicKey;
}PKServerToPClientOrLodiServer;

typedef struct{
    enum {responseAuth} messageType;
    unsigned int userID;
}TFAServerToLodiServer;

typedef struct{
    enum {registerKey, requestKey} messageType;
    unsigned int userID;
    unsigned long publicKey;
}PClientOrLodiServertoPKEServer;


int main(){
    //variable declaration and intialization for PKE
    int sock_PKE;
    struct sockaddr_in pkeAddress;
    socklen_t pkeAddressLength = sizeof(pkeAddress);
    PClientOrLodiServertoPKEServer requestMsg;
    PKServerToPClientOrLodiServer responseMsg;

    printf("[Lodi Server]: Module Loaded. \n");
    // Socket creation for PKE
    if((sock_PKE = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("[Lodi Server]: socket() for PKE failed");
        exit(1);
    }
    // Configuration to PKE Server
    memset(&pkeAddress, 0, sizeof(pkeAddress));
    pkeAddress.sin_family = AF_INET;
    pkeAddress.sin_port = htons(5050); //same port as what I put in PKEServer
    pkeAddress.sin_addr.s_addr = inet_addr("127.0.0.1"); // I just put this to simplify testing
    printf("[Lodi Server]: Ready to communicate with PKE Server\n");

    requestMsg.messageType = requestKey;
    requestMsg.userID = 2; //dummy test user
    requestMsg.publicKey = 0;

    printf("[Lodi Server]: Sending request to user %u... \n", requestMsg.userID);
    
    // sendto PKE server
    if(sendto(sock_PKE, &requestMsg, sizeof(requestMsg), 0 ,(struct sockaddr *)&pkeAddress, pkeAddressLength) != sizeof(requestMsg)){
        perror("{Lodi Server}: sendto() failed");
        close(sock_PKE);
        return 1;
    }

    // recvfrom PKEServer
    ssize_t recvLength =  recvfrom(sock_PKE, &responseMsg, sizeof(responseMsg), 0, (struct sockaddr *)&pkeAddress, &pkeAddressLength);

    if(recvLength < 0){
        perror("[Lodi Server]: recvfrom() failed");
        close(sock_PKE);
        return 1;
    }

    printf("[Lodi Server]: Response recieved from PKE Server \n");
    printf("                Message Type: %d\n", responseMsg.messageType);
    printf("                UserID: %u\n", responseMsg.userID);
    printf("                Public Key: %lu\n", responseMsg.publicKey);
    
    
    //variable decalaration for TFA
    int sock_TFA;
    struct sockaddr_in tfaAddress;
    socklen_t tfaAddressLength =sizeof(tfaAddress);
    TFAClientOrLodiServerToTFAServer authRequest;
    TFAServerToLodiServer authResponse;

    // socket creation for TFA
    if((sock_TFA = socket(AF_INET,SOCK_DGRAM, 0)) < 0){
        perror("[Lodi Server]: socket() for TFA failed");
        close(sock_PKE);
        return 1;
    }
    memset(&tfaAddress, 0, sizeof(tfaAddress));
    tfaAddress.sin_family = AF_INET;
    tfaAddress.sin_port = htons(6060); //also random
    tfaAddress.sin_addr.s_addr =inet_addr("127.0.0.1"); //just local for testing

    printf("[Lodi Server]: Ready to communicate with the TFA Server\n");

    authRequest.messageType = requestAuth;
    authRequest.userID = 2;
    authRequest.timestamp = 12345678; //test value
    authRequest.digitalSig = 987654321; //test value

    printf("[Lodi Server]: Sending authentication request for user %u\n", authRequest.userID);

    //send to TFA Server
    if(sendto(sock_TFA, &authRequest, sizeof(authRequest), 0, (struct sockaddr *)&tfaAddress, tfaAddressLength)!= sizeof(authRequest)){
        perror("[Lodi Server]: sendto() to TFA failed");
        close(sock_TFA);
        close(sock_PKE);
        return 1;
    }

    //recive response
    ssize_t recvLengthTFA = recvfrom(sock_TFA, &authResponse, sizeof(authResponse), 0, (struct sockaddr *)&tfaAddress, &tfaAddressLength);

    if (recvLengthTFA < 0) {
        perror("[Lodi Server]: recvfrom() from TFA failed");
        close(sock_PKE);
        close(sock_TFA);
        return 1;
    }else{
        printf("[Lodi Server]: Received TFA response: \n");
        printf("                Message Type: %d\n", authResponse.messageType);
        printf("                User ID: %u\n", authResponse.userID);
    }

    close(sock_PKE);
    close(sock_TFA);
    return 0;
}
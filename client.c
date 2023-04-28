#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define MAXDATASIZE 1024 // max number of bytes we can get at once

bool readLine(char** line, size_t* size, size_t* length);

int sendall(int s, char *buf, size_t *len)
{
    int total = 0;        // how many bytes we've sent
    int bytesleft = *len; // how many we have left to send
    int n;

    uint32_t len_to_send = htonl(*len);
    if (send(s, &len_to_send, sizeof(uint32_t), 0) == -1) {
        perror("send failed");
        return -1;
    }

    while(total < *len) {
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }

    *len = total; // return number actually sent here

    return n==-1?-1:0; // return -1 onm failure, 0 on success
}

char* recvall(int s) {
    int len_to_read = 0;
    int numbytes;
    if ((numbytes = recv(s, &len_to_read, sizeof(len_to_read), 0)) == -1) {
        perror("recv");
        return NULL;
    }
    len_to_read = ntohl(len_to_read);

    int total = 0;
    char* new_buf = malloc(len_to_read);

    while (total < len_to_read) {
        if ((numbytes = recv(s, new_buf + total, 1023, 0)) == -1) {
            perror("recv");
            free(new_buf);
            return NULL;
        }
        total += numbytes;
    }

    new_buf[total] = '\0';
    return new_buf;
}

// get sockaddr, IPv4 or IPv6
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*) sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*) sa)->sin6_addr);
}

int main(int argc, char *argv[]) {
    int sockfd, numbytes;
    char buf[MAXDATASIZE];
    struct addrinfo hints;
    struct addrinfo *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    if (argc != 3) {
        fprintf(stderr, "usage: client <server-IP-address> <port-number>\n");
        exit(1);
    }

    char* ip = argv[1];
    char* port = argv[2];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(argv[1], port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    printf("Client has requested to start connection with host %s on port %s\n", ip, port);
    printf("***********************************************************\n");

    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("Client: socket\n");
            close(sockfd);
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("Client: connect\n");
            close(sockfd);
            continue;
        }
        break;
    }

    if(p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
    printf("Connection established, now waiting for user input...\n");
    
    freeaddrinfo(servinfo);

    char* line = NULL;
    size_t size = 0;
    size_t len;

    while(readLine(&line, &size, &len)) {
        printf("\tSending message to Server...\n");

        if (sendall(sockfd, line, &len) == -1) {
            perror("sendall");
        }

        if (strcmp(line, ";;;") == 0 || strcmp(line, "") == 0) {
            printf("\tUser entered sentinel of \";;;\", now stopping client\n");
            printf("***********************************************************\n");
            break;
        }
        
        printf("\tReceived response from server of\n");

        char *server_buf;
         if ((server_buf = recvall(sockfd)) == NULL) {
            perror("recvall");
            continue;
         }
        printf("\t\t\"%s\"\n", server_buf);
        free(server_buf);
    }

    printf("Attepting to shut down client sockets and other streams\n");
    if (close(sockfd) == -1) {
        perror("Client: failed to close socket");
        exit(1);
    };
    printf("Shut down successful... goodbye\n");
}

bool readLine(char** line, size_t* size, size_t* length)
{
    while(1)
    {
        printf("\tprompt> ");
        size_t len = getline(line, size, stdin);

        if(len == -1) {
            return false;
        }

        int len_sent = 0;

        if((*line)[len-1] == '\n') {
            (*line)[--len] = '\0';
        }

        *length = len;

        if(len == 0) {
            continue;
        }

        return len > 1 || **line != '.';
    }
}
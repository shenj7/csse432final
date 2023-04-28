#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <ctype.h>
#include <sys/mman.h>

#define BACKLOG 10
#define MAP_ANONYMOUS 0x20

void sigchild_handler(int s)
{
    (void)s;

    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*) sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*) sa)->sin6_addr);
}

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

int main(int argc, char *argv[])
{
    int sockfd, new_fd, numbytes;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    int *msg_count;

    msg_count = mmap(NULL, sizeof(*msg_count), PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    *msg_count = 0;




    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (argc != 2) {
        fprintf(stderr, "usage: server <port-number>\n");
        exit(1);
    }

    char* port = argv[1];

    if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("Server: setsockopt");
            exit(1);
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("Server: socket");
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("Server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL) {
        fprintf(stderr, "Server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("Server: failed to listen");
        exit(1);
    }

    sa.sa_handler = sigchild_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("Server: failed sigaction");
        exit(1);
    }

    printf("Serial Server on host 0.0.0.0/0.0.0.0 is listening on port %s\n", port);
    printf("Serial Server string listening on port %s\n", port);

    while(1) {
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("Server: failed to accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *) &their_addr),
            s, sizeof s);
        printf("Received connection request from %s\n", s);
        printf("***********************************************************\n");
        printf("\tNow listening for incoming messages...\n");

        if (!fork()) {
            close(sockfd);

            while(1) {
                char* buf;

                if ((buf = recvall(new_fd)) == NULL) {
                    perror("Server: recvall");
                    continue;
                }
                
                if (strlen(buf) == 0) {
                    perror("Server: failed to recv");
                    break;
                }

                printf("\tReceived the following message from client: \n");
                printf("\t\t\"%s\"\n", buf);

                if (strcmp(buf, ";;;") == 0 || strcmp(buf, "") == 0) {
                    printf("\tClient finished, now waiting to service another client...\n");
                    printf("***********************************************************\n");
                    break;
                }

                *msg_count = *msg_count + 1;
                printf("\tNow sending message %d back having changed the string to upper case...\n", *msg_count);
                
                for (int s = 0; s < strlen(buf); s++) {
                    buf[s] = toupper(buf[s]);
                }

                // printf("\tuppercase message: %s\n", buf);

                char* sendback;
                asprintf(&sendback, "%d %s", *msg_count, buf);
                free(buf);

                // printf("sendback %s", sendback);

                size_t to_send_len = (size_t) strlen(sendback);
                if (sendall(new_fd, sendback, &to_send_len) == -1) {
                    perror("sendall");
                    continue;
                }
            }

            close(new_fd);
            exit(0);
        }
        close(new_fd);
    }

    return 0;
}
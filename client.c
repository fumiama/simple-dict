#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc,char *argv[]) {   //usage: ./client host port
    int sockfd, numbytes;
    char buf[BUFSIZ];
    struct sockaddr_in their_addr;
    puts("break!");
    while((sockfd = socket(AF_INET,SOCK_STREAM,0)) == -1);
    puts("Get sockfd");
    their_addr.sin_family = AF_INET;
    their_addr.sin_port = htons(atoi(argv[2]));
    their_addr.sin_addr.s_addr=inet_addr(argv[1]);
    bzero(&(their_addr.sin_zero), 8);
    
    while(connect(sockfd,(struct sockaddr*)&their_addr,sizeof(struct sockaddr)) == -1);
    puts("Connected to server");
    numbytes = recv(sockfd, buf, BUFSIZ,0);
    buf[numbytes]='\0';  
    puts(buf);
    while(1) {
        printf("Enter command:");
        scanf("%s",buf);
        numbytes = send(sockfd, buf, strlen(buf), 0);
        numbytes = recv(sockfd,buf,BUFSIZ,0);
        buf[numbytes]='\0';
        puts(buf);
    }
    close(sockfd);
    return 0;
}

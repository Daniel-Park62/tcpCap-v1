#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

#define PORT 20162
#define BUFFER_SIZE 4096
#define BUFF_SIZE 100

# define LISTEN_QUEUE_SIZE 5

void childHandler(int signal)
{

    int status;
    pid_t spid;

    // -1 :: 어떠한 child process모두 다 받는다. WNOHANG :: 자식 프로세스가 종료되지 않아도 부모는 자신할 일 한다.
    while((spid = waitpid(-1, &status, WNOHANG)) > 0)
    {
        printf("자식프로세스 wait한 결과 \n");
        printf("================================\n");
        printf("PID         : %d\n", spid);
        printf("Exit Value  : %d\n", WEXITSTATUS(status));
        printf("Exit Stat   : %d\n", WIFEXITED(status));
    }
}

int main() {

    //childHandler 함수가 SIGCHLD 시그널을 처리할 수 있도록 시그널 설치

    signal(SIGCHLD, (void *)childHandler);

    struct sockaddr_in listenSocket;

    memset(&listenSocket, 0, sizeof(listenSocket));

    listenSocket.sin_family = AF_INET;
    listenSocket.sin_addr.s_addr = htonl(INADDR_ANY);
    listenSocket.sin_port = htons(PORT);

    int listenFD = socket(AF_INET, SOCK_STREAM, 0);
    int connectFD;

    ssize_t receivedBytes;
    char readBuff[BUFFER_SIZE];
    char sendBuff[BUFFER_SIZE];
    pid_t pid;


    if (bind(listenFD, (struct sockaddr *) &listenSocket, sizeof(listenSocket)) == -1) {
        printf("Can not bind.\n");
        return -1;
    }

    if (listen(listenFD, LISTEN_QUEUE_SIZE) == -1) {
        printf("Listen fail.\n");
        return -1;
    }

    printf("Waiting for clients...\n");

    while (1)
    {
        struct sockaddr_in connectSocket, peerSocket;

        socklen_t connectSocketLength = sizeof(connectSocket);

        while((connectFD = accept(listenFD, (struct sockaddr*)&connectSocket, (socklen_t *)&connectSocketLength)) >= 0)
        {
            getpeername(connectFD, (struct sockaddr*)&peerSocket, &connectSocketLength);

            char peerName[sizeof(peerSocket.sin_addr) + 1] = { 0 };
            sprintf(peerName, "%s", inet_ntoa(peerSocket.sin_addr));

            // 접속이 안되었을 때는 출력 x
            if(strcmp(peerName,"0.0.0.0") != 0)
                printf("Client : %s\n", peerName);


            if (connectFD < 0)
            {
                printf("Server: accept failed\n");
                exit(0);
            }
            // 클라이언트가 접속할 때마다 fork를 통해 child process를 생성해 echo를 발생.
            pid = fork();

            // 자식 서버일 때
            if(pid == 0)            {
                // 리스닝 소켓은 닫아준다.
                close(listenFD);

                ssize_t receivedBytes;

                // read할 값이 있다면 계속 읽어들인다.
                while((receivedBytes = read(connectFD, readBuff, BUFF_SIZE)) > 0)
                {

                    printf("%lu bytes read\n", receivedBytes);
                    readBuff[receivedBytes] = '\0';
                    fputs(readBuff, stdout);
                    fflush(stdout);

                    sprintf(sendBuff,"%s",readBuff);
                    write(connectFD, sendBuff, strlen(sendBuff));
                }

                // 클라이언트가 종료되면 해당 자식 프로세스의 커넥팅 소켓도 종료
                close(connectFD);
                return 0; // 혹은 exit(0); 이용

            }

            // 부모 서버라면 커넥팅 소켓을 닫아준다.
            else
                close(connectFD);
        }

    }
    close(listenFD);

    return 0;
}

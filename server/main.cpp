//
//  main.cpp
//  remote_rsc
//
//  Created by yaron shani on 9/15/15.
//  Copyright (c) 2015 ys. All rights reserved.
//

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>
#include <signal.h>
#include <poll.h>

#define ALLOCTAE_CMD 4
#define READ_CMD 1
#define WRITE_CMD 2
#define RUN_SYSCALL 3

void read_from_socket(int socketfd, void *buff, unsigned int length)
{
    int n;
    n = recv(socketfd, buff, length, MSG_WAITALL);
    if (n < 0)
    {
        perror("ALLOCATE: ERROR reading from socket");
        exit(1);
    }
    
}

int call_sys(int socketfd)
{
    char syscall_name[30];
    unsigned int args_count;
    int args[6];
    void *handle;
    read_from_socket(socketfd, &syscall_name, 30);
    read_from_socket(socketfd, &args_count, 4);
    handle = dlopen("libc.dylib", RTLD_LAZY);
    if (!handle) {
        printf("Error handle %s\n", dlerror());
        return -1;
    }
    for (int i=0;i<args_count;i++) {
        read_from_socket(socketfd, &args[i], 4);
    }
    void* tmp_syscall = dlsym(handle, syscall_name);
    if(!tmp_syscall) {
        printf("%s\n", dlerror());
        return -1;
    }
    printf("Run Syscall: syscallname: %s arg_count %du\n", syscall_name, args_count);
    switch (args_count) {
        case 1:
            int (*my_syscall1)(unsigned int);
            *(void **) (&my_syscall1) = tmp_syscall;
            return my_syscall1(args[0]);
        case 2:
            int (*my_syscall2)(unsigned int, unsigned int);
            *(void **) (&my_syscall2) = tmp_syscall;
            return my_syscall2(args[0], args[1]);
        case 3:
            int (*my_syscall3)(int, int, int);
            *(void **) (&my_syscall3) = tmp_syscall;
            printf("3 args syscall %d %d %d\n", args[0], args[1], args[2]);
            return my_syscall3(args[0], args[1], args[2]);
        case 4:
            int (*my_syscall4)(unsigned int, unsigned int, unsigned int, unsigned int);
            *(void **) (&my_syscall4) = tmp_syscall;
            return my_syscall4(args[0], args[1], args[2], args[3]);
        case 5:
            int (*my_syscall5)(unsigned int, unsigned int, unsigned int, unsigned int, unsigned int);
            *(void **) (&my_syscall5) = tmp_syscall;
            return my_syscall5(args[0], args[1], args[2], args[3], args[4]);
        case 6:
            int (*my_syscall6)(unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int);
            *(void **) (&my_syscall6) = tmp_syscall;
            return my_syscall6(args[0], args[1], args[2], args[3], args[4], args[5]);
            break;
            
        default:
            break;
    }
    
    //asm("push 0;");
    //asm("push 1;");
    //asm("push 2;");
    //unsigned int res = my_socket();
    //printf("socket -> %d", res);
    close(socketfd);
    //my_socket(2,1,0);

    return -1;
}
#define POLL_SIZE 32

void doprocessing(int socketfd)
{
    socklen_t
    void *address;
    size_t size;
    void *data;
    int syscall_ret;
    char command[1];
    struct pollfd poll_set[POLL_SIZE];
    poll_set[0].fd = socketfd;
    poll_set[0].events = POLLIN;
    while (1) {
        poll(poll_set, 1, 10000);
        read_from_socket(socketfd, &command, 1);
        printf("Got Command %d\n", command[0]);
        if (command[0] == -1)
            break;
        switch (command[0]) {
            case ALLOCTAE_CMD:
                read_from_socket(socketfd, &size, 4);
                printf("Alocate Command - size: %du\n", (unsigned int)size);
                address = malloc(size);
                printf("Alocate Command - addr: %du\n", (unsigned int)address);
                write(socketfd, &address, 4);
                break;
            case READ_CMD:
                read_from_socket(socketfd, &address, 4);
                read_from_socket(socketfd, &size, 4);
                printf("Read Command: address: %du, size %du\n", (unsigned int)address, (unsigned int)size);
                data = malloc(size);
                memcpy(data, address, size);
                write(socketfd, data, size);
                break;
            case WRITE_CMD:
                read_from_socket(socketfd, &address, 4);
                read_from_socket(socketfd, &size, 4);
                printf("Write Command: address: %du, size %du\n", (unsigned int)address, (unsigned int)size);
                data = malloc(size);
                read_from_socket(socketfd, data, size);
                memcpy(address, data, size);
                break;
            case RUN_SYSCALL:
                printf("Run Syscall\n");
                syscall_ret = call_sys(socketfd);
                if (syscall_ret < 0)
                    printf("SYCALL ERR %d\n", errno);
                printf("Syscall res: %d\n", syscall_ret);
                write(socketfd, (void *)&syscall_ret, 4);
                break;
            default:
                break;
        }
        command[0]=0xFF;
    }
    
}

void server_listen()
{
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    char buffer[256];
    struct sockaddr_in serv_addr, cli_addr;
    int  n, pid;
    
    /* First call to socket() function */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (sockfd < 0)
    {
        perror("ERROR opening socket");
        exit(1);
    }
    
    /* Initialize socket structure */
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = 5001;
    
    int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    
    /* Now bind the host address using bind() call.*/
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("ERROR on binding");
        exit(1);
    }
    
    /* Now start listening for the clients, here
     * process will go in sleep mode and will wait
     * for the incoming connection
     */
    
    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    
    while (1)
    {
        newsockfd = accept(sockfd, (struct sockaddr  *) &cli_addr, &clilen);
        if (newsockfd < 0)
        {
            //perror("ERROR on accept");
            continue;
        }
        
        printf("new child\n");
        /* Create child process */
        pid = fork();
        if (pid < 0)
        {
            perror("ERROR on fork");
            exit(1);
        }
        
        if (pid == 0)
        {
            /* This is the client process */
            close(sockfd);
            printf("process request\n");
            doprocessing(newsockfd);
            exit(0);
        }
        else
        {
            close(newsockfd);
        }
    } /* end of while */
}

int main(int argc, const char * argv[]) {
    // insert code here...
    server_listen();
    std::cout << "Hello, World!\n";
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include "../include/dirtree.h"

#define OFFSET 100

/**
* @brief loops the call recv() until all bytes are received from the input 
* buffer and returns the number of bytes received
* @param[in] fd 
* @param[in] msg 
* @param[in] bytes 
* @return number of bytes received from the buffer msg 
*/
size_t recvloop(int fd, char *msg, size_t bytes) {
    size_t bytesrcv;
    size_t bytesread;
    memcpy(&bytesread, &bytes, sizeof(size_t));
    while (bytes > 0) {
        bytesrcv = recv(fd, msg, bytes, 0);
        bytes -= bytesrcv;
    }
    return bytesread;
}

/**
* @brief loops the call send() until all bytes from the input buffer are sent 
* and returns the number of bytes sent
* @param[in] fd 
* @param[in] msg 
* @param[in] bytes 
* @return number of bytes sent from the buffer msg 
*/
size_t sendloop(int fd, char *msg, size_t bytes) {
    size_t bytesrcv;
    size_t bytessent;
    memcpy(&bytessent, &bytes, sizeof(size_t));
    while (bytes > 0) {
        bytesrcv = send(fd, msg, bytes, 0);
        bytes -= bytesrcv;
    }
    return bytessent;
}

/**
* @brief recursively traverses the input tree and gets the size of each node and
its fields. 
* @param[in] tree
* @return size in bytes of tree;
*/
size_t getsizetree(struct dirtreenode *tree) {
    if (tree->num_subdirs == 0) {
        return strlen(tree->name) + 1 + sizeof(int) + sizeof(size_t);
    }
    size_t size = strlen(tree->name) + 1 + sizeof(int) + sizeof(size_t);
    for (int i = 0; i < tree->num_subdirs; i++) {
        size += getsizetree(tree->subdirs[i]);
    }
    return size;
}

/**
* @brief Takes input tree and deconstructs it into a char array. 
* @param[in] tree
* @param[out] buf
* @param[in] offset
* @return number of bytes sent from the buffer msg 
*/
char *packtree(struct dirtreenode *tree, char buf[], int *offset) {
    size_t bytes;
    size_t len; 
    len = strlen(tree->name) + 1;
    bytes = sizeof(size_t) + sizeof(int) + len;
    memcpy(buf + *offset, &len, sizeof(size_t));
    memcpy(buf + *offset + sizeof(size_t), &tree->num_subdirs, sizeof(int));
    memcpy(buf + *offset + sizeof(size_t) + sizeof(int), tree->name, len);
    *offset += bytes;
    if (tree->num_subdirs == 0) {
        return buf;
    }
    for (int i = 0; i < tree->num_subdirs; i++) {
        packtree(tree->subdirs[i], buf, offset);
    }
    return buf;
    
}

/**
* @brief loops the call recv() until all bytes of int sized message are received.
* The int that was received is returned.
* @param[in] sessfd 
* @return unpacked int value
*/
int unpackint(int sessfd) {
    size_t bytes = sizeof(int);
    int msg[bytes];
    size_t bytesrcv;
    //receive loop
    while (bytes > 0) {
        bytesrcv = recv(sessfd, msg, bytes, 0);
        bytes -= bytesrcv;
    }
    int retval = msg[0];
    return retval;
}

int main(int argc, char**argv) {
    char *serverport;
    unsigned short port;
    int sockfd, sessfd, rv;
    struct sockaddr_in srv, cli;
    socklen_t sa_size;

    // Get environment variable indicating the port of the server
    serverport = getenv("serverport15440");
    if (serverport) port = (unsigned short)atoi(serverport);
    else port=15440;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);    // TCP/IP socket
    if (sockfd<0) err(1, 0);            // in case of error

    // setup address structure to indicate server port
    memset(&srv, 0, sizeof(srv));            // clear it first
    srv.sin_family = AF_INET;            // IP family
    srv.sin_addr.s_addr = htonl(INADDR_ANY);    // don't care IP address
    srv.sin_port = htons(port);            // server port

    // bind to our port
    rv = bind(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
    if (rv<0) err(1,0);
    
    // start listening for connections
    rv = listen(sockfd, 5);
    if (rv<0) err(1,0);

    // main server loop, handle clients one at a time, quit after 10 clients
    while(1) {
        // wait for next client, get session socket
        sa_size = sizeof(struct sockaddr_in);
        sessfd = accept(sockfd, (struct sockaddr *)&cli, &sa_size);
        if (sessfd<0) err(1,0);
        if (fork() == 0) {
        // get messages and send replies to this client, until it goes away
            int fnc;
            while(recvloop(sessfd, (char*)&fnc, sizeof(int)) > 0) {
                //OPEN
                if (fnc == 0) {
                    int msglen = unpackint(sessfd);
                    char msg[msglen];
                    recvloop(sessfd, msg, msglen);
                    //msg = [PATHLEN|PATHNAME|FLAG|MODE]
                    int length;
                    memcpy(&length, msg, sizeof(int)); //copy pathlen into length
                    char path[length];
                    memcpy(&path, msg + sizeof(int), length); //copy pathname into path
                    int flag;
                    memcpy(&flag, msg + sizeof(int) + length, sizeof(int)); //copy flags into flag
                    mode_t mode;
                    memcpy(&mode, msg + 2*sizeof(int) + length, sizeof(mode_t)); //copy mode
                    int fd = open(path, flag, mode);
                    if (fd == -1) { //case of error we want to send client -1 and errno
                        char retval[2*sizeof(int)];
                        memcpy(retval, &fd, sizeof(int));
                        memcpy(retval + sizeof(int), &errno, sizeof(int));
                        sendloop(sessfd, retval, 2*sizeof(int));
                    } 
                    else {
                        fd += OFFSET;
                        char retval[sizeof(int)];
                        memcpy(retval, &fd, sizeof(int));
                        sendloop(sessfd, retval, sizeof(int));
                    }
                }
                //CLOSE
                else if (fnc == 1) {
                    int fd = unpackint(sessfd); //unpack 
                    fd  -= OFFSET;
                    int returnval = close(fd);
                    if (returnval == -1) {
                        char retval[2*sizeof(int)];
                        memcpy(retval, &returnval, sizeof(int));
                        memcpy(retval + sizeof(int), &errno, sizeof(int));
                        sendloop(sessfd, retval, 2*sizeof(int));
                    }
                    // we need to send back the return value to client
                    else { 
                        char retval[sizeof(int)];
                        memcpy(retval, &returnval, sizeof(int));
                        sendloop(sessfd, retval, sizeof(int));
                    }
                }
                //WRITE
                else if (fnc == 2) {
                    int fd = unpackint(sessfd);
                    fd -= OFFSET;
                    size_t count;
                    recvloop(sessfd, (char *)&count, sizeof(size_t));
                    //rcv loop
                    char buf[count];
                    recvloop(sessfd, buf, count);
                    ssize_t returnval = write(fd, buf, count);
                    if (returnval == -1) {
                        char retval[sizeof(ssize_t) + sizeof(int)];
                        memcpy(retval, &returnval, sizeof(ssize_t));
                        memcpy(retval + sizeof(ssize_t), &errno, sizeof(int));
                        sendloop(sessfd, retval, sizeof(ssize_t) + sizeof(int));
                    }
                    else {
                        sendloop(sessfd, (char *)&returnval, sizeof(ssize_t));
                    }    
                }
                //READ
                else if (fnc == 3) { 
                    int fd = unpackint(sessfd);
                    fd -= OFFSET;
                    size_t count;
                    recvloop(sessfd, (char *)&count, sizeof(size_t));
                    char buf[count];
                    ssize_t retval = read(fd, buf, count);
                    if (retval == -1) {
                        char errbuf[sizeof(ssize_t) + sizeof(int)];
                        memcpy(errbuf, &retval, sizeof(ssize_t));
                        memcpy(errbuf + sizeof(ssize_t), &errno, sizeof(int));
                        sendloop(sessfd, errbuf, sizeof(ssize_t) + sizeof(int));
                    }
                    else {
                        size_t bytes = sizeof(ssize_t) + retval;
                        char msg[bytes];
                        memcpy(msg, &retval, sizeof(ssize_t));
                        memcpy(msg + sizeof(ssize_t), buf, retval);
                        sendloop(sessfd, msg, bytes);
                    }
                }
                else if (fnc == 4) {
                    int fd = unpackint(sessfd);
                    fd -= OFFSET;
                    size_t bytes = sizeof(off_t) + sizeof(int);
                    char msg[bytes];
                    recvloop(sessfd, msg, bytes);
                    off_t offset;
                    int whence;
                    memcpy(&offset, msg, sizeof(off_t));
                    memcpy(&whence, msg + sizeof(off_t), sizeof(int));
                    off_t retval = lseek(fd, offset, whence);
                    if (retval == -1) {
                        char errbuf[sizeof(off_t) + sizeof(int)];
                        memcpy(errbuf, &retval, sizeof(off_t));
                        memcpy(errbuf + sizeof(off_t), &errno, sizeof(int));
                        sendloop(sessfd, errbuf, sizeof(off_t) + sizeof(int));
                    }
                    else {
                        sendloop(sessfd, (char *)&retval, sizeof(off_t));
                    }
                }
                else if (fnc == 5) {
                    //[PATHLEN|PATHNAME]
                    size_t pathlen;
                    recvloop(sessfd, (char *)&pathlen, sizeof(size_t));
                    char pathname[pathlen];
                    recvloop(sessfd, pathname, pathlen);
                    struct stat buf;
                    int retval = stat(pathname, &buf);
                    if (retval == -1) {
                        char errbuf[2*sizeof(int)];
                        memcpy(errbuf, &retval, sizeof(int));
                        memcpy(errbuf, &errno, sizeof(int));
                        sendloop(sessfd, errbuf, 2*sizeof(int));
                    }
                    else {
                        //[retval|buf]
                        int bytes = sizeof(int) + sizeof(struct stat);
                        char msg[bytes];
                        memcpy(msg, &retval, sizeof(int));
                        memcpy(msg + sizeof(int), &buf, sizeof(struct stat));
                        sendloop(sessfd, msg, bytes);
                    }
                    
                }
                else if (fnc == 6) {
                    size_t pathlen;
                    recvloop(sessfd, (char *)&pathlen, sizeof(size_t));
                    char pathname[pathlen];
                    recvloop(sessfd, pathname, pathlen);
                    int retval = unlink(pathname);
                    if (retval == -1) {
                        char errbuf[2*sizeof(int)];
                        memcpy(errbuf, &retval, sizeof(int));
                        memcpy(errbuf + sizeof(int), &errno, sizeof(int));
                        sendloop(sessfd, errbuf, 2*sizeof(int));
                    }
                    else {
                        sendloop(sessfd, (char *)&retval, sizeof(int));
                    }
                }
                
                else if (fnc == 7) {
                    //[OPCODE|FD|NBYTES|BASEP]
                    int fd = unpackint(sessfd);    
                    fd -= OFFSET;
                    size_t bytes = sizeof(size_t) + sizeof(off_t);
                    char msg[bytes];
                    recvloop(sessfd, (char *)&msg, bytes);
                    size_t nbytes;
                    memcpy(&nbytes, msg, sizeof(size_t));
                    off_t basep;
                    memcpy(&basep, msg + sizeof(size_t), sizeof(off_t));
                    char buf[nbytes];
                    ssize_t retval = getdirentries(fd, buf, nbytes, &basep);
                    if (retval == -1) {
                        char errbuf[sizeof(ssize_t) + sizeof(int)];
                        memcpy(errbuf, &retval, sizeof(ssize_t));
                        memcpy(errbuf + sizeof(ssize_t), &errno, sizeof(int));
                        sendloop(sessfd, errbuf, sizeof(ssize_t) + sizeof(int));
                    }
                    else {
                        char response[sizeof(ssize_t) + nbytes];
                        memcpy(response, (char *)&retval, sizeof(ssize_t));
                        memcpy(response + sizeof(ssize_t), buf, nbytes);
                        sendloop(sessfd, response, sizeof(ssize_t) + nbytes);
                    }
                }
                else if (fnc == 8) {
                    //[OPCODE|PATHLEN|PATH]
                    size_t pathlen;
                    recvloop(sessfd, (char *)&pathlen, sizeof(size_t));
                    char path[pathlen];
                    recvloop(sessfd, path, pathlen);
                    struct dirtreenode *tree = malloc(sizeof(struct dirtreenode));
                    tree = getdirtree(path);
                    if (tree == NULL) {
                        int flag = -1;
                        char errbuf[2*sizeof(int)];
                        memcpy(errbuf, &flag, sizeof(int));
                        memcpy(errbuf + sizeof(int), &errno, sizeof(int));
                        sendloop(sessfd, errbuf, 2*sizeof(int));
                    }
                    else {
                        int size = getsizetree(tree);
                        char buf[size];
                        int *offset = calloc(1, sizeof(int));
                        packtree(tree, buf, offset);
                        free(offset);
                        char msg[sizeof(int) + size];
                        memcpy(msg, &size, sizeof(int));
                        memcpy(msg + sizeof(int), buf, size);
                        sendloop(sessfd, msg, sizeof(int) + size);
                        freedirtree(tree);
                    }

                }
            }
            close(sessfd);
            exit(0);
        }
        else {
            if (rv<0) err(1,0);
            close(sessfd);
        }
        // either client closed connection, or error
    }
    // close socket
    close(sockfd);
    return 0;
}
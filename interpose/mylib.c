#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include "../include/dirtree.h"
#include <errno.h>

#define minfd 105

int sockfd;

// The following line declares a function pointer with the same prototype as the open function.  
int (*orig_open)(const char *pathname, int flags, ...);  // mode_t mode is needed when flags includes O_CREAT
int (*orig_close)(int fd);
ssize_t (*orig_read)(int fd, void *buf, size_t count);
ssize_t (*orig_write)(int fd, const void *buf, size_t count);
off_t (*orig_lseek)(int fd, off_t offset, int whence);
int (*orig_stat)(const char *path, struct stat *buf);
int (*orig_unlink)(const char *pathname);
ssize_t (*orig_getdirentries)(int fd, char  *buf,  size_t nbytes , off_t *basep);
struct dirtreenode* (*orig_getdirtree)(const char *path);
void (*orig_freedirtree)(struct dirtreenode* dt);

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
* @brief handles error messages sent from server side. Receives the errorno 
* from the server side and stores it on the client side.
*/
void handleerr() {
    int bytes = sizeof(int);
    int err;
    recvloop(sockfd, (char *)&err, bytes);
    errno = err;
}

/**
* @brief Takes encoded tree and recursively reconstructs it back into a directory tree.
* @param[in] buf
* @param[in] offset
* @return returns directory tree
*/
struct dirtreenode *unpacktree(char buf[], int *offset) {
    size_t len;
    int numdirs;
    memcpy(&len, buf + *offset, sizeof(size_t));
    char *name = malloc(len);
    memcpy(&numdirs, buf + *offset + sizeof(size_t), sizeof(int));
    memcpy(name, buf + *offset + sizeof(size_t) + sizeof(int), len);
    size_t bytes = sizeof(size_t) + sizeof(int) + len;
    *offset += bytes;
    struct dirtreenode *tree = malloc(sizeof(struct dirtreenode));
    // struct dirtreenode **subdirs = malloc(sizeof(struct dirtreenode *));
    tree->name = name;
    tree->num_subdirs = numdirs;
    tree->subdirs = malloc(numdirs*sizeof(struct dirtreenode *));
    for (int i = 0; i < numdirs; i++) {
        tree->subdirs[i] = unpacktree(buf, offset);
    }
    return tree;
}

/**
* @brief Packs open() arguments, opcode, message length and path length into a 
* char array and sends it to the server. It then receives the response from the
* server which can be an error or return value and returns it on the client side.
* @param[in] pathname
* @param[in] flags
* @param[in] mode
* @return either -1 on error or return value of syscall open
*/
// This is our replacement for the open function from libc.
int open(const char *pathname, int flags, ...) { 
    mode_t m=0;
    if (flags & O_CREAT) {
        va_list a;
        va_start(a, flags);
        m = va_arg(a, mode_t);
        va_end(a);
    }
    //build message [OPCODE|MSGLEN|PATHLEN|PATHNAME|FLAG|MODE]
    int pathlen = (int)strlen(pathname) + 1; 
    size_t bytes = 4*sizeof(int) + sizeof(mode_t) + pathlen; // bytes for opcode, msglen, pathlen, flag and mode
    char msg[4*sizeof(int) + pathlen + sizeof(mode_t)];
    int msglen = 2*sizeof(int) + pathlen + sizeof(mode_t);
    int fnc = 0; //opcode
    memcpy(msg, &fnc, sizeof(int)); //copy opcode into msg
    memcpy(msg + sizeof(int), &msglen, sizeof(int)); //copy rest of msg len
    memcpy(msg + 2*sizeof(int), &pathlen, sizeof(int)); //copy length of pathname
    memcpy(msg + 3*sizeof(int), pathname, pathlen); //copy pathname
    memcpy(msg + 3*sizeof(int) + pathlen, &flags, sizeof(int)); //copy flag
    memcpy(msg + 4*sizeof(int) + pathlen, &m, sizeof(mode_t)); //copy mode
    //send message to server
    sendloop(sockfd, msg, bytes);
    //receive reply from server
    int rcvbuf;
    bytes = sizeof(int); //we want to receive 4 bytes (int) from open return 
    recvloop(sockfd, (char *)&rcvbuf, bytes);
    if (rcvbuf == -1) {
        handleerr();
    }
    return rcvbuf;
}

/**
* @brief Packs fd and opcode into a char array and sends it to the server. It 
* then receives the response from the server which can be an error or return 
* value and returns it on the client side.
* @param[in] fd
* @return either -1 on error or return value of syscall close
*/
int close(int fd) { 
    if (fd < minfd) {
        return orig_close(fd);
    }
    size_t bytes = 2*sizeof(int); //opcode and fd
    char msg[bytes];
    int fnc = 1;
    memcpy(msg, &fnc, sizeof(int));
    memcpy(msg + sizeof(int), &fd, sizeof(int));
    //send message
    sendloop(sockfd, msg, bytes);
    //receive reply
    int rcvbuf;
    recvloop(sockfd, (char *)&rcvbuf, sizeof(int));
    if (rcvbuf == -1) {
        handleerr();
    }
    return rcvbuf;
}
//dont pass buf to server. Make buf on server side, write into buf, 
//and send back what we want to write into buffer and then write it in buffer locally

/**
* @brief Packs fd, count, and opcode into a char array and sends it to the 
* server. It then receives the response from the server which can be an error or
* return value and returns it on the client side. buf is declared on the client
* side and content stored in buf from the server side read() call is sent to the
* client side and stored in the buf.
* @param[in] fd
* @param[out] buf
* @param[in] count
* @return either -1 on error or return value of syscall read()
*/
ssize_t read(int fd, void *buf, size_t count) {
    if (fd < minfd) {
        return orig_read(fd, buf, count);
    }
    size_t bytes = 2*sizeof(int) + sizeof(size_t);
    int fnc = 3;
    char msg[bytes];
    memcpy(msg, &fnc, sizeof(int));
    memcpy(msg + sizeof(int), &fd, sizeof(int));
    memcpy(msg + 2*sizeof(int), &count, sizeof(size_t));
    //msg = [OPCODE|FD|COUNT]
    sendloop(sockfd, msg, bytes);
    ssize_t rcvbuf;
    recvloop(sockfd, (char *)&rcvbuf, sizeof(ssize_t));
    if (rcvbuf == -1) {
        handleerr();
    }
    else {
        recvloop(sockfd, buf, rcvbuf);
    }
    return rcvbuf;
}

/**
* @brief Packs fd, count, and opcode into a char array and sends it to the 
* server. It then receives the response from the server which can be an error or
* return value and returns it on the client side. buf is declared on the client
* side and content stored in buf from the server side write() call is sent to the
* client side and stored in the buf.
* @param[in] fd
* @param[out] buf
* @param[in] count
* @return either -1 on error or return value of syscall write()
*/
ssize_t write(int fd, const void *buf, size_t count) {
    if (fd < minfd) {
        return orig_write(fd, buf, count);
    }
    size_t bytes = 2*sizeof(int) + sizeof(size_t) + count;
    int fnc = 2;
    char msg[bytes];
    memcpy(msg, &fnc, sizeof(int));
    memcpy(msg + sizeof(int), &fd, sizeof(int));
    memcpy(msg + 2*sizeof(int), &count, sizeof(size_t));
    memcpy(msg + 2*sizeof(int) + sizeof(size_t), buf, count);
    //msg = [OPCODE|FD|COUNT|BUF]
    //send loop
    sendloop(sockfd, msg, bytes);
    //receive reply from server
    ssize_t rcvbuf;
    recvloop(sockfd, (char *)&rcvbuf, sizeof(ssize_t));
    if (rcvbuf == -1) {
        handleerr();
    }
    return rcvbuf;
}
/**
* @brief Packs fd, offset, whence, and opcode into a char array and sends it to 
* the server. It then receives the response from the server which can be an 
* error or return value and returns it on the client side. 
* @param[in] fd
* @param[in] offset
* @param[in] whence
* @return either -1 on error or return value of syscall lseek()
*/
off_t lseek(int fd, off_t offset, int whence) {
    if (fd < minfd) {
        return orig_lseek(fd, offset, whence);
    }
    size_t bytes = 3*sizeof(int) + sizeof(off_t);
    int fnc = 4;
    char msg[bytes];
    memcpy(msg, &fnc, sizeof(int));
    memcpy(msg + sizeof(int), &fd, sizeof(int));
    memcpy(msg + 2*sizeof(int), &offset, sizeof(off_t));
    memcpy(msg + 2*sizeof(int) + sizeof(off_t), &whence, sizeof(int));
    //msg = [OPCODE|FD|OFFSET|WHENCE]
    sendloop(sockfd, msg, bytes);
    off_t rcvbuf;
    recvloop(sockfd, (char *)&rcvbuf, sizeof(off_t));
    if (rcvbuf == -1) {
        handleerr();
    }
    return rcvbuf;
}

/**
* @brief Packs opcode, pathlen, and path into a char array and sends it to the 
* server. It then receives the response from the server which can be an error or
* return value and returns it on the client side. buf is declared on the client
* side and content stored in buf from the server side read() call is sent to the
* client side and stored in the buf.
* @param[in] path
* @param[out] buf
* @return either -1 on error or return value of syscall stat()
*/
int stat(const char *path, struct stat *buf) {
    //[opcode|pathlen|path]
    int fnc = 5;
    size_t pathlen = strlen(path) + 1;
    size_t bytes = sizeof(int) + sizeof(size_t) + pathlen;
    char msg[bytes];
    memcpy(msg, &fnc, sizeof(int));
    memcpy(msg + sizeof(int), &pathlen, sizeof(size_t));
    memcpy(msg + sizeof(int) + sizeof(size_t), path, pathlen);
    sendloop(sockfd, msg, bytes);
    int rcvbuf;
    recvloop(sockfd, (char *)&rcvbuf, sizeof(int));
    if (rcvbuf == -1) {
        handleerr();
    } else {
        recvloop(sockfd, (char *)buf, sizeof(struct stat));
    }
    return rcvbuf;
}

/**
* @brief Packs opcode, pathlen, and path into a char array and sends it to the 
* server. It then receives the response from the server which can be an error or
* return value and returns it on the client side. 
* @param[in] pathname
* @return either -1 on error or return value of syscall unlink()
*/
int unlink(const char *pathname) {
    int fnc = 6;
    size_t pathlen = strlen(pathname) + 1;
    size_t bytes = sizeof(int) + sizeof(size_t)+ pathlen;
    char msg[bytes];
    memcpy(msg, &fnc, sizeof(int));
    memcpy(msg + sizeof(int), &pathlen, sizeof(size_t));
    memcpy(msg + sizeof(int) + sizeof(size_t), pathname, pathlen);
    //[OPCODE|PATHLEN|PATHNAME]
    sendloop(sockfd, msg, bytes);
    int rcvbuf;
    recvloop(sockfd, (char *)&rcvbuf, sizeof(int));
    if (rcvbuf == -1) {
        handleerr();
    }
    return rcvbuf;
}
/**
* @brief Packs opcode, fd, nbytes, and basep into a char array and sends it to the 
* server. It then receives the response from the server which can be an error or
* return value and returns it on the client side. buf is passed in on the client
* side and content stored in buf from the server side getdirentries() call is 
* sent to the client side and stored in the buf.
* @param[in] fd
* @param[out] buf
* @param[in] nbytes
* @param[in] basep
* @return either -1 on error or return value of library call getdirentires()
*/
ssize_t getdirentries(int fd, char  *buf,  size_t nbytes , off_t *basep) {
    if (fd < minfd) {
        return orig_getdirentries(fd, buf, nbytes, basep);
    }
    int fnc = 7;
    size_t bytes = 2*sizeof(int) + sizeof(size_t) + sizeof(off_t);
    char msg[bytes];
    memcpy(msg, &fnc, sizeof(int));
    memcpy(msg + sizeof(int), &fd, sizeof(int));
    memcpy(msg + 2*sizeof(int), &nbytes, sizeof(size_t));
    memcpy(msg + 2*sizeof(int) + sizeof(size_t), basep, sizeof(off_t));
    //[OPCODE|FD|NBYTES|BASEP]
    sendloop(sockfd, msg, bytes);
    ssize_t rcvbuf;
    recvloop(sockfd, (char *)&rcvbuf, sizeof(ssize_t));
    recvloop(sockfd, buf, nbytes);
    if (rcvbuf == -1) {
        handleerr();
    }
    return rcvbuf;
}

/**
* @brief Packs opcode, pathlen, and path into a char array and sends it to the 
* server. On the server side, getdirtree constructs a directory tree. The client
* receives the tree encoded into a char array or receives -1 on error which 
* indicates that the return value of the library call is NULL. In the non error
* case, it reconstructs the encoded tree into a tree directory and returns.
* @param[in] path
* @return either NULL on error or directory tree
*/
struct dirtreenode* getdirtree(const char *path) {
    int fnc = 8;
    size_t pathlen = strlen(path) + 1;
    size_t bytes = sizeof(int) + sizeof(size_t) + pathlen;
    //[OPCODE|PATHLEN|PATH]
    char msg[bytes];
    memcpy(msg, &fnc, sizeof(int));
    memcpy(msg + sizeof(int), &pathlen, sizeof(size_t));
    memcpy(msg + sizeof(int) + sizeof(size_t), path, pathlen);
    sendloop(sockfd, msg, bytes);
    int rcvbuf;
    //receive either -1 on error or size of tree
    recvloop(sockfd, (char *)&rcvbuf, sizeof(int));
    if (rcvbuf == -1) {
        handleerr();
        return NULL;
    }
    else {
        int treesize = rcvbuf;
        char buf[treesize];
        recvloop(sockfd, buf, treesize);
        struct dirtreenode *tree = malloc(sizeof(struct dirtreenode));
        int *offset = calloc(1, sizeof(int));
        tree = unpacktree(buf, offset);
        free(offset);
        return tree;
    }
}

void freedirtree(struct dirtreenode *dt) {
    return orig_freedirtree(dt);
}

// This function is automatically called when program is started
void _init(void) {
    // set function pointer orig_open to point to the original open function
    orig_open = dlsym(RTLD_NEXT, "open");
    orig_close = dlsym(RTLD_NEXT, "close");
    orig_read = dlsym(RTLD_NEXT, "read");
    orig_write = dlsym(RTLD_NEXT, "write");
    orig_lseek = dlsym(RTLD_NEXT, "lseek");
    orig_stat = dlsym(RTLD_NEXT, "stat");
    orig_unlink = dlsym(RTLD_NEXT, "unlink");
    orig_getdirentries = dlsym(RTLD_NEXT, "getdirentries");
    orig_getdirtree = dlsym(RTLD_NEXT, "getdirtree");
    orig_freedirtree = dlsym(RTLD_NEXT, "freedirtree");

    char *serverip;
    char *serverport;
    unsigned short port;
    int rv;
    struct sockaddr_in srv;
    
    // Get environment variable indicating the ip address of the server
    serverip = getenv("server15440");
    if (!serverip) {
        serverip = "127.0.0.1";
    }
    
    // Get environment variable indicating the port of the server
    serverport = getenv("serverport15440");
    if (!serverport) {
        serverport = "15440";
    }
    port = (unsigned short)atoi(serverport);
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);    // TCP/IP socket
    if (sockfd<0) err(1, 0);            // in case of error
    
    // setup address structure to point to server
    memset(&srv, 0, sizeof(srv));            // clear it first
    srv.sin_family = AF_INET;            // IP family
    srv.sin_addr.s_addr = inet_addr(serverip);    // IP address of server
    srv.sin_port = htons(port);            // server port

    // actually connect to the server
    rv = connect(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
    if (rv<0) err(1,0);
}
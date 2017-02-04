/*
 * Copyright (c) 2014      Andrea Marcelli marcelli.andrea@outlook.it
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Andrea Marcelli marcelli.andrea@outlook.it
 *
 *
 */

#include "man_in_the_middle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>    /* _exit, fork */

#include "lwip/opt.h"
#include "lwip/sys.h"
#include "lwip/api.h"
#include "lwip/sys.h"
#include "lwip/sockets.h"
#include "ipv4/lwip/ip_addr.h"

#include "lwip/debug.h"

#define SOCKET int
#define SOCKET_ERROR -1

#define BUFFER_RECV 1500
#define TIMEOUT 15

#define IPADDR_ANY          ((u32_t)0x00000000UL)
#define SEND_ERROR  1

//#define DEBUG_PRINT_FILE MANINTHEMIDDLE_DEBUG
#define DEBUG_PRINT_FILE 0


#define left "/Users/andreamarcelli/Desktop/log_left.txt"
#define right "/Users/andreamarcelli/Desktop/log_right.txt"

typedef enum {false, true} boolean;

typedef struct {
    SOCKET  accepted_socket;
    SOCKET  remote_socket;
}sockets;


typedef struct{
    int  accepted_socket;
    struct sockaddr_in accepted;
}infoo;

/** forward declaration */
void printfile_left(char *buf, int len);
void printfile_right(char *buf, int len);
int send_a(const char * string, int client, int dim);


#define ASSERT(condition, message, action) {if(condition){ printf("%s\n", message);  action; }}



/*
 *  It sends dim bytes over a connection. 
 *
 */
int send_a(const char * string, SOCKET remote_socket, int dim){
    
    /** SEND SOMETHING: **/
    
    ssize_t remaining = dim;
    ssize_t sent;
    
    const char *buffer = string;
    
    while (remaining>0) {
        
        sent = send(remote_socket, buffer, dim, 0);
        ASSERT(sent<0, "Errore nell'invio dei dati!", return 1);
        
        remaining-=sent;
        buffer+=sent;
    }
    
    return 0;
}



/*
 *
 *  Print the received buffer in a file.
 *
 */
void printfile_left(char *buf, int len){
    
    static FILE *fp;
    
    if (fp==NULL) {
        fp = fopen(left, "wb");
    }
    
    ASSERT(fp==NULL, "Error while opening the left log file.\n", return);
    
    fwrite(buf, len, 1, fp);
}



/*
 *
 *  Print the received buffer in a file.
 *
 */
void printfile_right(char *buf, int len){
    
    static FILE *fp;
    
    if (fp==NULL) {
        fp = fopen(right, "wb");
    }
    
    ASSERT(fp==NULL, "Error while opening the right log file.\n", return);
    
    fwrite(buf, len, 1, fp);
}



/*
 *  It manages the client (who opened the connection) side
 *  of the man in the middle. It takes the data from the socket
 *  of the other side and send it to the client. When the connection
 *  is closed, this closed the socket too. 
 *
 */
static void manage_left(void *arg){
    
    int received;
    
    char buffer_rcv1[BUFFER_RECV];
    
    SOCKET remote_socket, accepted_socket;
    
    
    sockets *sock_info = (sockets *) arg;
    
    ASSERT(sock_info==NULL, "sock_info is NULL", exit(1));
    
    remote_socket = sock_info->remote_socket;
    accepted_socket = sock_info->accepted_socket;
    
    while ((received=recv(remote_socket, buffer_rcv1, BUFFER_RECV-1, 0))>0) {
        
        buffer_rcv1[received]='\0'; /* Usefull only for debugging (if you want to print or calculate length in a easy way) */

#if DEBUG_PRINT_FILE
        printfile_right(buffer_rcv1, received); /* print what I received form remote */
#endif       
        
        if(send_a(buffer_rcv1, accepted_socket, received)==SEND_ERROR){
            LWIP_DEBUGF(MANINTHEMIDDLE_DEBUG, ("Sending error, accepted_socket: %d\n", accepted_socket));
            break;
        }
    }
    if (received <0) {
        LWIP_DEBUGF(MANINTHEMIDDLE_DEBUG, ("Receiving Error left\n"));

    }
    
    LWIP_DEBUGF(MANINTHEMIDDLE_DEBUG, ("Closing accepted_socket: %d\n", accepted_socket));
    if (accepted_socket) {
        sleep(4);
        close(accepted_socket);
    }
    
}



/*
 *  It manages the remote (to whom I open the connection) side
 *  of the man in the middle. It takes the data from the socket
 *  of the other side and send it to the remote host. 
 *  When the connection is closed, this closed the socket too.
 *
 */
static void manage_right(void *arg){
    
    int received;
    
    char buffer_rcv[BUFFER_RECV];
    
    SOCKET remote_socket, accepted_socket;
    
    sockets *sock_info = (sockets *) arg;
    
    ASSERT(sock_info==NULL, "sock_info is NULL", exit(1));
    
    remote_socket = sock_info->remote_socket;
    accepted_socket = sock_info->accepted_socket;

    while ((received=recv(accepted_socket, buffer_rcv, BUFFER_RECV-1, 0))>0) {
        
        buffer_rcv[received]='\0'; /* Usefull only for debugging (if you want to print or calculate length in a easy way) */

#if DEBUG_PRINT_FILE
        printfile_left(buffer_rcv, received); /* print what I received from host */
#endif
        
        if(send_a(buffer_rcv, remote_socket, received)==SEND_ERROR){
            LWIP_DEBUGF(MANINTHEMIDDLE_DEBUG, ("Sending error, remote_socket: %d\n", remote_socket));
            break;
        }
    }
    
    if (received <0) {
        LWIP_DEBUGF(MANINTHEMIDDLE_DEBUG, ("Receiving Error right\n"));
    }
    
    LWIP_DEBUGF(MANINTHEMIDDLE_DEBUG, ("Closing remote_socket: %d\n", remote_socket));
    
    if (remote_socket) {
        sleep(4);
        close(remote_socket);
    }
    
}



/*
*
*   A new thread is created for each accepted connection. 
*   It get the address of remote host, it tries to open a connection with it,
*   and if everything works two new thread are created to manage the two sides 
*   of the man in the middle. 
*
*/
static void manage_connection(void *arg){
    
    SOCKET remote_socket, accepted_socket;
    struct sockaddr_in remote, local, accepted, info;
    struct sockaddr *generic;
    socklen_t dim = sizeof(struct sockaddr_in);
    
    sockets sock_info;
    
    infoo *info1 = (infoo *) arg;
    
    accepted_socket = info1->accepted_socket;
    accepted = info1->accepted;
    
    LWIP_DEBUGF(MANINTHEMIDDLE_DEBUG, ("Son, accepted_socket: %d\n", accepted_socket));
    
    /* Create the remote_socket */
    remote_socket = socket(PF_INET, SOCK_STREAM, 0);
    
    /* Get some info about the local host... */
    lwip_getsockname(accepted_socket, (struct sockaddr *) &info, &dim);
    LWIP_DEBUGF(MANINTHEMIDDLE_DEBUG, ("Local Address: %s Local Port: %d\n", inet_ntoa(info.sin_addr), ntohs(info.sin_port)));
        
    /* Fill the structure with the local informations that will be used to connect with the remote socket - right. */
    memset(&remote, 0, sizeof(struct sockaddr_in));
    remote.sin_family = AF_INET;
    remote.sin_addr = info.sin_addr;
    remote.sin_port = info.sin_port;
    
    /* Get some info about the remote host. */
    lwip_getpeername(accepted_socket, (struct sockaddr *) &info, &dim);
    LWIP_DEBUGF(MANINTHEMIDDLE_DEBUG, ("Remote Address: %s Remote Port: %d\n", inet_ntoa(info.sin_addr), ntohs(info.sin_port)));
    
#if PURE_MIM

    /* Fill the structure with the remote informations that will be used to connect with the remote socket - left. */
    memset(&local, 0, sizeof(struct sockaddr_in));
    local.sin_family = AF_INET;
    local.sin_addr = info.sin_addr;
    local.sin_port = info.sin_port;
    
    /* Connect with the remote host */
    ASSERT(lwip_connect_from_source(remote_socket, (struct sockaddr*)&remote, sizeof(remote), (struct sockaddr*)&local, sizeof(local))==SOCKET_ERROR,
                                                                                        "Error while opening connection (from source) with remote.", close(accepted_socket));
    LWIP_DEBUGF(MANINTHEMIDDLE_DEBUG, ("Connected with: %s:%d from %s:%d\n", inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), inet_ntoa(local.sin_addr), ntohs(local.sin_port)));
    
#else
    
    /* Connect with the remote host */
    ASSERT(lwip_connect(remote_socket, (struct sockaddr*)&remote, sizeof(remote))==SOCKET_ERROR, "Error while opening connection with remote.", close(accepted_socket));
    LWIP_DEBUGF(MANINTHEMIDDLE_DEBUG, ("Connected with: %s:%d\n", inet_ntoa(remote.sin_addr), ntohs(remote.sin_port)));
    
#endif /* PURE_MIM */
    
    /* Copy the information in  */
    sock_info.accepted_socket = accepted_socket;
    sock_info.remote_socket = remote_socket;

    
    /* I open two threads to manage the two sides of the connection. */
    sys_thread_new("Manage connection_LEFT", manage_left, &sock_info, 0, 0);
    sys_thread_new("Manage connection_RIGHT", manage_right, &sock_info, 0, 0);
    
    /* In orfer to give time to the thread to copy the information... */
    sleep(1);
    
}



/*
*   It binds a socket to a generic connection: each new tcp connection is
*   accepted and a new thread is created in order to manage it. 
*/
static void man_in_the_middle(void *arg)
{
    
    SOCKET listening_socket, accepted_socket;
    struct sockaddr_in listening, accepted;
    socklen_t dim;
    
    infoo info1;
    
    printf("MAN IN THE MIDDLE IMPLEMENTATION THROUGH LWIP\n");
    
    printf("                    **** LEGAL DISCLAIMER ****\n");
    
    printf("            This software could be potentially damaging or dangerous.\n \
           Refer to the laws in your province/country before accessing,\n \
           using,or in any other way utilizing these materials.\n \
           These materials are for educational and research purposes only.\n \
           Do not attempt to violate the law with anything contained here.\n \
           Authors of this material, or anyone else affiliated in any way,\n \
           is going to accept responsibility for your actions. \n\n");
    
    
    /* Initialize the socket module. */
    lwip_socket_init();
    
    /* Create the listening socket */
    listening_socket = socket(PF_INET, SOCK_STREAM, 0);
    ASSERT(listening_socket<0, "listening_socket creation failed", exit(1));
    
    /* Fill the structure that contains listening information */
    memset(&listening, 0, sizeof(struct sockaddr_in));
    listening.sin_family = AF_INET;
    listening.sin_addr.s_addr = IPADDR_ANY;
    listening.sin_port = 0;
    
    /* Bind the listening_socket. */
    ASSERT(lwip_bind(listening_socket, (struct sockaddr *)&listening, sizeof(struct sockaddr_in)) == SOCKET_ERROR, "Binding Error", exit(1));

    /* Listening with backlog of 5 */
    ASSERT(lwip_listen(listening_socket, 100)!=0, "Error listening operation.", exit(1));
    
    dim = sizeof(struct sockaddr_in);
    
    while (1) {
    
        LWIP_DEBUGF(MANINTHEMIDDLE_DEBUG, ("Waiting for a new connection!\n"));
        
        /* Accepting a new socket */
        ASSERT((accepted_socket = lwip_accept(listening_socket, (struct sockaddr *) &accepted, &dim))== SOCKET_ERROR, "Accepting new socket error!", exit(1));
        
        LWIP_DEBUGF(MANINTHEMIDDLE_DEBUG, ("Accepted connection from: %s:%d\n", inet_ntoa(accepted.sin_addr), ntohs(accepted.sin_port)));
        
        /* Create a new son */
        
        info1.accepted = accepted;
        info1.accepted_socket = accepted_socket;
    
        sys_thread_new("Manage connection", manage_connection, &info1, 0, 0);

    }

    LWIP_DEBUGF(MANINTHEMIDDLE_DEBUG, ("Closing listening_socket: %d\n", listening_socket));
    
    close(listening_socket);
}



/*
 *   It starts a new connection.
 *
*/
void man_in_the_middle_init(void)
{
    sys_thread_new("man_in_the_middle", man_in_the_middle, NULL, 0, 0);
}


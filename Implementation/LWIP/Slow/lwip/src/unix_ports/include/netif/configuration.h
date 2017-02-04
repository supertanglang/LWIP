/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
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

#ifndef _configuration_h
#define _configuration_h

#include "lwip/opt.h"
#include "lwip/ip_addr.h"

/* (manual) host IP configuration */



/* Definition of the MAC address of the interface (it may be even virtual,
 just need to receive and send something) that receive and sends the packets
 of the man in the middle.
 
 If you are going to use libpcap, it's better to use the same address of the
 physical interface that will be used. (During my attempts, I have always used
 libpcap in non promiscue mode).
 */

#define MACADD1 0x00
#define MACADD2 0x23
#define MACADD3 0x12
#define MACADD4 0x53
#define MACADD5 0xb3
#define MACADD6 0x49


#if SECOND_INTERFACE

    #define MAC_2_ADD1 0x00
    #define MAC_2_ADD2 0x23
    #define MAC_2_ADD3 0x32
    #define MAC_2_ADD4 0xd1
    #define MAC_2_ADD5 0x35
    #define MAC_2_ADD6 0x58

#endif /* SECOND_INTERFACE */


/* Definition of the primary and secondary interfaces. */
/* The secondary interfaces must be enabled in the main function. */

#define PRIMARY "en0"
#define SECONDARY "en0"


/* Only if you want that all the MAC ADDRESS will be static, fill this module.
   STATIC_ARP module must be enabled. */

#if STATIC_ARP

    /* number of entries */
    #define ARP_ENTRIES 2

    ip_addr_t ip_addresses[ARP_ENTRIES];

    #include "lwip/ip_addr.h"    /* where the structures are defined */
    #include "netif/etharp.h"


    #include <sys/socket.h> /* these are used for the conversion purpose */
    #include <netinet/in.h>
    #include <arpa/inet.h>

    /*
     
     I use the functions defined in the socket api, just to be sure to avoid error
     during the conversion phase. 
     
     struct in_addr {
        unsigned long s_addr;  // load with inet_aton()
     };
     */

    struct in_addr temp;

        /* set ip address -- android device */
    inet_aton("192.168.0.55", &temp);
    ip_addresses[0].addr=temp.s_addr;

        /* set ip address -- gateway device */
    inet_aton("192.168.0.1", &temp);
    ip_addresses[1].addr=temp.s_addr;

    struct eth_addr eth_addresses[ARP_ENTRIES];

        /* set mac address -- android device */
    eth_addresses[0].addr[0] = 0x34;
    eth_addresses[0].addr[1] = 0xaa;
    eth_addresses[0].addr[2] = 0x8b;
    eth_addresses[0].addr[3] = 0x7d;
    eth_addresses[0].addr[4] = 0x0e;
    eth_addresses[0].addr[5] = 0x3c;

        /* set mac address -- default gateway */
    eth_addresses[1].addr[0] = 0x00;
    eth_addresses[1].addr[1] = 0x22;
    eth_addresses[1].addr[2] = 0x3f;
    eth_addresses[1].addr[3] = 0x51;
    eth_addresses[1].addr[4] = 0x41;
    eth_addresses[1].addr[5] = 0x08;


#endif /* STATIC_ARP */



#endif

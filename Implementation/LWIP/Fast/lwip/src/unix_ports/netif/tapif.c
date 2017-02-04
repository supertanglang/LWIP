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
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
 
#include <stdio.h>
#include <stdlib.h>
#include "pcap.h" /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */

//#include "netif/mac_address.h" /* definition of the mac address */
//#include "netif/l2_libpcap_interfaces.h" /* definition of the interfaces */

#include "netif/etharp.h"

#include "netif/configuration.h"

#include "netif/tapif.h"
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>


#include "lwip/debug.h"

#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/ip.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"

#include "netif/etharp.h"
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <netinet/if_ether.h> /* includes net/ethernet.h */

#if defined(LWIP_DEBUG) && defined(LWIP_TCPDUMP)
#include "netif/tcpdump.h"
#endif /* LWIP_DEBUG && LWIP_TCPDUMP */

#define IFNAME0 'p'
#define IFNAME1 '1'
#define IFNAME2 'p'
#define IFNAME3 '2'

#define STRESS_TEST 0  /* It simulate packet loss. */

/** Gobal values for the libpcap interfaces. **/

const char *dev = PRIMARY;
const char *dev2 = SECONDARY;

struct netif *netifff;
char errbuf[PCAP_ERRBUF_SIZE];
char errbuf2[PCAP_ERRBUF_SIZE];

pcap_t* descr;
pcap_t* descr2;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

struct tapif {
  struct eth_addr *ethaddr;
    /* Add whatever per-interface state that is needed here. */
  int fd;
};

#define PACKET_SIZE 65535
#define TO_MS 2 /* in ms */

/* Forward declarations. */
static void low_level_init(struct netif *netif);
static void low_level_init2(struct netif *netif);

static void tapif_thread(void *data);
static void tapif_thread2(void *arg);

static err_t low_level_output2(struct netif *netif, struct pbuf *p);
static err_t low_level_output(struct netif *netif, struct pbuf *p);


/*-----------------------------------------------------------------------------------*/
/*
 * tapif_init():
 *
 * Should be called at the beginning of the program to set up the
 * network interface. It calls the function low_level_init() to do the
 * actual setup of the hardware.
 *
 */
/*-----------------------------------------------------------------------------------*/
err_t tapif_init(struct netif *netif)
{
    struct tapif *tapif;
    
    tapif = (struct tapif *)mem_malloc(sizeof(struct tapif));
    if (!tapif) {
        return ERR_MEM;
    }
    netif->state = tapif;
    netif->name[0] = IFNAME0;
    netif->name[1] = IFNAME1;
    netif->output = etharp_output;
    netif->linkoutput = low_level_output;
    netif->mtu = 1500;
    /* hardware address length */
    netif->hwaddr_len = 6;
    
    tapif->ethaddr = (struct eth_addr *)&(netif->hwaddr[0]);
    
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;
    
    low_level_init(netif); /* Call the function for libpcap initialization */
    
    return ERR_OK;
}

#if SECOND_INTERFACE

err_t tapif_init2(struct netif *netif)
{
    struct tapif *tapif;
    
    tapif = (struct tapif *)mem_malloc(sizeof(struct tapif));
    if (!tapif) {
        return ERR_MEM;
    }
    netif->state = tapif;
    netif->name[0] = IFNAME2;
    netif->name[1] = IFNAME3;
    netif->output = etharp_output;
    netif->linkoutput = low_level_output2;
    netif->mtu = 1500;
    /* hardware address length */
    netif->hwaddr_len = 6;
    
    tapif->ethaddr = (struct eth_addr *)&(netif->hwaddr[0]);
    
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;
    
    low_level_init2(netif); /* Call the function for libpcap initialization */
    
    return ERR_OK;
}
#endif /* SECOND_INTERFACE */
/*-----------------------------------------------------------------------------------*/




/*-----------------------------------------------------------------------------------*/
/*
 * low_level_init():
 *
 * It manages the initialization of the interface through libpcap.
 * It sets the MAC ADDRESS and open the capture.
 * If you want to Do whatever else is needed to initialize interface, this
 * this is the place!
 *
 */
/*-----------------------------------------------------------------------------------*/
static void low_level_init(struct netif *netif)
{
  struct tapif *tapif;

  tapif = (struct tapif *)netif->state;

  /* Obtain MAC address from network interface. */

  /* Address of the first interface. */
  tapif->ethaddr->addr[0] = MACADD1;
  tapif->ethaddr->addr[1] = MACADD2;
  tapif->ethaddr->addr[2] = MACADD3;
  tapif->ethaddr->addr[3] = MACADD4;
  tapif->ethaddr->addr[4] = MACADD5;
  tapif->ethaddr->addr[5] = MACADD6;
    

    /* Insert the stati ARP entry -- only if STATIC_ARP is enabled */
#if STATIC_ARP
    int i;
    for (i=0; i<ARP_ENTRIES; i++) {
        if(etharp_add_static_entry(&ip_addresses[i], &eth_addresses[i])==ERR_OK){
            LWIP_DEBUGF(LIBPCAP_DEBUG, ("low_level_init2() | etharp_add_static_entry ok\n"));
            
        }else{
            LWIP_DEBUGF(LIBPCAP_DEBUG, ("low_level_init2() | etharp_add_static_entry ERROR!!\n"));
        }
    }
#endif

  /** Initialization of the libpcap libraries.  **/
  	
    /* dev = pcap_lookupdev(errbuf); */ /* For automatic research of the interface. */

    if(dev == NULL)
    {
        LWIP_DEBUGF(LIBPCAP_DEBUG, ("low_level_init() | %s\n",errbuf));
        exit(1);
    }

    LWIP_DEBUGF(LIBPCAP_DEBUG, ("low_level_init() | DEV: %s\n",dev));


    descr = pcap_open_live(dev,PACKET_SIZE,1,TO_MS,errbuf);
    //pcap_setdirection(descr,PCAP_D_IN);

    if(descr == NULL)
    {
        LWIP_DEBUGF(LIBPCAP_DEBUG, ("low_level_init() | pcap_open_live(): %s\n",errbuf));
        exit(1);
    }

    LWIP_DEBUGF(LIBPCAP_DEBUG, ("low_level_init() | Initialization of libpcap on %s completed!\n", dev));
    

	/** NEW THREAD WAITITING FOR PACKET ARRIVALS **/
    
    sys_thread_new("tapif_thread", tapif_thread, netif, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
}

#if SECOND_INTERFACE

static void low_level_init2(struct netif *netif)
{
    struct tapif *tapif;
    
    tapif = (struct tapif *)netif->state;
    
    /* Address of the second interface. */
    tapif->ethaddr->addr[0] = MAC_2_ADD1;
    tapif->ethaddr->addr[1] = MAC_2_ADD2;
    tapif->ethaddr->addr[2] = MAC_2_ADD3;
    tapif->ethaddr->addr[3] = MAC_2_ADD4;
    tapif->ethaddr->addr[4] = MAC_2_ADD5;
    tapif->ethaddr->addr[5] = MAC_2_ADD6;
    
    /** Initialization of the libpcap libraries.  **/
  	
	/*dev = pcap_lookupdev(errbuf2);*/
    
    if(dev2 == NULL)
    {
        LWIP_DEBUGF(LIBPCAP_DEBUG, ("low_level_init2() | %s\n",errbuf2));
        exit(1);
    }
    
    LWIP_DEBUGF(LIBPCAP_DEBUG, ("low_level_init2() | DEV: %s\n",dev2));

	
    descr2 = pcap_open_live(dev2,PACKET_SIZE,1,TO_MS,errbuf2);
    
    if(descr2 == NULL)
    {
        LWIP_DEBUGF(LIBPCAP_DEBUG, ("low_level_init2() | pcap_open_live(): %s\n",errbuf2));
        exit(1);
    }
    
    LWIP_DEBUGF(LIBPCAP_DEBUG, ("low_level_init2() | Initialization of libpcap on %s completed!\n", dev2));

    
    /** NEW THREAD WAITITING FOR PACKET ARRIVALS **/
    
    sys_thread_new("tapif_thread2", tapif_thread2, netif, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
    
}
#endif /* SECOND_INTERFACE */
/*-----------------------------------------------------------------------------------*/



/*-----------------------------------------------------------------------------------*/
/*
 * tapif_thread():
 *
 * It manages the initialization of the interface through libpcap.
 * It sets the MAC ADDRESS and open the capture.
 * If you want to Do whatever else is needed to initialize interface, this
 * this is the place!
 *
 */
/*-----------------------------------------------------------------------------------*/
static void tapif_thread(void *arg)
{
    struct netif *netif;
    struct tapif *tapif;
    fd_set fdset;
    int ret;
    
    netif = (struct netif *)arg;
	netifff=netif;
    tapif = (struct tapif *)netif->state;
    
    while(1) {
        
        /* Wait for a packet to arrive. */
        LWIP_DEBUGF(LIBPCAP_DEBUG, ("tapif_thread() | pcap_loop in esecuzione!\n"));
  		pcap_loop(descr, 0, packet_handler, NULL);
    }
}

#if SECOND_INTERFACE

static void tapif_thread2(void *arg)
{
    struct netif *netif;
    struct tapif *tapif;
    fd_set fdset;
    int ret;
    
    netif = (struct netif *)arg;
	netifff=netif;
    tapif = (struct tapif *)netif->state;
    
    while(1) {
        
        /* Wait for a packet to arrive. */
        LWIP_DEBUGF(LIBPCAP_DEBUG, ("tapif_thread2() | pcap_loop in esecuzione!\n"));
  		pcap_loop(descr2, 0, packet_handler, NULL);
                
    }
}
#endif /* SECOND_INTERFACE */
/*-----------------------------------------------------------------------------------*/



/*-----------------------------------------------------------------------------------*/
/*
 * packet_handler():
 *
 * implementa in modo congiunto (in un'unica funzione)
 * quelle che prima erano le funizoni di tapif input e low_level input!
 *
 */
/*-----------------------------------------------------------------------------------*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header,const u_char *pkt_data){
    
	struct eth_hdr *ethhdr;
	struct tapif *tapif;
	struct pbuf *p, *q;
	const unsigned char *bufptr;
	
	int i;
	u_char *ptr;
	int drop =0;
 	struct ether_header *eptr;
	
	u16_t len = header->len;
    
	
	/* We allocate a pbuf chain of pbufs from the pool. */
  	p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    
    if(p != NULL) {
        
        /* We iterate over the pbuf chain until we have read the entire packet into the pbuf. */
        bufptr=pkt_data;
        
        for(q = p; q != NULL; q = q->next) {
            
            memcpy(q->payload, bufptr, q->len);
            bufptr += q->len;
        }
    } else {
        /* Packet is dropped. */
        LWIP_DEBUGF(LIBPCAP_DEBUG, ("packet_handler() | Can't allocate a new pbuf!!\n"));
    }
    
    ethhdr = (struct eth_hdr *)p->payload;
    
    /* Controllare questo switch case. */
    switch(htons(ethhdr->type)) {
            /* IP or ARP packet? */
        case ETHTYPE_IP:
        case ETHTYPE_ARP:
            
#if PPPOE_SUPPORT
            /* PPPoE packet? */
        case ETHTYPE_PPPOEDISC:
        case ETHTYPE_PPPOE:
#endif /* PPPOE_SUPPORT */
            
            
            /* full packet is sent to tcpip_thread to process */
            if (netifff->input(p, netifff) != ERR_OK) {
                LWIP_DEBUGF(LIBPCAP_DEBUG, ("packet_handler() | Error while sending packet to upper IP layer\n"));
                pbuf_free(p);
                p = NULL;
            }
            break;
            
        default:
            pbuf_free(p);
            break;
    }
	
}
/*-----------------------------------------------------------------------------------*/



/*-----------------------------------------------------------------------------------*/
/*
 * low_level_output():
 *
 * Should do the actual transmission of the packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * might be chained.
 *
 */
/*-----------------------------------------------------------------------------------*/

static err_t
low_level_output(struct netif *netif, struct pbuf *p)
{
  struct pbuf *q;
  char buf[1514];  /* MAX MTU is fixed. */
  char *bufptr;
  struct tapif *tapif;

  tapif = (struct tapif *)netif->state;
    
    
#if STRESS_TEST
    if(((double)rand()/(double)RAND_MAX) < 0.2) {
    LWIP_DEBUGF(LIBPCAP_DEBUG, ("low_level_output() | Stress test: packet dropped!\n"));
    return ERR_OK;
    }
#endif
    
    
 /* Packet data is saved in a linked list of pbuf. Use this 
    cycle to save that in a buf array.
    The size of the data in each pbuf is kept in the ->len variable. */
  
    
  bufptr = &buf[0];

  for(q = p; q != NULL; q = q->next) {
      
    memcpy(bufptr, q->payload, q->len);
    bufptr += q->len;
  }

    
  /* Send the paccket using pacap library. */
  if (pcap_sendpacket(descr, (u_char*) buf /* packet's bytes */, p->tot_len /* packet's size */) != 0){
        LWIP_DEBUGF(LIBPCAP_DEBUG, ("\n low_level_output | Libpcap error sending the packet: %s\n", pcap_geterr(descr)));
  }
  
  return ERR_OK;
}

#if SECOND_INTERFACE

static err_t
low_level_output2(struct netif *netif, struct pbuf *p)
{
    struct pbuf *q;
    char buf[1514];
    char *bufptr;
    struct tapif *tapif;
    
    tapif = (struct tapif *)netif->state;
    
    
#if STRESS_TEST
    if(((double)rand()/(double)RAND_MAX) < 0.2) {
        LWIP_DEBUGF(LIBPCAP_DEBUG, ("low_level_output2() | Stress test: packet dropped!\n"));
        return ERR_OK;
    }
#endif
    
    
    /* Packet data is saved in a linked list of pbuf. Use this
     cycle to save that in a buf array.
     The size of the data in each pbuf is kept in the ->len variable. */
    
    
    bufptr = &buf[0];
    
    for(q = p; q != NULL; q = q->next) {
        
        memcpy(bufptr, q->payload, q->len);
        bufptr += q->len;
    }
    
    /* Send the paccket using pacap library. */
    if (pcap_sendpacket(descr2, (u_char*) buf, p->tot_len /* size */) != 0){
        LWIP_DEBUGF(LIBPCAP_DEBUG, ("low_level_output2() | \nError sending the packet: %s\n", pcap_geterr(descr2)));
    }
    
    return ERR_OK;
}

#endif /* SECOND_INTERFACE */
/*-----------------------------------------------------------------------------------*/

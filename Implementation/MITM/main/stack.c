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

#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>

#include "lwip/opt.h"

#include "lwip/init.h"

#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/sys.h"

#include "lwip/stats.h"

#include "lwip/tcp_impl.h"
#include "lwip/inet_chksum.h"

#include "netif/configuration.h"

#include "lwip/tcpip.h"
#include "lwip/sockets.h"

#include "netif/tapif.h"
#include "netif/tunif.h"

#include "netif/unixif.h"
#include "netif/dropif.h"
#include "netif/pcapif.h"

#include "netif/tcpdump.h"

#if PPP_SUPPORT
#include "netif/ppp/ppp.h"
#define PPP_PTY_TEST 1
#include <termios.h>
#endif

#include "lwip/ip_addr.h"
#include "arch/perf.h"

#include "man_in_the_middle.h"
#include "netif/configuration.h"

#if LWIP_RAW
#include "lwip/icmp.h"
#include "lwip/raw.h"
#endif



/* Definition of the structure that implements the interfaces. */
struct netif netif1, netif2;

static ip_addr_t ipaddr1, netmask1, gw1;
static ip_addr_t ipaddr2, netmask2, gw2;


static struct option longopts[] = {
  {"help", no_argument, NULL, 'h'},
  {"gateway", required_argument, NULL, 'g'},
  {"ipaddr", required_argument, NULL, 'i'},
  {"netmask", required_argument, NULL, 'm'},
  {NULL, 0, NULL, 0}
};


#define NUM_OPTS ((sizeof(longopts) / sizeof(struct option)) - 1)

static void init_netifs(void);


static void usage(void)
{
  unsigned char i;

  printf("options:\n");
  for (i = 0; i < NUM_OPTS; i++) {
    printf("-%c --%s\n",longopts[i].val, longopts[i].name);
  }
}


static void tcpip_init_done(void *arg)
{
  sys_sem_t *sem;
  sem = (sys_sem_t *)arg;

  init_netifs();

  sys_sem_signal(sem);
}



/*-----------------------------------------------------------------------------------*/
/*
 *      init_netifs -- creation of the network interfaces. 
 *
 */
static void init_netifs(void)
{
  
    /* Add the interface to the list of the available ones. */
    
  netif_set_default(netif_add(&netif1,&ipaddr1, &netmask1, &gw1, NULL, tapif_init, tcpip_input));
  netif_set_up(&netif1);
    

#if SECOND_INTERFACE
     
     /* Add a second interface to the list of the available ones. */
  netif_add(&netif2,&ipaddr2, &netmask2, &gw2, NULL, tapif_init2, tcpip_input);
  netif_set_up(&netif2);

#endif /* SECOND_INTERFACE */

    
    /* Call the program that implements the man in the middle (man_in_the_middle.c) */

  man_in_the_middle_init();

}



/*-----------------------------------------------------------------------------------*/
/*
 *      main_thread function
 *
 */
static void main_thread(void *arg){
  sys_sem_t sem;
#if PPP_SUPPORT
  sio_fd_t ppp_sio;
#endif
  LWIP_UNUSED_ARG(arg);

  netif_init();

  if(sys_sem_new(&sem, 0) != ERR_OK) {
    LWIP_ASSERT("Failed to create semaphore", 0);
  }
    
  tcpip_init(tcpip_init_done, &sem);
    
  sys_sem_wait(&sem);


#ifdef MEM_PERF
  mem_perf_init("/tmp/memstats.client");
#endif /* MEM_PERF */
    
    
  /* Block forever. */
  sys_sem_wait(&sem);
}



/*-----------------------------------------------------------------------------------*/
/*
 *      MAIN function --> static definition of network configuration of the interfaces. 
 *
 */
int main(int argc, char **argv){
    
  struct in_addr inaddr;
  int ch;
  char ip_str[16] = {0}, nm_str[16] = {0}, gw_str[16] = {0};

    
    IP4_ADDR(&gw1, 192,168,0,1);
    IP4_ADDR(&netmask1, 255,255,255,0);
    IP4_ADDR(&ipaddr1, 192,168,0,33);
    
//    IP4_ADDR(&gw1, _GW1);
//    IP4_ADDR(&netmask1, _NM1);
//    IP4_ADDR(&ipaddr1, _IP1);
    
    
#if SECOND_INTERFACE /* only if it's enabled */
    
//#define _IP2    192,168,0,33
//#define _NM2    255,255,255,0
//#define _GW2    192,168,0,1
    
    IP4_ADDR(&gw2, 192,168,1,1);
    IP4_ADDR(&netmask2, 255,255,255,0);
    IP4_ADDR(&ipaddr2, 192,168,1,33);
    
#endif /* SECOND_INTERFACE */
    
    
  while ((ch = getopt_long(argc, argv, "dhg:i:m:", longopts, NULL)) != -1) {
    switch (ch) {
      case 'h':
        usage();
        exit(0);
        break;
      case 'g':
        inet_aton(optarg, &inaddr);
        gw1.addr = inaddr.s_addr;
        break;
      case 'i':
        inet_aton(optarg, &inaddr);
        ipaddr1.addr = inaddr.s_addr;
        break;
      case 'm':
        inet_aton(optarg, &inaddr);
        netmask1.addr = inaddr.s_addr;
        break;
      default:
        usage();
        break;
    }
  }
    
  argc -= optind;
  argv += optind;

  inaddr.s_addr = ipaddr1.addr;
  strncpy(ip_str,inet_ntoa(inaddr),sizeof(ip_str));
    
  inaddr.s_addr = netmask1.addr;
  strncpy(nm_str,inet_ntoa(inaddr),sizeof(nm_str));
    
  inaddr.s_addr = gw1.addr;
  strncpy(gw_str,inet_ntoa(inaddr),sizeof(gw_str));
    
  printf("INTERFACE 1: Host at %s mask %s gateway %s\n", ip_str, nm_str, gw_str);
    
#if SECOND_INTERFACE

    inaddr.s_addr = ipaddr2.addr;
    strncpy(ip_str,inet_ntoa(inaddr),sizeof(ip_str));
    
    inaddr.s_addr = netmask2.addr;
    strncpy(nm_str,inet_ntoa(inaddr),sizeof(nm_str));
    
    inaddr.s_addr = gw2.addr;
    strncpy(gw_str,inet_ntoa(inaddr),sizeof(gw_str));
    
    printf("INTERFACE 2: Host at %s mask %s gateway %s\n", ip_str, nm_str, gw_str);

#endif /* SECOND_INTERFACE */


#ifdef PERF
  perf_init("/tmp/simhost.perf");
#endif /* PERF */

  sys_thread_new("main_thread", main_thread, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
  pause();
  return 0;
}

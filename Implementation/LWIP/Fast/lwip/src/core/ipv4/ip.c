/**
 * @file
 * This is the IPv4 layer implementation for incoming and outgoing IP traffic.
 *
 * @see ip_frag.c
 *
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "lwip/opt.h"
#include "lwip/ip.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/ip_frag.h"
#include "lwip/inet_chksum.h"
#include "lwip/netif.h"
#include "lwip/icmp.h"
#include "lwip/igmp.h"
#include "lwip/raw.h"
#include "lwip/udp.h"
#include "lwip/tcp_impl.h"
#include "lwip/snmp.h"
#include "lwip/dhcp.h"
#include "lwip/autoip.h"
#include "lwip/stats.h"
#include "arch/perf.h"

/*aggiunta da me!*/
#include <stdio.h>

#include <string.h>

/** Set this to 0 in the rare case of wanting to call an extra function to
 * generate the IP checksum (in contrast to calculating it on-the-fly). */
#ifndef LWIP_INLINE_IP_CHKSUM
#define LWIP_INLINE_IP_CHKSUM   1
#endif
#if LWIP_INLINE_IP_CHKSUM && CHECKSUM_GEN_IP
#define CHECKSUM_GEN_IP_INLINE  1
#else
#define CHECKSUM_GEN_IP_INLINE  0
#endif



/**
 * The interface that provided the packet for the current callback
 * invocation.
 */
struct netif *current_netif;


/**
 * Header of the input packet currently being processed.
 */
const struct ip_hdr *current_header;


/** Source IP address of current_header */
ip_addr_t current_iphdr_src;


/** Destination IP address of current_header */
ip_addr_t current_iphdr_dest;



/** The IP header ID of the next outgoing IP packet */
static u16_t ip_id;




/**
 * Finds the appropriate network interface for a given IP address. It
 * searches the list of network interfaces linearly. A match is found
 * if the masked IP address of the network interface equals the masked
 * IP address given to the function.
 *
 * @param dest the destination IP address for which to find the route
 * @return the netif on which to send to reach dest
 */
struct netif * ip_route(ip_addr_t *dest)
{
    struct netif *netif;
    
    /* Per default questa funzione non è stata definita.. da implementare
        Non so bene quali benefici possa apportare, forse è solo questione di 
            efficienza! (ps:come al solito!!) */
#ifdef LWIP_HOOK_IP4_ROUTE
    netif = LWIP_HOOK_IP4_ROUTE(dest);
    if (netif != NULL) {
        return netif;
    }
#endif
    
    /* iterate through netifs */
    for (netif = netif_list; netif != NULL; netif = netif->next) {
//        printf("Interfaccia: %s\n", netif->name);
        /* network mask matches? */
        if (netif_is_up(netif)) {
            if (ip_addr_netcmp(dest, &(netif->ip_addr), &(netif->netmask))) {
                /* return netif on which to forward IP packet */
                
//               printf("Il pacchetto viene mandato sulla seguente interfaccia: %s\n", netif->name);
                return netif;
            }
        }
    }
    if ((netif_default == NULL) || (!netif_is_up(netif_default))) {
        LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip_route: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                                                        ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
        IP_STATS_INC(ip.rterr);
        snmp_inc_ipoutnoroutes();
        return NULL;
    }
    
    /* no matching netif found, use default netif */
//    printf("Il pacchetto viene mandato sull'interfaccia di default: %s\n", netif_default->name);
    return netif_default;
}

/**
 * This function is called by the network interface device driver when
 * an IP packet is received. The function does the basic checks of the
 * IP header such as packet size being at least larger than the header
 * size etc. If the packet was not destined for us, the packet is
 * forwarded (using ip_forward). The IP checksum is always checked.
 *
 * Finally, the packet is sent to the upper layer protocol input function.
 *
 * @param p the received IP packet (p->payload points to IP header)
 * @param inp the netif on which this packet was received
 * @return ERR_OK if the packet was processed (could return ERR_* if it wasn't
 *         processed, but currently always returns ERR_OK)
 */
err_t ip_input(struct pbuf *p, struct netif *inp)
{
    struct in_addr address;
    
    struct ip_hdr *iphdr;
    struct netif *netif;
    u16_t iphdr_hlen;
    u16_t iphdr_len;
    ip_addr_t address3;
    
  /* LO COMMENTO perchè continua a darmi errore */
/*
#if IP_ACCEPT_LINK_LAYER_ADDRESSING
    int check_ip_src=1;
#endif */  /* IP_ACCEPT_LINK_LAYER_ADDRESSING */
    
    
    IP_STATS_INC(ip.recv);
    snmp_inc_ipinreceives();
    
    
    /* identify the IP header */
    iphdr = (struct ip_hdr *)p->payload;
    if (IPH_V(iphdr) != 4) {
        LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_WARNING, ("IP packet dropped due to bad version number %"U16_F"\n", IPH_V(iphdr)));
        ip_debug_print(p);
        pbuf_free(p);
        IP_STATS_INC(ip.err);
        IP_STATS_INC(ip.drop);
        snmp_inc_ipinhdrerrors();
        return ERR_OK;
    }
    
    
#ifdef LWIP_HOOK_IP4_INPUT
    if (LWIP_HOOK_IP4_INPUT(p, inp)) {
        /* the packet has been eaten */
        return ERR_OK;
    }
#endif
    
    
    /* obtain IP header length in number of 32-bit words */
    iphdr_hlen = IPH_HL(iphdr);
    /* calculate IP header length in bytes */
    iphdr_hlen *= 4;
    /* obtain ip length in bytes */
    iphdr_len = ntohs(IPH_LEN(iphdr)); 
    
    
    /* header length exceeds first pbuf length, or ip length exceeds total pbuf length? */
    if ((iphdr_hlen > p->len) || (iphdr_len > p->tot_len)) {
        if (iphdr_hlen > p->len) {
            LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                        ("IP header (len %"U16_F") does not fit in first pbuf (len %"U16_F"), IP packet dropped.\n",
                         iphdr_hlen, p->len));
        }
        if (iphdr_len > p->tot_len) {
            LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                        ("IP (len %"U16_F") is longer than pbuf (len %"U16_F"), IP packet dropped.\n",
                         iphdr_len, p->tot_len));
        }
        /* free (drop) packet pbufs */
        pbuf_free(p);
        IP_STATS_INC(ip.lenerr);
        IP_STATS_INC(ip.drop);
        snmp_inc_ipindiscards();
        return ERR_OK;
    }
    
    
    /* verify checksum */
#if CHECKSUM_CHECK_IP
    if (inet_chksum(iphdr, iphdr_hlen) != 0) {
        
        LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                    ("Checksum (0x%"X16_F") failed, IP packet dropped.\n", inet_chksum(iphdr, iphdr_hlen)));
        ip_debug_print(p);
        pbuf_free(p);
        IP_STATS_INC(ip.chkerr);
        IP_STATS_INC(ip.drop);
        snmp_inc_ipinhdrerrors();
        return ERR_OK;
    }
#endif
    
    
    /* Trim pbuf. This should have been done at the netif layer,
     * but we'll do it anyway just to be sure that its done. */
    pbuf_realloc(p, iphdr_len);
    
    
    
    /* copy IP addresses to aligned ip_addr_t */
    ip_addr_copy(current_iphdr_dest, iphdr->dest);
    ip_addr_copy(current_iphdr_src, iphdr->src);
    /*
    printf("Pacchetto IP arrivato!\n");
	
    address.s_addr=current_iphdr_src.addr;
	printf("Source Address: %s\n", inet_ntoa(address));
    
    address.s_addr=current_iphdr_dest.addr;
	printf("Destinarion Address: %s\n", inet_ntoa(address));
    */
    
    /* IL PROBLEMA NON è QUELLO DI ASSOCIARE LA GIUSTA INTERFACCIA DI INGRESSO (VISTO CHE SO DA DOVE IL PACCHETTO ARRIVA)
        MA è QUELLO DI SELEZIONARE QUALI PACCHETTI TENERE E QUALI SCARTARE PERCHè NON MI INTERESSANO.
     
        Qui era presente del codice che è poi stato cancellato che permetteva di selezionare
        quali pacchetti entranti andavano elaborati. Originariamente la scelta era semplicemente 
        basata sull'indirizzo di destinazione, ciclando tra tutte le interfacce e andando a vedere se l'indirizzo di 
        destinazione era uno di quelli associato ad un'interfaccia.
    
        Adesso devo definire delle regole un po' più "flessibili", magari basate sulla stessa funzione usata nella routing
        table, che confronta indirizzo sorgente e destinazione con una rete ed una netmask. 
     
        TODO: In una fase futura sarebbe bello
        che queste regole venissero inserite all'interno di un file xml in modo da dare la massima flssibilità
        e la possibilità di cambiare le impostazioni senza dover ricompilare tutt il codice.
     
        è molto probabile che il problema del ritorno (© Andrea) sia presente solo se si utilizza il codice con
        le librerie libpcap. In frog, poichè arrivano solo i pacchetti destinati a me, non dovrei avere questo problema.
     
        IL PROBLEMA DEL RITORNO & libpcap = quando genero un pacchetto con lpcap e questo esce dalla scheda ethernet,
        lo trovo in input nella callback chiamata quando arriva un pacchetto. Poiche sto implementando un man in the middle
        se utilizzassi la sua versione più pura, ossia quella in cui l'indirizzo sorgente del secondo spezzone della connessione
        TCP è uguale all'indirizzo sorgente del primo spezzone della connessione TCP, dovrei distinguire questo nuova connessione
        che andrebbe filtrata, caratterizzata da tutti i parametri uguali a quella che è gia presente sull'altro ramo, se non per
        la porta sorgente, generata dal mio stack che solo in un caso particolarmente sfortunato potrebbe essere uguale a
        quella sorgente del primo ramo della connessione.
     
        propongo a questo punto due soluzioni:
            -> non utilizzare nel secondo spezzone della connessione TCP l'indirizzo sorgente dell'host che origina tutto,
                ma usare un mio inidirizzo, quello associato alla mia interfaccia ed implementare quindi un proxy non più molto
                trasparente anzi mascherato da NAT. In questo modo potrei mettere come filtro quello di tutti i pacchetti che hanno
                indirizzo sorgente uguale a quello della mia interfaccia. Tra l'altro questo non permetterebbe alcun tipo di connessione
                diretta esplicitamente al mio stack.
            
            --> seconda ipotesi: tralasciando la possibilità remota che il mio stack scelga come porta sorgente per iniziare la
                nuova connessione la stessa usata dall'host per iniziare la connessone globale, potrei mettere come filtro, quello
                di impedire la creazione di una nuova pcb e quindi la non possibilità di generare risposta e droppare i pacchetti
                che hanno tutti i parametri se non la porta sorgente uguali a quelli di una pcb già presente.
                Se da un lato risolvo il problema del ritorno, introduco il problema di non poter permettere all'host di iniziare
                connessioni multiple verso la stessa destinazione, in quanto queste sarebbero tutte caratterizzate dalla sola
                porta sorgente diversa e quindi sarebbero tutte filtrate e solo una alla volta sarebbe in grado di sopravvivere!!
     
            Una soluzione VERAMENTE GLOBALE sarebbe quella di inserire all'interno della pcb l'informazione sul mac address sorgente
            e destinazione. Anche se questo richiederebbe di cambiare notevolmente parte dell'architettura dello stack, sarebbe una soluzione
            che non presenta drawbacks!!
     
        Come prima soluzione adotto la prima ipotesi!!
     
     */
    
    netif = inp;
    
    ip_addr_copy(address3, netif->ip_addr);
    
    if (ip_addr_cmp(&current_iphdr_src, &address3)){
        /* Il pacchetto va droppato perchè viola il funzionamento del man in the middle! */
        /* printf("ip.c | packet dropped\n"); */
        return ERR_OK;
    }
    
    

        /* send to upper layers */
        LWIP_DEBUGF(IP_DEBUG, ("ip_input: \n"));
        ip_debug_print(p);
        LWIP_DEBUGF(IP_DEBUG, ("ip_input: p->len %"U16_F" p->tot_len %"U16_F"\n", p->len, p->tot_len));
        
        current_netif = inp;
        current_header = iphdr;
        
#if LWIP_RAW
        /* raw input did not eat the packet? */
        if (raw_input(p, inp) == 0)
#endif /* LWIP_RAW */
        {
            switch (IPH_PROTO(iphdr)) {
                    
#if LWIP_UDP
                case IP_PROTO_UDP:
                    
#if LWIP_UDPLITE
                case IP_PROTO_UDPLITE:
#endif /* LWIP_UDPLITE */
                    snmp_inc_ipindelivers();
                    udp_input(p, inp);
                    break;
#endif /* LWIP_UDP */
                    
                    
#if LWIP_TCP
                case IP_PROTO_TCP:
                    snmp_inc_ipindelivers();
                    /*QUESTO E' INTERESSANTE!*/
                    /*printf("salgo a TCP\n");*/
		    tcp_input(p, inp);
                    break;
#endif /* LWIP_TCP */
                    
                    
#if LWIP_ICMP
                case IP_PROTO_ICMP:
                    snmp_inc_ipindelivers();
                    icmp_input(p, inp);
                    break;
#endif /* LWIP_ICMP */
                    
                    
#if LWIP_IGMP
                case IP_PROTO_IGMP:
                    igmp_input(p, inp, &current_iphdr_dest);
                    break;
#endif /* LWIP_IGMP */
                    
                    
                default:
#if LWIP_ICMP
                    /* send ICMP destination protocol unreachable unless is was a broadcast */
                    if (!ip_addr_isbroadcast(&current_iphdr_dest, inp) &&
                        !ip_addr_ismulticast(&current_iphdr_dest)) {
                        p->payload = iphdr;
                        icmp_dest_unreach(p, ICMP_DUR_PROTO);
                    }
#endif /* LWIP_ICMP */
                    
                    pbuf_free(p);
                    
                    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("Unsupported transport protocol %"U16_F"\n", IPH_PROTO(iphdr)));
                    
                    IP_STATS_INC(ip.proterr);
                    IP_STATS_INC(ip.drop);
                    snmp_inc_ipinunknownprotos();
            }
        }
        
        current_netif = NULL;
        current_header = NULL;
        ip_addr_set_any(&current_iphdr_src);
        ip_addr_set_any(&current_iphdr_dest);
        
        return ERR_OK;
    }


    /**
     * Sends an IP packet on a network interface. This function constructs
     * the IP header and calculates the IP header checksum. If the source
     * IP address is NULL, the IP address of the outgoing network
     * interface is filled in as source address.
     * If the destination IP address is IP_HDRINCL, p is assumed to already
     * include an IP header and p->payload points to it instead of the data.
     *
     * @param p the packet to send (p->payload points to the data, e.g. next
     protocol header; if dest == IP_HDRINCL, p already includes an IP
     header and p->payload points to that IP header)
     * @param src the source IP address to send from (if src == IP_ADDR_ANY, the
     *         IP  address of the netif used to send is used as source address)
     * @param dest the destination IP address to send the packet to
     * @param ttl the TTL value to be set in the IP header
     * @param tos the TOS value to be set in the IP header
     * @param proto the PROTOCOL to be set in the IP header
     * @param netif the netif on which to send this packet
     * @return ERR_OK if the packet was sent OK
     *         ERR_BUF if p doesn't have enough space for IP/LINK headers
     *         returns errors returned by netif->output
     *
     * @note ip_id: RFC791 "some host may be able to simply use
     *  unique identifiers independent of destination"
     */
    err_t
    ip_output_if(struct pbuf *p, ip_addr_t *src, ip_addr_t *dest,
                 u8_t ttl, u8_t tos,
                 u8_t proto, struct netif *netif)
    {
#if IP_OPTIONS_SEND
        return ip_output_if_opt(p, src, dest, ttl, tos, proto, netif, NULL, 0);
    }
    
    /**
     * Same as ip_output_if() but with the possibility to include IP options:
     *
     * @ param ip_options pointer to the IP options, copied into the IP header
     * @ param optlen length of ip_options
     */
    err_t ip_output_if_opt(struct pbuf *p, ip_addr_t *src, ip_addr_t *dest,
                           u8_t ttl, u8_t tos, u8_t proto, struct netif *netif, void *ip_options,
                           u16_t optlen)
    {
#endif /* IP_OPTIONS_SEND */
        struct ip_hdr *iphdr;
        ip_addr_t dest_addr;
#if CHECKSUM_GEN_IP_INLINE
        u32_t chk_sum = 0;
#endif /* CHECKSUM_GEN_IP_INLINE */
        
        /* pbufs passed to IP must have a ref-count of 1 as their payload pointer
         gets altered as the packet is passed down the stack */
        LWIP_ASSERT("p->ref == 1", p->ref == 1);
        
        snmp_inc_ipoutrequests();

            /*printf("ip_output | src:%s dst:%s\n", ipaddr_ntoa(src), ipaddr_ntoa(dest));
    */
        /* Should the IP header be generated or is it already included in p? */
        if (dest != IP_HDRINCL) {
            u16_t ip_hlen = IP_HLEN;
#if IP_OPTIONS_SEND
            u16_t optlen_aligned = 0;
            if (optlen != 0) {
#if CHECKSUM_GEN_IP_INLINE
                int i;
#endif /* CHECKSUM_GEN_IP_INLINE */
                /* round up to a multiple of 4 */
                optlen_aligned = ((optlen + 3) & ~3);
                ip_hlen += optlen_aligned;
                /* First write in the IP options */
                if (pbuf_header(p, optlen_aligned)) {
                    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip_output_if_opt: not enough room for IP options in pbuf\n"));
                    IP_STATS_INC(ip.err);
                    snmp_inc_ipoutdiscards();
                    return ERR_BUF;
                }
                MEMCPY(p->payload, ip_options, optlen);
                if (optlen < optlen_aligned) {
                    /* zero the remaining bytes */
                    memset(((char*)p->payload) + optlen, 0, optlen_aligned - optlen);
                }
#if CHECKSUM_GEN_IP_INLINE
                for (i = 0; i < optlen_aligned/2; i++) {
                    chk_sum += ((u16_t*)p->payload)[i];
                }
#endif /* CHECKSUM_GEN_IP_INLINE */
            }
#endif /* IP_OPTIONS_SEND */
            /* generate IP header */
            if (pbuf_header(p, IP_HLEN)) {
                LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip_output: not enough room for IP header in pbuf\n"));
                
                IP_STATS_INC(ip.err);
                snmp_inc_ipoutdiscards();
                return ERR_BUF;
            }
            
            iphdr = (struct ip_hdr *)p->payload;
            LWIP_ASSERT("check that first pbuf can hold struct ip_hdr",
                        (p->len >= sizeof(struct ip_hdr)));
            
            IPH_TTL_SET(iphdr, ttl);
            IPH_PROTO_SET(iphdr, proto);
#if CHECKSUM_GEN_IP_INLINE
            chk_sum += LWIP_MAKE_U16(proto, ttl);
#endif /* CHECKSUM_GEN_IP_INLINE */
            
            /* dest cannot be NULL here */
            ip_addr_copy(iphdr->dest, *dest);
#if CHECKSUM_GEN_IP_INLINE
            chk_sum += ip4_addr_get_u32(&iphdr->dest) & 0xFFFF;
            chk_sum += ip4_addr_get_u32(&iphdr->dest) >> 16;
#endif /* CHECKSUM_GEN_IP_INLINE */
            
            IPH_VHL_SET(iphdr, 4, ip_hlen / 4);
            IPH_TOS_SET(iphdr, tos);
#if CHECKSUM_GEN_IP_INLINE
            chk_sum += LWIP_MAKE_U16(tos, iphdr->_v_hl);
#endif /* CHECKSUM_GEN_IP_INLINE */
            IPH_LEN_SET(iphdr, htons(p->tot_len));
#if CHECKSUM_GEN_IP_INLINE
            chk_sum += iphdr->_len;
#endif /* CHECKSUM_GEN_IP_INLINE */
            IPH_OFFSET_SET(iphdr, 0);
            IPH_ID_SET(iphdr, htons(ip_id));
#if CHECKSUM_GEN_IP_INLINE
            chk_sum += iphdr->_id;
#endif /* CHECKSUM_GEN_IP_INLINE */
            ++ip_id;
            
            if (ip_addr_isany(src)) {
                ip_addr_copy(iphdr->src, netif->ip_addr);
            } else {
                /* src cannot be NULL here */
                ip_addr_copy(iphdr->src, *src);
            }
            
#if CHECKSUM_GEN_IP_INLINE
            chk_sum += ip4_addr_get_u32(&iphdr->src) & 0xFFFF;
            chk_sum += ip4_addr_get_u32(&iphdr->src) >> 16;
            chk_sum = (chk_sum >> 16) + (chk_sum & 0xFFFF);
            chk_sum = (chk_sum >> 16) + chk_sum;
            chk_sum = ~chk_sum;
            iphdr->_chksum = chk_sum; /* network order */
#else /* CHECKSUM_GEN_IP_INLINE */
            IPH_CHKSUM_SET(iphdr, 0);
#if CHECKSUM_GEN_IP
            IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, ip_hlen));
#endif
#endif /* CHECKSUM_GEN_IP_INLINE */
        } else {
            /* IP header already included in p */
            iphdr = (struct ip_hdr *)p->payload;
            ip_addr_copy(dest_addr, iphdr->dest);
            dest = &dest_addr;
        }
        
        IP_STATS_INC(ip.xmit);
        
        LWIP_DEBUGF(IP_DEBUG, ("ip_output_if: %c%c%"U16_F"\n", netif->name[0], netif->name[1], netif->num));
        ip_debug_print(p);
        
#if ENABLE_LOOPBACK
        if (ip_addr_cmp(dest, &netif->ip_addr)) {
            /* Packet to self, enqueue it for loopback */
            LWIP_DEBUGF(IP_DEBUG, ("netif_loop_output()"));
            return netif_loop_output(netif, p, dest);
        }
#if LWIP_IGMP
        if ((p->flags & PBUF_FLAG_MCASTLOOP) != 0) {
            netif_loop_output(netif, p, dest);
        }
#endif /* LWIP_IGMP */
#endif /* ENABLE_LOOPBACK */
#if IP_FRAG
        /* don't fragment if interface has mtu set to 0 [loopif] */
        if (netif->mtu && (p->tot_len > netif->mtu)) {
            return ip_frag(p, netif, dest);
        }
#endif /* IP_FRAG */
        
        LWIP_DEBUGF(IP_DEBUG, ("netif->output()"));
        return netif->output(netif, p, dest);
    }
    
    /**
     * Simple interface to ip_output_if. It finds the outgoing network
     * interface and calls upon ip_output_if to do the actual work.
     *
     * @param p the packet to send (p->payload points to the data, e.g. next
     protocol header; if dest == IP_HDRINCL, p already includes an IP
     header and p->payload points to that IP header)
     * @param src the source IP address to send from (if src == IP_ADDR_ANY, the
     *         IP  address of the netif used to send is used as source address)
     * @param dest the destination IP address to send the packet to
     * @param ttl the TTL value to be set in the IP header
     * @param tos the TOS value to be set in the IP header
     * @param proto the PROTOCOL to be set in the IP header
     *
     * @return ERR_RTE if no route is found
     *         see ip_output_if() for more return values
     */
    err_t
    ip_output(struct pbuf *p, ip_addr_t *src, ip_addr_t *dest,
              u8_t ttl, u8_t tos, u8_t proto)
    {
        struct netif *netif;
        
        /* pbufs passed to IP must have a ref-count of 1 as their payload pointer
         gets altered as the packet is passed down the stack */
        LWIP_ASSERT("p->ref == 1", p->ref == 1);
        
        if ((netif = ip_route(dest)) == NULL) {
            LWIP_DEBUGF(IP_DEBUG, ("ip_output: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                                   ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
            IP_STATS_INC(ip.rterr);
            return ERR_RTE;
        }
        
        return ip_output_if(p, src, dest, ttl, tos, proto, netif);
    }
    
#if LWIP_NETIF_HWADDRHINT
    /** Like ip_output, but takes and addr_hint pointer that is passed on to netif->addr_hint
     *  before calling ip_output_if.
     *
     * @param p the packet to send (p->payload points to the data, e.g. next
     protocol header; if dest == IP_HDRINCL, p already includes an IP
     header and p->payload points to that IP header)
     * @param src the source IP address to send from (if src == IP_ADDR_ANY, the
     *         IP  address of the netif used to send is used as source address)
     * @param dest the destination IP address to send the packet to
     * @param ttl the TTL value to be set in the IP header
     * @param tos the TOS value to be set in the IP header
     * @param proto the PROTOCOL to be set in the IP header
     * @param addr_hint address hint pointer set to netif->addr_hint before
     *        calling ip_output_if()
     *
     * @return ERR_RTE if no route is found
     *         see ip_output_if() for more return values
     */
    err_t
    ip_output_hinted(struct pbuf *p, ip_addr_t *src, ip_addr_t *dest,
                     u8_t ttl, u8_t tos, u8_t proto, u8_t *addr_hint)
    {
        struct netif *netif;
        err_t err;
        
        /* pbufs passed to IP must have a ref-count of 1 as their payload pointer
         gets altered as the packet is passed down the stack */
        LWIP_ASSERT("p->ref == 1", p->ref == 1);
        
        if ((netif = ip_route(dest)) == NULL) {
            LWIP_DEBUGF(IP_DEBUG, ("ip_output: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                                   ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
            IP_STATS_INC(ip.rterr);
            return ERR_RTE;
        }
        
        NETIF_SET_HWADDRHINT(netif, addr_hint);
        err = ip_output_if(p, src, dest, ttl, tos, proto, netif);
        NETIF_SET_HWADDRHINT(netif, NULL);
        
        return err;
    }
#endif /* LWIP_NETIF_HWADDRHINT*/
    
    
#if IP_DEBUG
    /* Print an IP header by using LWIP_DEBUGF
     * @param p an IP packet, p->payload pointing to the IP header
     */
    void ip_debug_print(struct pbuf *p)
    {
        struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;
        
        LWIP_DEBUGF(IP_DEBUG, ("IP header:\n"));
        LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
        LWIP_DEBUGF(IP_DEBUG, ("|%2"S16_F" |%2"S16_F" |  0x%02"X16_F" |     %5"U16_F"     | (v, hl, tos, len)\n",
                               IPH_V(iphdr),
                               IPH_HL(iphdr),
                               IPH_TOS(iphdr),
                               ntohs(IPH_LEN(iphdr))));
        LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
        LWIP_DEBUGF(IP_DEBUG, ("|    %5"U16_F"      |%"U16_F"%"U16_F"%"U16_F"|    %4"U16_F"   | (id, flags, offset)\n",
                               ntohs(IPH_ID(iphdr)),
                               ntohs(IPH_OFFSET(iphdr)) >> 15 & 1,
                               ntohs(IPH_OFFSET(iphdr)) >> 14 & 1,
                               ntohs(IPH_OFFSET(iphdr)) >> 13 & 1,
                               ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK));
        LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
        LWIP_DEBUGF(IP_DEBUG, ("|  %3"U16_F"  |  %3"U16_F"  |    0x%04"X16_F"     | (ttl, proto, chksum)\n",
                               IPH_TTL(iphdr),
                               IPH_PROTO(iphdr),
                               ntohs(IPH_CHKSUM(iphdr))));
        LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
        LWIP_DEBUGF(IP_DEBUG, ("|  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  | (src)\n",
                               ip4_addr1_16(&iphdr->src),
                               ip4_addr2_16(&iphdr->src),
                               ip4_addr3_16(&iphdr->src),
                               ip4_addr4_16(&iphdr->src)));
        LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
        LWIP_DEBUGF(IP_DEBUG, ("|  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  | (dest)\n",
                               ip4_addr1_16(&iphdr->dest),
                               ip4_addr2_16(&iphdr->dest),
                               ip4_addr3_16(&iphdr->dest),
                               ip4_addr4_16(&iphdr->dest)));
        LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
    }
#endif /* IP_DEBUG */

/* ping-rat - generates a packet with a generalized Bloom filter as an IP option
 * by Gustavo L. Coutinho <gustavo@gta.ufrj.br>
 * Copyright (C) 2005 Gustavo L. Coutinho
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

 /*--------------------------------------------------------------------------*
  * This program sends an ICMP ECHO packet with a new option included in IP  *
  * header, using raw sockets. This new option carries a generalized Bloom   *
  * filter where routers mark the packet to notify the victim of their       *
  * presence in the attack path.                                             *
  *--------------------------------------------------------------------------*/

#include <sys/socket.h>       /* socket      */
#include <netinet/in.h>       /* sockaddr_in */
#include <netinet/ip.h>       /* ip header   */
#include <netinet/ip_icmp.h>  /* icmp header */
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define OPTION_SIZE 40               /* the size of the option field */
#define N sizeof(struct ip)     + \
		  sizeof(struct icmphdr)+ \
          OPTION_SIZE                /* total size of the packet */

/*----- checksum function -----*/
unsigned short csum (unsigned short *buf, int nwords)
{
	unsigned long sum;
	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
};

int main(int argc, char *argv[])
{
	char *option  = 0;         /* the option field                 */
	int s;                     /* the socket file descriptor       */
	int i;                     /* dummy variable                   */
	struct sockaddr_in sin;	   /* the source socket structure      */
	unsigned src_addr;         /* source address 		       */
	char datagram[N];          /* the whole packet (IP + ICMP)     */
	struct ip       *iph;      /* the IP header structure          */
	struct icmphdr  *icmph;    /* the ICMP header structure        */
	struct protoent *proto;    /* the protocol structure           */
	struct hostent  *dst_host; /* structure for resolving names    */
	struct hostent  *src_host; /* structure for resolving names    */

	/*----- Getting the protocol number for ICMP -----*/
	if (!(proto = getprotobyname("icmp"))){
		fprintf(stderr, "ping-rat: unknown protocol icmp.\n");
		return 1;
	}
	
	/*----- Openining a raw socket -----*/
	if ((s = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0){ 
		if (errno == EPERM)
			fprintf(stderr, "ping-rat: ping-rat must run as root.\n");
		else
			perror("ping-rat: socket");
        return 1;
	}

	/*----- Droping root priviledges -----*/
#ifdef __linux__
	setuid(getuid()); 
#endif

	/*----- Checking arguments -----*/
	if (argc != 3){
		fprintf(stderr,"Usage: %s <src ip> <dst ip>\n", argv[0]);
		return 1;
	}

	/*----- Resolving source hostname -----*/
	if (!(src_host = gethostbyname(argv[1]))){
		fprintf(stderr,"ping-rat: unknown host %s\n",argv[1]);
		return 1;
	}
	/*----- Saving source address -----*/
	memcpy(&src_addr, src_host->h_addr, src_host->h_length);
	
	/*----- Resolving destination hostname -----*/
	if (!(dst_host = gethostbyname(argv[2]))){
		fprintf(stderr,"ping-rat: unknown host %s\n",argv[2]);
		return 1;
	}
	
	/*-----------------------------------------------------------------*
	 * Filling the sockaddr_in structure with family (AF_INET) and	   *
	 * destination addresses	 	                           *
	 *-----------------------------------------------------------------*/
	sin.sin_family = AF_INET;
	sin.sin_port   = 0;
	memcpy(&sin.sin_addr.s_addr, dst_host->h_addr, dst_host->h_length);
	
	/*------------------------------------------------------------*
	 * We are building the whole packet in 'datagram' and the IP  *
	 * header is at the beginning of the 'datagram' buffer        *
	 *------------------------------------------------------------*/
	iph = (struct ip *) datagram; 

	/*---- Filling the packet with zeros -----*/
	memset(datagram, 0, N);
	
	/*----- Building the IP options -----*/
	option = datagram + sizeof(struct ip); /* setting up the option pointer */
	option[0] = 25|0x80; 	               /* setting the option id         */
	option[1] = OPTION_SIZE;               /* the size of the option field  */
	for (i = 2; i < OPTION_SIZE; i++)      /* filling the option with data  */
		option[i] = 0;
	
	/*---- Building the IP Header -----*/
	iph->ip_v   = 4;                  /* IP version                           */
	iph->ip_hl  = 5 + OPTION_SIZE/4;  /* IP header size in 32-bits words      */
	iph->ip_tos = 0;                  /* Type of Service (ToS), not needed    */
	iph->ip_len = sizeof (struct ip)      + \
				  sizeof (struct icmphdr) + \
				  OPTION_SIZE;	      /* total size of the packet in bytes    */
	iph->ip_id  = 0;	              /* this value doesn't matter, kernel    */
	                                  /* sets one automatically               */
	iph->ip_off = 0;                  /* fragment offset, not needed          */
	iph->ip_ttl = 127;                /* Time To Live (TTL)                   */
	iph->ip_p   = 1;                  /* Protocol = ICMP = 1                  */
	iph->ip_sum = 0;                  /* set to 0 before calculating checksum */
	iph->ip_src.s_addr = src_addr;    /* source address			  */
	iph->ip_dst.s_addr = sin.sin_addr.s_addr; /* destination address          */
	
	/*----- Calculate IP checksum -----*/
	iph->ip_sum = csum ((unsigned short *) iph, iph->ip_len >> 1);

	/*----- Building the ICMP Header -----*/
	icmph = (struct icmphdr *)     /* setting up the ICMP pointer          */
			(datagram + sizeof(struct ip) + OPTION_SIZE);
   	icmph->type = 8;              /* ICMP_ECHO requires type 8 and code 0 */
	icmph->code = 0; 
	icmph->checksum = 0;          /* set to 0 before calculating checksum */
	icmph->un.echo.id = 18;       /* any value will do                    */
	icmph->un.echo.sequence = 33; /* any value will do                    */

	/*----- Calculating ICMP checksum (8 = ICMP ECHO header size) -----*/
	icmph->checksum = csum((unsigned short *) icmph, 8 >> 1); 

	/*---- Notifying the kernel that we have our own IP header -----*/
	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, datagram, sizeof(struct ip)) < 0){
		perror("ping-rat: IP header");
		return 1;
	}

	/*----- Sending the datagram -----*/
	if(sendto(s,datagram,iph->ip_len,0,(struct sockaddr *)&sin,sizeof(sin)) < 0)
		perror("ping-rat: error sending datagram");
	else
		fprintf(stdout,"ping-rat: datagram successfully sent.\n");
	
	return 0;
}

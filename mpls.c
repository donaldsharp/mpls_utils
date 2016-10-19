/* Copyright (C) 2016 Cumulus Networks
 *                    Donald Sharp <sharpd@cumulusnetworks.com>
 *
 * This file is part of mpls_util.
 *
 * mpls_util is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * mpls_util is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with mpls_util.  If not, see <http://www.gnu.org/licenses/>
 */
#include <stdio.h>
#include <malloc.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include "mpls.h"
#include "mpls_ping.h"

void
print_binary (char *buff, uint32_t data)
{
  int i;
  int eights = 0;
  unsigned int val, leftover;

  memset(buff, 0, 100);
  val = data;
  for (i=0; i <= 31; i++) {
    if ((i != 0 ) && (i%8 == 0)) {
      buff[i+eights] = '-';
      eights++;
    }
    leftover = val % 2;
    val = val/2;
    if (leftover == 1) {
      buff[i+eights]='1';
    } else {
      buff[i+eights]='0';
    }

  }
}

/*
 * mpls_label_stack
 *
 * Code assumes that label, exp, bos and ttl are valid values checked elsewhere
 *
 * Returns the modified label stack.
 */
struct mpls_label_stack *
mpls_add_label (struct mpls_label_stack *ls, uint32_t label,
		uint8_t exp, uint8_t ttl)
{
  struct mpls_label_stack *nls;

  nls = malloc(sizeof(struct mpls_label_stack));
  if (nls == NULL) {
    return(NULL);
  }

  memset(nls, 0, sizeof(struct mpls_label_stack));

  nls->next  = ls;
  mpls_set_hdr_label(&nls->l, label);
  nls->l.exp   = exp;
  if (ls == NULL) {
    nls->l.bos = 1;
  } else {
    nls->l.bos = 0;
  }

  nls->l.ttl   = ttl;
  return(nls);
}

int
mpls_build_label_stream(struct mpls_label_stack *ls, unsigned char *buff, uint32_t size)
{
  struct mpls_label_stack *iterate;
  unsigned char *stream;
  uint32_t bytes_written = 0;
  uint32_t value;

  stream = buff;
  iterate = ls;
  while ((iterate != NULL) && size > (sizeof(struct mpls_label))) {
    value = *((uint32_t *)&iterate->l);
    value = htonl(value);
    memcpy(stream, &value, sizeof(struct mpls_label));
    bytes_written += sizeof(struct mpls_label);
    stream = buff + bytes_written;
    iterate = iterate->next;
  }
    
  return(bytes_written);
}

int
mpls_build_mac_header(unsigned char *buffer, int length, 
		      unsigned char dest[ETH_ALEN],
		      unsigned char src[ETH_ALEN])
{
  char *eth = buffer;
  uint16_t *proto;

  if (length < ETH_HLEN             ) {
    return(-1);
  }

  printf("eth: %x\n", eth);
  memcpy(eth, dest, ETH_ALEN);
  eth = eth + ETH_ALEN;
  printf("eth: %x\n", eth);
  memcpy(eth, src, ETH_ALEN);
  eth = eth + ETH_ALEN;

  proto = (uint16_t *)eth;
  *proto = ETH_P_MPLS_UC;

  return(ETH_HLEN);
}

/* 
 * mpls_build_ip_header
 *
 * Section 4.3 -
 *
 * The IP address is a routeable address of the sender
 * The IP address is a (randomy choosen)
 *     - v4 - random from 127/8
 *     - v6 - random from 0:0:0:0:0:FFFF:127/104
 * The IP TTL is set to 1
 */
int
mpls_build_ip_header (unsigned char *buffer, int length)
{
  struct iphdr *ip = (struct iphdr *)buffer;
  unsigned int *ra = (unsigned int *)buffer + 20;

  ip->ihl = 6;  // Must have Router Alert option
  ip->version = IPVERSION;
  ip->tos = 0;
  ip->id = htons(44);
  ip->frag_off = 0;
  ip->ttl = 255;
  ip->protocol = 4;
  ip->check = 0;
  ip->saddr = htonl(0x44332211);
  ip->daddr = htonl(0x55443322);

  *ra = htonl(0x94040000);  //Set the Router alert value
  
  return(24);
}

/*
 * mpls_build_udp_header
 *
 * Section 4.3 -
 *
 * The source UDP port is chosen by the sender;
 * The destination UDP port is set to 3503
 */
int mpls_build_udp_header (unsigned char *buffer, int length)
{
  struct udphdr *uhdr = (struct udphdr *)buffer;

  uhdr->source = 5999;
  uhdr->dest   = 3503;
  uhdr->len = sizeof(mpls_ping_packet) + 8;
  uhdr->check = 0;
  return(8);
}

/*
 * mpls_build_udp_packet
 *
 * Section 3 - Packet Format
 */
int mpls_build_udp_data (unsigned char *buffer, int length)
{
  mpls_ping_packet *pdata = (mpls_ping_packet *)buffer;

  pdata->version        = htons(MPLS_PING_VERSION_NUMBER);
  pdata->gflags         = htons(GLOBAL_FLAG_V_NO_FEC_VALIDATION);
  pdata->msgtype        = MPLS_ECHO_REQUEST;
  pdata->replymode      = MPLS_REPLY_PACKET;
  pdata->rcode          = MPLS_NO_RETURN_CODE;
  pdata->rsubcode       = MPLS_NO_RETURN_CODE;
  pdata->sender_handle  = htonl(0xdeadbeef);               // FIX-ME
  pdata->seq_number     = htonl(random());                 // FIX-ME
  pdata->secs_sent      = htonl(random());                 // FIX-ME
  pdata->msecs_sent     = htonl(random());                 // FIX-ME
  pdata->secs_received  = htonl(0);
  pdata->msecs_received = htonl(0);
  
  return(sizeof(mpls_ping_packet));
}

int
mpls_build_packet (unsigned char *buffer, int length, struct mpls_label_stack *ls)
{
  int bytes = 0;
  int total_bytes = 0;
  unsigned char *stream;
  unsigned char dest[6] = { 0xde, 0xad, 0xbe, 0xef, 0x44, 0x69 };
  unsigned char src[6] = { 0x9, 0x8, 0x7, 0x6, 0x5, 0x4 };

  stream = buffer;
  bytes = mpls_build_mac_header(stream, length, dest, src);
  if (bytes <= 0 ) {
    printf("Insufficient space in packet, building mac header\n");
    return(-1);
  }
  total_bytes += bytes;
  length = length - bytes;
  stream = stream + bytes;

  bytes = mpls_build_label_stream(ls, stream, length);
  if (bytes <= 0) {
    printf("Insufficent space in packet, build labels\n");
    return(-1);
  }
  total_bytes += bytes;
  length = length - bytes;
  stream = stream + bytes;

  bytes = mpls_build_ip_header(stream, length);
  if (bytes <= 0) {
    printf("Insufficent space in packet, build ip header\n");
    return(-1);
  }
  total_bytes += bytes;
  length = length - bytes;
  stream = stream + bytes;

  bytes = mpls_build_udp_header(stream, length);
  if (bytes <= 0) {
    printf("Insufficient space in packet to build udp information\n");
  }
  total_bytes += bytes;
  length = length - bytes;
  stream = stream + bytes;

  bytes = mpls_build_udp_data(stream, length);
  return(total_bytes);
}

void
mac_ntoa(unsigned char *ptr)
{
  printf("%02X:%02X:%02X:%02X:%02X:%02X",
	 ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);

}

void
print_hex(unsigned char *ptr)
{
  printf("%02X:%02X:%02X:%02X ",
	 ptr[0], ptr[1], ptr[2], ptr[3]);
}
#define TEST 1

#if defined(TEST)
void main (void)
{
  unsigned char buff[1000];
  unsigned char buff1[1000];
  int length = 1000;
  int i;
  struct mpls_label_stack *ls = NULL;
  FILE *fp;
  unsigned int *b;


  ls = mpls_add_label(ls, 100, 0, 255);
  //ls = mpls_add_label(ls, 0x000fffff, 0, 15);
  //ls = mpls_add_label(ls, 0x000efefe, 0, 1);
  //  length = mpls_build_label_stream(ls, buff, length);

  memset(buff, 0, 1000);
  mpls_build_packet(buff, length, ls);
  b = (unsigned int *)buff;
  for (i=0; i < 200/sizeof(int)   ; i++ ) {
    printf("%x ", b);
    print_hex(b);
    print_binary(buff1, *b);
    printf("%s\n", buff1);
    b++;
  }

  mac_ntoa(buff);

}
#endif
  

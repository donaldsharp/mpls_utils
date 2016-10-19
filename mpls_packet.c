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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <netinet/ip6.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include "mpls_util.h"
#include "mpls_network.h"
#include "mpls_label.h"
#include "mpls_ping.h"
#include "mpls_packet.h"

void
mpls_packet_clean (packet_peeker *packet)
{
  packet->ls = mpls_label_free_stream(packet->ls);
  if (packet->ilm) {
    free(packet->ilm);
  }
  memset(packet, 0, sizeof(packet_peeker));
}

void
mpls_packet_get_src_addr (packet_peeker *packet, address *addr)
{
  struct iphdr *iphdr;
  struct ipv6hdr *ip6hdr;

  if (packet->iphdr) {
    addr->af = AF_INET;
    iphdr = (struct iphdr *)packet->iphdr;
    addr->u.v4.s_addr = iphdr->saddr;
  } else {
    addr->af = AF_INET6;
    ip6hdr = (struct ipv6hdr *)packet->ip6hdr;
    addr->u.v6 = ip6hdr->saddr;
  }
}

void
mpls_packet_get_time_sent (packet_peeker *packet, struct timeval *time)
{
  ntp_time_t ntp_sent;

  mpls_ping_packet *mpp = (mpls_ping_packet *)packet->udpdata;
  ntp_sent.seconds  = ntohl(mpp->secs_sent);
  ntp_sent.fraction = ntohl(mpp->msecs_sent);
  mpls_util_ntp_to_unix_time(&ntp_sent, time);

  return;
}

/*
 * Is this a mpls packet
 */
int
mpls_packet_is_mpls (packet_peeker *packet)
{
  uint16_t proto = ntohs(*(uint16_t *)(packet->ethhdr + 12));

  if (proto == ETH_P_MPLS_UC) {
    return 1;
  }

  return 0;
}

/*
 * mpls_packet_parse_tlv
 *
 * Attempts to parse the tlv's associated with a packet
 * If it can it will create pointers to the structures in
 * the tlv for the tlv's we understand.
 *
 * If we don't understand the tlv return a TLV_NOT_UNDERSTOOD
 * return code for those under MPLS_TLV_MUST_UNDERSTAND
 *
 */
uint32_t
mpls_packet_parse_tlv (packet_peeker *packet)
{
  mpls_ping_tlv *tlv = (mpls_ping_tlv *)packet->tlvdata;
  uint32_t tlv_total = packet->length - (packet->tlvdata - packet->stream);
  uint32_t tlv_length = 0;

  while (tlv) {
    switch(ntohs(tlv->type)) {
    case MPLS_TLV_TYPE_FEC_STACK:
      packet->tlv_fec_stack = (mpls_ping_tlv *)&tlv->data[0];
      break;
    case MPLS_TLV_TYPE_DOWNSTREAM_MAPPING:
      packet->tlv_downstream_mapping = (mpls_downstream_mapping *)(tlv);
      break;
    default:
      if (tlv->type < MPLS_TLV_MUST_UNDERSTAND) {
	return MPLS_TLV_NOT_UNDERSTOOD;
      }
      break;
    }

    tlv_length += sizeof(mpls_ping_tlv) + ntohs(tlv->length);
    if (tlv_length == tlv_total) {
      return MPLS_NO_RETURN_CODE;
    }
    if (tlv_length > tlv_total) {
      return MPLS_MALFORMED_ECHO_REQUEST;
    }

    tlv = (mpls_ping_tlv *)(packet->tlvdata + tlv_length);
  }

  return MPLS_MALFORMED_ECHO_REQUEST;
}

/*
 * mpls_packet_parse_structures
 *
 * Given a packet from the wire setup internal
 * pointers to allow for easier reading later
 *
 * Returns false if packet size specified is
 * incongruent with data structures of the
 * packet.
 */
int
mpls_packet_parse_structures (packet_peeker *packet)
{
  uint32_t length;

  struct iphdr *ip;  // Version information is in the same place!
  mpls_ping_packet *mpp;

  packet->ethhdr = packet->stream;
  if (mpls_packet_is_mpls(packet)) {
    packet->lhdr  = packet->ethhdr + ETH_HLEN;
    packet->iphdr = mpls_label_read_stream(packet->lhdr, &packet->ls);
    if (packet->iphdr == NULL) {
      return 0;
    }
  } else {
    packet->lhdr  = NULL;
    packet->iphdr = packet->ethhdr + ETH_HLEN;
  }

  /*
   * The version field is the same for v4/v6
   * Use it to determine what type of packet we have
   */
  ip = (struct iphdr *)packet->iphdr;
  if (ip->version == 6) {
    struct ipv6hdr *ip6 = (struct ipv6hdr *)packet->iphdr;
    packet->ip6hdr = packet->iphdr;
    packet->iphdr = NULL;
    
    if (ip6->nexthdr == 0) {                  // Has RA embedded
      struct ipv6_opt_hdr *opt = (struct ipv6_opt_hdr *)(packet->ip6hdr + sizeof(struct ipv6hdr));
      if (opt->nexthdr != IPPROTO_UDP) {
	return 0;
      }
      packet->udphdr = packet->ip6hdr + MPLS_PACKET_IP6_LEN_RA_BYTES;
    } else if (ip6->nexthdr == IPPROTO_UDP) {
      packet->udphdr = packet->ip6hdr + MPLS_PACKET_IP6_LEN_BYTES;
    } else {
      return 0;                              // Isn't a udp packet
    }
  } else if (ip->version == 4) {
    packet->ip6hdr = NULL;
    if (ip->protocol != IPPROTO_UDP) {
      return 0;
    }
    if (ip->ihl == MPLS_PACKET_IP_LEN_RA_WORDS) {
      packet->udphdr = packet->iphdr + MPLS_PACKET_IP_LEN_RA_BYTES;
    } else {
      packet->udphdr = packet->iphdr + MPLS_PACKET_IP_LEN_BYTES;
    }
  } else {  // Not a v4 or v6 packet
    return 0;
  }
  
  packet->udpdata = packet->udphdr + 8;
  mpp = (mpls_ping_packet *)packet->udpdata;

  packet->replymode = mpp->replymode;

  length = packet->udpdata - packet->stream + sizeof(mpls_ping_packet);

  packet->tlvdata = packet->stream + length;

  if (length > packet->length) {
    return 0;
  }
  return 1;
}

/*
 * mpls_packet_retrieve_local_address
 *
 * given a destination address
 * retreive the same address family as the daddr
 * local address
 */
int
mpls_packet_retrieve_local_address (address *dest, address *laddr, uint32_t *use_mpls)
{
  FILE *fp;
  char buffer[1000];
  char buf1[100];

  sprintf(buffer, "ip %s route get %s > /tmp/lafull.tmp",
          (dest->af == AF_INET) ? "" : "-6",
          inet_ntop(dest->af, (void *)&dest->u.v32, buf1, 100));

  system(buffer);

  sprintf(buffer, "grep src /tmp/lafull.tmp | sed -r s/.*src// | cut -d \" \" -f 2 > /tmp/lsaddr.tmp");
  system(buffer);

  sprintf(buffer, "grep src /tmp/lafull.tmp | cut -d \" \" -f 4 > /tmp/lsmpls.tmp");
  system(buffer);

  unlink("/tmp/lafull.tmp");

  fp = fopen("/tmp/lsmpls.tmp", "r+");
  fscanf(fp, "%s", buffer);

  *use_mpls = (strcmp(buffer, "mpls") == 0);
  fclose(fp);
  unlink("/tmp/lsmpls.tmp");

  fp = fopen("/tmp/lsaddr.tmp", "r+");
  fscanf(fp, "%s", buffer);

  fclose(fp);
  unlink("/tmp/lsaddr.tmp");
  if (!mpls_network_addr_retrieve(buffer, laddr))
    return 0;
  else
    return 1;
}

void
mpls_packet_build_mac_header(unsigned char *buffer,
			     unsigned char dest[ETH_ALEN],
			     unsigned char src[ETH_ALEN],
			     uint16_t protocol)
{
  unsigned char *eth = buffer;
  uint16_t *proto;

  memcpy(eth, dest, ETH_ALEN);
  eth = eth + ETH_ALEN;
  memcpy(eth, src, ETH_ALEN);
  eth = eth + ETH_ALEN;

  proto = (uint16_t *)eth;
  *proto = htons(protocol);

  return;
}

u_int32_t
checksum(unsigned char *buf, unsigned nbytes, u_int32_t sum)
{
  uint i;

  /* Checksum all the pairs of bytes first... */
  for (i = 0; i < (nbytes & ~1U); i += 2) {
    sum += (u_int16_t)ntohs(*((u_int16_t *)(buf + i)));
    if (sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  /*
   * If there's a single byte left over, checksum it, too.
   * Network byte order is big-endian, so the remaining byte is
   * the high byte.
   */
  if (i < nbytes) {
    sum += buf[i] << 8;
    if (sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  return (sum);
}

u_int32_t
wrapsum(u_int32_t sum)
{
  sum = ~sum & 0xFFFF;
  return (htons(sum));
}

/*
 * mpls_packet_build_udp_header_cksum
 *
 * Build the udp header checksum
 */
void
mpls_packet_build_udp_header_cksum (unsigned char *stream_udphdr,
				    unsigned char *stream_iphdr,
				    unsigned char *data, uint32_t len)
{
  struct iphdr *ip = (struct iphdr *)stream_iphdr;
  struct ipv6hdr *ip6 = (struct ipv6hdr *)stream_iphdr;
  struct udphdr *udp = (struct udphdr *)stream_udphdr;
  int af = (ip->version == IPVERSION) ? AF_INET : AF_INET6;
  uint32_t add_size = 0;
  unsigned char *srcptr;

  udp->check = 0;

  if (af == AF_INET) {
    add_size = sizeof(ip->saddr);
    srcptr = (unsigned char *)&ip->saddr;
  } else {
    srcptr = (unsigned char *)&ip6->saddr;
    add_size = sizeof(ip6->saddr);
  }

  udp->check = wrapsum(checksum(stream_udphdr, sizeof(struct udphdr),
		       checksum(data, len, checksum(srcptr, add_size * 2,
						    IPPROTO_UDP + (uint32_t)ntohs(udp->len)))));
}

/*
 * mpls_packet_build_udp_header
 *
 * Section 4.3 -
 *
 * The source UDP port is chosen by the sender;
 * The destination UDP port is set to 3503
 */
void
mpls_packet_build_udp_header (unsigned char *buffer, int length,
			      uint16_t dport, uint16_t sport)
{
  struct udphdr *uhdr = (struct udphdr *)buffer;

  uhdr->source = htons(sport);
  uhdr->dest   = htons(dport);
  uhdr->len = htons(length);
  uhdr->check = 0;                // This is built after we build ip header

  return;
}


static unsigned short
calc_csum (unsigned short *buffer, int words)
{
  unsigned long sum;

  for (sum = 0; words > 0; words--) {
    sum += *buffer++;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  return (unsigned short)(~sum);
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
void
mpls_packet_build_ip_header (unsigned char *buffer, address *saddr,
			     address *daddr, int length, int includera)
{
  struct iphdr *ip = (struct iphdr *)buffer;
  unsigned int *ra = (unsigned int *)buffer + MPLS_PACKET_IP_LEN_WORDS;
  uint32_t iphdr_size;

  ip->ihl = includera ?
    MPLS_PACKET_IP_LEN_RA_WORDS : MPLS_PACKET_IP_LEN_WORDS;
  iphdr_size = (includera) ? MPLS_PACKET_IP_LEN_RA_BYTES : MPLS_PACKET_IP_LEN_BYTES;
  ip->version = IPVERSION;
  ip->tos = 0;
  ip->id = 0;
  ip->frag_off = 0;
  ip->ttl = 255;
  ip->protocol = IPPROTO_UDP;
  ip->check = 0;
  ip->saddr = saddr->u.v4.s_addr;
  ip->daddr = daddr->u.v4.s_addr;
  ip->tot_len = htons(length + iphdr_size);

  if (includera) {
    *ra = htonl(0x94040000);  //Set the Router alert value
  }

  ip->check = calc_csum((unsigned short *)buffer, ip->ihl * 4 /2);
}

void
mpls_packet_build_ip6_header (unsigned char *buffer, address *saddr,
			      address *daddr, int length, int includera)
{
  struct ipv6hdr *ip6 = (struct ipv6hdr *)buffer;
  struct ipv6_opt_hdr *opt = (struct ipv6_opt_hdr *)(buffer + sizeof(struct ipv6hdr));
  unsigned char *ra = (unsigned char *)opt + 2;

  ip6->version  = 6;
  ip6->priority = 0;
  
  memset(ip6->flow_lbl, 0, 3);

  ip6->payload_len = htons(length + sizeof(struct ipv6hdr));
  ip6->hop_limit = 255;
  ip6->nexthdr = includera ? 0 : IPPROTO_UDP;    // HOP by HOP value
  ip6->daddr = daddr->u.v6;
  ip6->saddr = saddr->u.v6;

  if (includera) {
    opt->nexthdr = IPPROTO_UDP;
    opt->hdrlen  = 0;
    *ra = 0x05;
    ra++;
    *ra = 0x02;
    ra++;
    *ra = 00;
    ra++;
    *ra = 45;
    ra++;
  }
  return;
}

/*
 * mpls_packet_build_tlv_prefix
 *
 * Build the target FEC stack
 *
 */
static uint32_t
mpls_packet_build_tlv_prefix(mpls_ping_tlv *ptlv, route *route)
{
  mpls_ipv4_prefix *mip4p;
  mpls_ipv6_prefix *mip6p;
  uint32_t length = sizeof(mpls_ping_tlv);

  ptlv->type = htons(MPLS_TLV_TYPE_FEC_STACK);
  if (route->addr.af == AF_INET) {
    ptlv->length              = htons(12);
    mip4p                     = (mpls_ipv4_prefix *)&ptlv->data[0];
    mip4p->tlv.type           = htons(MPLS_TFS_LDP_V4_PREFIX_ST);
    mip4p->tlv.length         = htons(MPLS_TFS_LDP_V4_PREFIX_L);
    mip4p->ipv4_prefix.s_addr = route->addr.u.v32;
    mip4p->plength            = route->prefix;
    length += sizeof(mpls_ipv4_prefix);
  } else {
    ptlv->length              = htons(24);
    mip6p                     = (mpls_ipv6_prefix *)&ptlv->data[0];
    mip6p->tlv.type           = htons(MPLS_TFS_LDP_V6_PREFIX_ST);
    mip6p->tlv.length         = htons(MPLS_TFS_LDP_V6_PREFIX_L);
    memcpy(&mip6p->ipv6_prefix, &route->addr.u.v6, sizeof(struct in6_addr));
    mip6p->plength            = route->prefix;
    length += sizeof(mpls_ipv6_prefix);
  }

  return(length);
}

static uint32_t
mpls_packet_build_tlv_downstream (mpls_downstream_mapping *mdm, uint32_t label,
				  address *nh_ip, uint32_t mtu)
{
  uint32_t length = sizeof(mpls_downstream_mapping);
  mpls_downstream_ipv4_address *v4_addr;
  mpls_downstream_ipv6_address *v6_addr;
  mpls_downstream_multipath *mpath;
  mpls_downstream_label     *mlabel;

  mdm->tlv.type = htons(MPLS_TLV_TYPE_DOWNSTREAM_MAPPING);
  
  mdm->mtu = htons(mtu);

  mdm->ds_flags = 0;
  if (nh_ip->af == AF_INET) {
    mdm->address_type = MPLS_DS_ADDR_TYPE_IPV4_NUMBERED;
    v4_addr = (mpls_downstream_ipv4_address *)&mdm->data[0];
    v4_addr->downstream.s_addr = nh_ip->u.v32;
    v4_addr->downstream_interface.s_addr = nh_ip->u.v32;
    length += sizeof(mpls_downstream_ipv4_address);
  } else {
    mdm->address_type = MPLS_DS_ADDR_TYPE_IPV6_NUMBERED;
    v6_addr = (mpls_downstream_ipv6_address *)&mdm->data[0];
    memcpy(&v6_addr->downstream, &nh_ip->u.v6, sizeof(struct in6_addr));
    memcpy(&v6_addr->downstream_interface, &nh_ip->u.v6, sizeof(struct in6_addr));
    length += sizeof(mpls_downstream_ipv6_address);
  }

  mpath = (mpls_downstream_multipath *)((void *)mdm + length);
  length += sizeof(mpls_downstream_multipath);
  /*
   * There don't seem to be anything that says this is an ipv6 multipath..
   */
  mpath->mtype  = MPLS_MP_BIT_MASK_IP;
  mpath->dlimit = 0;
  if (nh_ip->af == AF_INET) {
    mpls_downstream_ipv4_address *mpath_v4 = (mpls_downstream_ipv4_address *)&mpath->data[0];
    mpath->mlength = htons(8);

    mpath_v4->downstream.s_addr = htonl(0x7f000000);
    mpath_v4->downstream_interface.s_addr = htonl(0x40000000);

    length += sizeof(mpls_downstream_ipv4_address);
  } else {
    mpls_downstream_ipv6_address *mpath_v6 = (mpls_downstream_ipv6_address *)&mpath->data[0];
    mpath->mlength = htons(32);
    memcpy(&mpath_v6->downstream, &nh_ip->u.v6, sizeof(struct in6_addr));
    memcpy(&mpath_v6->downstream_interface, &nh_ip->u.v6, sizeof(struct in6_addr));

    length += sizeof(mpls_downstream_ipv6_address);
  }


  mlabel = (mpls_downstream_label *)((void *)mdm + length);
  mlabel->hlabel = htons(label >> 4);
  mlabel->llabel = label & 0xf;
  mlabel->exp = 0;
  mlabel->bos = 1;
  mlabel->protocol = 0;
 
  length += sizeof(mpls_downstream_label);

  mdm->tlv.length = htons(length - sizeof(mpls_ping_tlv));
  return(length);
}

/*
 * mpls_build_udp_packet
 *
 * Section 3 - Packet Format
 *
 * Returns the sizeof mpls_ping_packet and the tlv data generated
 *
 */
static uint32_t
mpls_packet_build_udp_data (unsigned char *buffer, route *route,
			    uint32_t seq_no, uint32_t sender_handle,
			    uint32_t msgtype, uint32_t replymode,
			    uint32_t rcode, uint32_t rsubcode,
			    struct timeval *stv, struct timeval *rtv,
			    uint32_t downstream_mapping, address *nh_info,
			    mpls_label_stack *ls, mpls_label_ilm *ilm,
			    uint32_t mtu)
{
  mpls_ping_packet *pdata = (mpls_ping_packet *)buffer;
  uint32_t length = sizeof(mpls_ping_packet);
  ntp_time_t sntp, rntp;
  uint32_t label;

  mpls_util_unix_to_ntp_time(stv, &sntp);
  /*
   * Set these values to 0, from 4.3:
   * The TimeStamp Received is set to zero.
   * We signal this by sending in rtv with 0 values
   */
  if ((rtv->tv_sec == 0) && (rtv->tv_usec == 0)) {
    rntp.seconds = 0;
    rntp.fraction = 0;
  } else {
    mpls_util_unix_to_ntp_time(rtv, &rntp);
  }

  pdata->version        = htons(MPLS_PING_VERSION_NUMBER);
  pdata->gflags         = htons(GLOBAL_FLAG_V_NO_FEC_VALIDATION);
  pdata->msgtype        = msgtype;
  pdata->replymode      = replymode;
  pdata->rcode          = rcode;
  pdata->rsubcode       = rsubcode;
  pdata->sender_handle  = htonl(sender_handle);
  pdata->seq_number     = htonl(seq_no);
  pdata->secs_sent      = htonl(sntp.seconds);
  pdata->msecs_sent     = htonl(sntp.fraction);
  pdata->secs_received  = htonl(rntp.seconds);
  pdata->msecs_received = htonl(rntp.fraction);

  length += mpls_packet_build_tlv_prefix((mpls_ping_tlv *)(buffer + length), route);
  if (downstream_mapping) {
    if (ilm == NULL) {
      label = mpls_get_hdr_label(&ls->u.l);
    } else {
      label = ilm->operation;
    }
    length += mpls_packet_build_tlv_downstream((mpls_downstream_mapping *)(buffer + length), label, nh_info, mtu);
  }

  return length;
}

unsigned int
mpls_packet_build_packet (unsigned char *buffer, int length, mac_info *source,
			  address *daddr, mac_info *nh,
			  mpls_label_stack *ls, uint32_t seqno,
			  uint32_t sender_handle, uint16_t dport, uint16_t sport,
			  route *route, uint32_t msgtype, uint32_t replymode,
			  uint32_t rcode, uint32_t rsubcode,
			  struct timeval *stv, struct timeval *rtv,
			  int includels, int includera, int downstream_mapping,
			  mpls_label_ilm *ilm, uint32_t mtu)
{
  uint32_t packet_size = 0;
  uint32_t ethhdr_size = ETH_HLEN;
  uint32_t iphdr_size;
  uint32_t udphdr_size = 8;
  uint32_t ls_size;
  uint32_t data_size = 0;
  uint16_t proto = ETH_P_MPLS_UC;

  unsigned char *stream_ethhdr;
  unsigned char *stream_ls;
  unsigned char *stream_iphdr;
  unsigned char *stream_udphdr;
  unsigned char *stream_udpdata;

  if (source->addr.af == AF_INET) {
    if (includera) {
      iphdr_size = MPLS_PACKET_IP_LEN_RA_BYTES;
    } else {
      iphdr_size = MPLS_PACKET_IP_LEN_BYTES;
    }
  } else {
    if (includera) {
      iphdr_size = MPLS_PACKET_IP6_LEN_RA_BYTES;
    } else {
      iphdr_size = MPLS_PACKET_IP6_LEN_BYTES;
    }
  }

  stream_ethhdr  = buffer;
  stream_ls      = stream_ethhdr + ethhdr_size;

  if (includels) {
    stream_iphdr   = stream_ls + mpls_label_ls_size(ls);
  } else {
    stream_iphdr   = stream_ls;
  }
  ls_size = stream_iphdr - stream_ls;

  stream_udphdr  = stream_iphdr + iphdr_size;
  stream_udpdata = stream_udphdr + udphdr_size;

  packet_size = ethhdr_size + ls_size + iphdr_size + udphdr_size;
  /*
   * Build the packet backwards so that we can do crc and other stuff.
   * I should do this blindfolded as well
   */
  data_size = mpls_packet_build_udp_data(stream_udpdata, route, seqno, sender_handle,
					 msgtype, replymode, rcode, rsubcode, stv, rtv,
					 downstream_mapping, &nh->addr, ls, ilm, mtu);

  packet_size += data_size;
  if (packet_size > length) {
    printf("Length of buffer given cannot contain packet\n");
    return 0;
  }

  mpls_packet_build_udp_header(stream_udphdr, data_size + udphdr_size, dport, sport);
  if (source->addr.af == AF_INET) {
    mpls_packet_build_ip_header(stream_iphdr, &source->addr, daddr,
				data_size + udphdr_size, includera );
  } else {
    mpls_packet_build_ip6_header(stream_iphdr, &source->addr, daddr,
				 data_size + udphdr_size, includera);
  }

  mpls_packet_build_udp_header_cksum(stream_udphdr, stream_iphdr, stream_udpdata,
				     data_size);

  if (includels) {
    mpls_label_build_stream(stream_ls, ls);
  } else {
    proto = (source->addr.af == AF_INET) ? ETH_P_IP : ETH_P_IPV6;
  }

  mpls_packet_build_mac_header(stream_ethhdr, nh->mac, source->mac, proto);

  return packet_size;
}

mpls_label_stack *
mpls_packet_get_label (route *route, char *intf, uint32_t ttl)
{
  FILE *fp;
  uint32_t out_label  = 0;
  uint32_t in_label = 0;
  uint32_t ret;
  char buffer[1000];
  char buf1[100];
  mpls_label_stack *ls = NULL;

  sprintf(buffer, "vtysh -c \"show %s route %s/%d\" | grep %s | grep label | "
          "sed -n -e 's/^.*label \\(.*\\)$/\\1/p' > /tmp/label.tmp",
	  (route->addr.af == AF_INET) ? "ip" : "ipv6",
	  inet_ntop(route->addr.af, (void *)&route->addr.u.v32, buf1, 100),
	  route->prefix, intf);

  system(buffer);

  fp = fopen("/tmp/label.tmp", "r+");
  ret = fscanf(fp, "%d/%d", &out_label, &in_label);
  if (ret != 2) {
    ret = fscanf(fp, "%d", &out_label);
  }

  fclose(fp);
  unlink("/tmp/label.tmp");

  if (in_label != 0)
    /*
     * 4.7 - Typically, an LSP ping for a VPN IPv4 prefix or VPN IPv6 prefix is
     * sent with a label stack of depth greater than 1, with the innermost
     * label having a TTL of 1.  This is to terminate the ping at the egress
     * PE, before it gets sent to the customer device.
     */
    ls = mpls_label_add(ls, in_label, 0, 1);

  ls = mpls_label_add(ls, out_label, 0, ttl);
  return ls;
}

int
mpls_packet_get_labeled_intf (address *addr, char *intf)
{
  FILE *fp;
  char buffer[1000];
  char buf1[100];
  int ret = 0;

  sprintf(buffer, "vtysh -c \"show %s route %s\" | grep via | grep -v inactive | grep -v distance | cut -d \",\" -f 2 | cut -d \" \" -f 3 > /tmp/lintf.tmp",
	  (addr->af == AF_INET) ? "ip" : "ipv6",
	  inet_ntop(addr->af, (void *)&addr->u.v32, buf1, 100));

  system(buffer);

  fp = fopen("/tmp/lintf.tmp", "r+");
  ret = fscanf(fp, "%s", intf);
  fclose(fp);
  unlink("/tmp/lintf.tmp");

  return ret == 1;
}

int
mpls_packet_get_labeled_nexthop (address *addr, char *intf, address *nh)
{
  FILE *fp;
  char buffer[1000];
  char buf1[100];

  sprintf(buffer, "vtysh -c \"show %s route %s\" | grep via | grep -v inactive | grep -v distance | grep %s | cut -d \",\" -f 1 | cut -d \" \" -f 4 > /tmp/lnh.tmp",
	  (addr->af == AF_INET) ? "ip" : "ipv6",
	  inet_ntop(addr->af, (void *)&addr->u.v32, buf1, 100),
	  intf);

  system(buffer);

  fp = fopen("/tmp/lnh.tmp", "r+");
  fscanf(fp, "%s", buffer);

  fclose(fp);
  unlink("/tmp/lnh.tmp");
  if (!mpls_network_addr_retrieve(buffer, nh)) {
    return 0;
  } else {
    return 1;
  }
}

int
mpls_packet_get_labeled_route (address *addr, route *route)
{
  FILE *fp;
  char buffer[1000];
  char buf1[100];
  char *address;
  char *prefix;

  route->addr.af = addr->af;

  /*
   * Cheating since I need to get this now
   */
  sprintf(buffer, "vtysh -c \"show %s route %s\" | grep \"Routing\" | cut -d \" \" -f 4 > /tmp/lroute.tmp",
	  (addr->af == AF_INET) ? "ip" : "ipv6",
	  inet_ntop(addr->af, (void *)&addr->u.v32, buf1, 100));

  system(buffer);
  fp = fopen("/tmp/lroute.tmp", "r+");
  fscanf(fp, "%s" , buffer);
  address = strtok(buffer, "/");
  prefix = strtok(NULL, "/");

  sscanf(prefix, "%d", &route->prefix);

  fclose(fp);
  unlink("/tmp/lroute.tmp");
  if (!mpls_network_addr_retrieve(address, &route->addr)) {
    return 0;
  } else {
    return 1;
  }
}

static int
mpls_packet_retrieve_intf_index (int s, char *interface, unsigned int *ifindex)
{
  struct ifreq ifr;

  strncpy(ifr.ifr_name, interface, strlen(interface) + 1);
  
  if (ioctl(s, SIOCGIFINDEX, &ifr) == -1) {
    perror("Failed to retrieve index from interface specified: \n");
    return 0;
  }

  *ifindex = ifr.ifr_ifindex;
  return 1;
}

uint32_t
mpls_packet_retrieve_intf_mtu (char *interface)
{
  int s;
  struct ifreq ifr;

  strncpy(ifr.ifr_name, interface, strlen(interface) + 1);

  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("Failed to create socket to retrieve interface mtu: \n");
    return 0;
  }

  if (ioctl(s, SIOCGIFMTU, &ifr) == -1) {
    close(s);
    perror("Failed to retrieve interface mtu:\n");
    return 0;
  }

  close(s);
  return ifr.ifr_mtu;
}

int
mpls_packet_retrieve_intf_mac (int s, char *interface, unsigned char *buff)
{
  struct ifreq ifr;

  strcpy(ifr.ifr_name, interface);
  
  if (ioctl(s, SIOCGIFHWADDR, &ifr) != 0) {
    perror("Unable to retrieve interface mac address\n");
    return -1;
  }

  memcpy(buff, ifr.ifr_hwaddr.sa_data, 6);
  return 1;
}

/*
 * mpls_packet_address_is_link_local
 *
 * Check to see that the address is a ipv6
 * link local address.
 *
 */
static int
mpls_packet_address_is_link_local (address *addr)
{
  if ((addr->af == AF_INET6) && (IN6_IS_ADDR_LINKLOCAL(&addr->u.v6.s6_addr))) {
    return 1;
  } 
  return 0;
}

/*
 * mpls_packet_retrieve_link_local_mac
 *
 * From a link local mac ipv6 address retrieve the mac address
 * embedded within it.
 *
 * See the ipv6 address Appendix for a description of this algorithm
 *
 */
static void
mpls_packet_retrieve_link_local_mac (mac_info *mi)
{
  struct in6_addr *a = &mi->addr.u.v6;
  unsigned char buff[6];
  uint8_t one;
  uint8_t count = 0;
  uint8_t i;

  for( i = 8 ; i < 16; i++ ) {
    one = a->s6_addr[i];
    if (i == 8) {
      one ^= 1 << 1;
      buff[count] = one;
      count++;
    } else if ((i == 11) || (i == 12)) {
      continue;
    } else {
      buff[count] = one;
      count++;
    }
  }
  memcpy(mi->mac, buff, 6);
}

static void
mpls_packet_retrieve_nh_mac (mac_info *nh, char *ifname)
{
  FILE *fp;
  char buffer[1000];
  char buf1[100];

  if (mpls_packet_address_is_link_local(&nh->addr)) {
    mpls_packet_retrieve_link_local_mac(nh);
    return;
  }

  sprintf(buffer, "ip neigh show %s | cut -d \" \" -f 5 > /tmp/nh_mac.tmp",
	  inet_ntop(nh->addr.af, (void *)&nh->addr.u.v32, buf1, 100));

  system(buffer);

  fp = fopen("/tmp/nh_mac.tmp", "r+");
  fscanf(fp, "%s", buffer);
  fclose(fp);
  unlink("/tmp/nh_mac.tmp");

  sscanf(buffer, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	 &nh->mac[0], &nh->mac[1], &nh->mac[2], &nh->mac[3], &nh->mac[4], &nh->mac[5]);

}

int
mpls_packet_retrieve_macs (char *interface, mac_info *nh,
			   unsigned char *local_mac,
			   unsigned int *ifindex, int connected)
{
  int s;

  if ((s = socket(nh->addr.af, SOCK_DGRAM, 0)) < 0) {
    return -1;
  }

  mpls_packet_retrieve_intf_index(s, interface, ifindex);
  mpls_packet_retrieve_intf_mac(s, interface, local_mac);
  if (!connected) {
    mpls_packet_retrieve_nh_mac(nh, interface);
  } else {
    memcpy(nh->mac, local_mac, 6);
  }
  close(s);

  return 0;
}

/*
 * mpls_packet_downstream_mapping_present
 *
 * Given a packet, is a downstream mapping tlv present?
 */
uint32_t
mpls_packet_downstream_mapping_present (packet_peeker *packet)
{
  // To be filled in later
  return 0;
}


uint32_t
mpls_packet_get_return_code (packet_peeker *packet)
{
  mpls_ping_packet *mpp = (mpls_ping_packet *)packet->udpdata;

  return mpp->rcode;
}

uint32_t
mpls_packet_get_sub_return_code (packet_peeker *packet)
{
  mpls_ping_packet *mpp = (mpls_ping_packet *)packet->udpdata;

  return mpp->rsubcode;
}

char *
mpls_packet_print_ret_code_info (packet_peeker *packet, char *buff)
{
  mpls_ping_packet *mpp = (mpls_ping_packet *)packet->udpdata;

  switch (mpp->rcode) {
  case MPLS_NO_RETURN_CODE:
    sprintf(buff, "No Return Code\n");
    break;
  case MPLS_MALFORMED_ECHO_REQUEST:
    sprintf(buff, "Malformed Echo Request\n");
    break;
  case MPLS_TLV_NOT_UNDERSTOOD:
    sprintf(buff, "TLV notUnderstood at: %d\n", mpp->rsubcode);
    break;
  case MPLS_FEC_EGRESS:
    sprintf(buff, "FEC Egress: %d\n", mpp->rsubcode);
    break;
  case MPLS_NO_FEC_MAPPING:
    sprintf(buff, "No FEC mapping at %d\n", mpp->rsubcode);
    break;
  case MPLS_MAPPING_MISSMATCH:
    sprintf(buff, "Downstream Mapping Missmatch at %d\n", mpp->rsubcode);
    break;
  case MPLS_UPSTREAM_INTERFACE_UNKNOWN:
    sprintf(buff, "Upstream Interface Unknown at %d\n", mpp->rsubcode);
    break;
  case MPLS_RESERVED:
    sprintf(buff, "Reserved Value\n");
    break;
  case MPLS_LABEL_SWITCHED_AT_DEPTH:
    sprintf(buff, "Label Switched at depth %d\n", mpp->rsubcode);
    break;
  case MPLS_LABEL_SWITCHED_NO_MPLS:
    sprintf(buff, "Label Switched no mapping %d\n", mpp->rsubcode);
    break;
  case MPLS_FEC_MAPPING_INCORRECT:
    sprintf(buff, "Mapping for FEC not the given label %d\n", mpp->rsubcode);
    break;
  case MPLS_NO_LABEL_AT_DEPTH:
    sprintf(buff, "No label entry at %d\n", mpp->rsubcode);
    break;
  case MPLS_WRONG_PROTO_AT_DEPTH:
    sprintf(buff, "Protocol not assoicated with interface at %d\n", mpp->rsubcode);
    break;
  case MPLS_PREMATURE_SHRINKAGE:
    sprintf(buff, "Premature termination of ping due to label stack shrinkage\n");
    break;
  default:
    sprintf(buff, "Unknown:%d\n", mpp->rsubcode);
    break;
  }

  return buff;
}

uint32_t
mpls_packet_get_downstream_mtu (packet_peeker *packet)
{
  mpls_downstream_mapping *mdm;

  mdm = packet->tlv_downstream_mapping;

  return ntohs(mdm->mtu);
}

uint32_t
mpls_packet_get_downstream_label (packet_peeker *packet)
{
  mpls_downstream_multipath *mpath;
  mpls_downstream_label *mlabel;
  mpls_downstream_mapping *mdm;
  uint32_t length;
  uint8_t addr_type;

  mdm = packet->tlv_downstream_mapping;

  addr_type = mdm->address_type;

  if ((addr_type == MPLS_DS_ADDR_TYPE_IPV4_NUMBERED) ||
      (addr_type == MPLS_DS_ADDR_TYPE_IPV4_UNNUMBERED)) {
    length = sizeof(mpls_downstream_ipv4_address);
  } else {
    length = sizeof(mpls_downstream_ipv6_address);
  }


  mpath = (mpls_downstream_multipath *)
    ((void *)mdm + sizeof(mpls_downstream_mapping) + length);

  mlabel = (mpls_downstream_label *)
    ((void *)mpath + sizeof(mpls_downstream_multipath) + length);

  return (ntohs(mlabel->hlabel) << 4) | mlabel->llabel;
}

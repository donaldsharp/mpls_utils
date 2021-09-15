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
#include <malloc.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <linux/if_arp.h>
#include <unistd.h>
#include <sys/time.h>
#include <netdb.h>
#include "mpls_util.h"
#include "mpls_network.h"
#include "mpls_label.h"
#include "mpls_ping.h"
#include "mpls_packet.h"
#include "mpls_log.h"

FILE *lf = NULL;
uint32_t debug = 0;
uint32_t debug_detail = 0;

char *mpls_ping = NULL;
uint32_t mpls_packets_sent = 0;
uint32_t mpls_packets_received = 0;
struct timeval time_start;

static int
mpls_ping_get_address (char *host, address *addr)
{
  struct addrinfo hints, *res;
  int errcode;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags |= AI_CANONNAME;

  errcode = getaddrinfo (host, NULL, &hints, &res);
  if (errcode != 0) {
    return 0;
  }

  addr->af = res->ai_family;
  switch(addr->af) {
  case AF_INET:
    memcpy(&addr->u.v4, &((struct sockaddr_in *)res->ai_addr)->sin_addr, sizeof(addr->u.v4));
    break;
  case AF_INET6:
    memcpy(&addr->u.v6, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, sizeof(addr->u.v6));
    break;
  default:
    freeaddrinfo(res);
    return 0;
    break;
  }

  freeaddrinfo(res);
  return 1;
}

void
mpls_ping_send_packet (uint32_t *sockfd, unsigned int ifindex, unsigned char *nh_mac,
		       unsigned char *buffer, int length)
{
  struct sockaddr_ll addr;

  DEBUG("%s Sending %d bytes\n", __FUNCTION__, length);
  memset(&addr, 0, sizeof(struct sockaddr_ll));
  addr.sll_family   = AF_PACKET;
  addr.sll_ifindex  = ifindex;
  addr.sll_halen    = ETH_ALEN;
  memcpy(addr.sll_addr, nh_mac, ETH_ALEN);

  DEBUG("Sending packet to ifindex: %d\n", ifindex);

  if (*sockfd == 0) {
    if ((*sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
      perror("Unable to open socket");
      exit(-1);
    }
  }

  if (sendto(*sockfd, buffer, length, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_ll)) < 0) {
    perror("Unable to send packet");
    exit(-1);
  }
}

static void
mpls_ping_set_daddr(uint32_t af, address *daddr)
{
  char buff[100] = "0000:0000:0000:0000:0000:FFFF:127:14";

  if (af == AF_INET) {
    daddr->af = AF_INET;
    daddr->u.v32 = htonl(0x7f2a2a2a);
  } else {
    daddr->af = AF_INET6;
    if (!inet_pton(af, buff, &daddr->u.v32)) {
      printf("Failed to convert address\n");
    }
  }
}

/*
 * mpls_ping_is_our_echo_reply
 *
 * This function ensures that we sent out the request that we've read
 */
static int
mpls_ping_is_our_echo_reply (mpls_ping_packet *mpp, uint32_t sh, uint32_t seq_no)
{
  if ((ntohl(mpp->sender_handle) == sh) && (ntohl(mpp->seq_number) == seq_no)) {
    return 1;
  }

  return 0;
}

static void
mpls_ping_change_seqno_and_time (packet_peeker *packet, uint32_t seq_no)
{
  struct timeval tv;
  ntp_time_t ntp_sent;

  gettimeofday(&tv, NULL);
  mpls_util_unix_to_ntp_time(&tv, &ntp_sent);

  mpls_ping_packet *mpp = (mpls_ping_packet *)packet->udpdata;

  mpp->seq_number     = htonl(seq_no);
  mpp->secs_sent      = htonl(ntp_sent.seconds);
  mpp->msecs_sent     = htonl(ntp_sent.fraction);
  mpp->secs_received  = 0;
  mpp->msecs_received = 0;
}

static void
mpls_ping_increment_ttl(packet_peeker *packet)
{
  struct mpls_label *label;

  if (!packet->lhdr) {
    return;
  }

  label = (struct mpls_label *)packet->lhdr;
  label->ttl = label->ttl + 1;
}

/*
 * mpls_ping_is_echo_reply
 *
 * This function parses the incoming packet
 * and then compares the af/dport and sender handle
 * to ensure that the data is correct to what we
 * sent
 */
mpls_ping_packet *
mpls_ping_is_echo_reply (packet_peeker *packet, int af, uint16_t dport)
{
  mpls_ping_packet *mpp;
  struct udphdr *udphdr;
  uint16_t rdport;

  if (!mpls_packet_parse_structures(packet)) {
    return NULL;
  }

  if (((af == AF_INET) && (packet->iphdr == NULL)) ||
      ((af == AF_INET6) && (packet->ip6hdr == NULL))) {
    return NULL;
  }

  udphdr = (struct udphdr *)packet->udphdr;
  rdport = ntohs(udphdr->dest);
  if (rdport != dport) {
    return NULL;
  }
  mpp = (mpls_ping_packet *)packet->udpdata;

  return mpp;
}

uint32_t
mpls_ping_print_traceroute_info (packet_peeker *packet)
{
  char buf1[80];
  struct timeval tv_recv, tv_sent, result;
  address responder;
  uint32_t ret;

  gettimeofday(&tv_recv, NULL);
  mpls_packet_get_time_sent(packet, &tv_sent);
  mpls_util_timeval_subtract(&result, &tv_recv, &tv_sent);
  mpls_packet_get_src_addr(packet, &responder);
  ret = mpls_packet_get_return_code(packet);
  printf("%d bytes from %s: time= %ld.%03ld",
	 packet->length,
	 inet_ntop(responder.af, (void *)&responder.u.v32, buf1, 80),
	 result.tv_sec, result.tv_usec / 1000);
  if (ret == MPLS_FEC_EGRESS) {
    printf("\n");
  } else {
    mpls_packet_parse_tlv(packet);
    if (packet->tlv_downstream_mapping) {
      printf(" MRU %d [%s]", mpls_packet_get_downstream_mtu(packet),
	     mpls_label_print_info(mpls_packet_get_downstream_label(packet),
				   buf1, 80));
    }
    printf(", %s", mpls_packet_print_ret_code_info(packet, buf1));
  }
  return ret;
}

uint32_t
mpls_ping_print_ping_info (packet_peeker *packet)
{
  char buf1[40];
  struct timeval tv_recv, tv_sent, result;
  address responder;
  uint32_t ret;
  mpls_ping_packet *mpp = (mpls_ping_packet *)packet->udpdata;

  gettimeofday(&tv_recv, NULL);
  mpls_packet_get_time_sent(packet, &tv_sent);
  mpls_util_timeval_subtract(&result, &tv_recv, &tv_sent);
  mpls_packet_get_src_addr(packet, &responder);
  ret = mpls_packet_get_return_code(packet);

  printf("%d bytes from %s: seq_no=%d, time= %ld.%03ld",
	 packet->length,
	 inet_ntop(responder.af, (void *)&responder.u.v32, buf1, 40),
	 ntohl(mpp->seq_number),
	 result.tv_sec, result.tv_usec / 1000);
  if (ret == MPLS_FEC_EGRESS) {
    printf("\n");
  } else {
    printf(", Unexpected Return code: %d, subret: %d\n",
	   ret, mpls_packet_get_sub_return_code(packet));
  }
  return ret;
}

uint32_t
mpls_ping_listen_packet (uint32_t *sockfd, int af, int sport, uint32_t sender_handle,
			 uint32_t seqno, uint32_t (*outputer)(packet_peeker *))
{
  packet_peeker packet;
  int data = 0;
  int count = 0;
  mpls_ping_packet *mpp;
  struct timeval tv;
  fd_set active_fd_set, read_fd_set;
  uint32_t ret;

  memset(&packet, 0, sizeof(packet_peeker));
  setbuf(stdout, NULL);

  if (*sockfd == 0) {
    *sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  }

  FD_ZERO(&active_fd_set);
  FD_SET(*sockfd, &active_fd_set);

  tv.tv_sec = 1;
  tv.tv_usec = 0;
  while (1) {
    mpls_packet_clean(&packet);
    packet.length = 1000;
    while(!data && count < 5) {
      read_fd_set = active_fd_set;
      data = select(*sockfd+1, &read_fd_set, NULL, NULL, &tv);

      if (!data) {
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	count++;
	putchar('.');
      }
    }
    data = 0;

    if (count == 5) {
      printf("  Did not receive response\n");
      return MPLS_NO_RETURN_CODE;
    }
    packet.length = read(*sockfd, &packet.stream, packet.length);

    mpp = mpls_ping_is_echo_reply(&packet, af, sport);

    if (mpp) {
      if (mpls_ping_is_our_echo_reply(mpp, sender_handle, seqno)) {
	mpls_packets_received++;
	ret = outputer(&packet);
	select(0, NULL, NULL, NULL, &tv);
	return ret;
      }
    }
  }
}

static void
mpls_ping_handle_traceroute (packet_peeker *packet, uint32_t ifindex,
			     unsigned char *nh_mac, address *addr,
			     uint32_t sender_handle, uint32_t seqno)
{
  uint32_t ret;
  uint32_t sockfd = 0;
  uint32_t listenfd = 0;

  while (1) {
    mpls_packets_sent++;
    mpls_ping_send_packet(&sockfd, ifindex, nh_mac, packet->stream, packet->length);
    DEBUG("Listen for %d, on %d, with %d handle\n", addr->af, 5309, sender_handle);
    printf("%02d: ", mpls_packets_sent);
    ret = mpls_ping_listen_packet(&listenfd, addr->af, 5309, sender_handle,
				  seqno, mpls_ping_print_traceroute_info);
    if (ret == MPLS_FEC_EGRESS) {
      exit(0);
    }
    /* If we've hit an error for traceroute, exit. */
    if (ret == MPLS_NO_LABEL_AT_DEPTH) {
      exit(-1);
    }
    seqno++;
    mpls_ping_change_seqno_and_time(packet, seqno);
    mpls_ping_increment_ttl(packet);
    mpls_packet_build_udp_header_cksum(packet->udphdr,
				       (packet->iphdr != NULL) ? packet->iphdr : packet->ip6hdr,
				       packet->udpdata,
				       packet->length - (packet->udpdata - packet->stream));
  }
}

static void
mpls_ping_print_statistics (void)
{
  struct timeval now;
  struct timeval result;

  gettimeofday(&now, NULL);
  mpls_util_timeval_subtract(&result, &now, &time_start);
  printf("\n---- %s ping statistics ----\n", mpls_ping);
  printf("%d packets transmitted, %d received in %ld.%03ld\n",
	 mpls_packets_sent, mpls_packets_received, result.tv_sec, result.tv_usec / 1000);
}

void
mpls_ping_handle_ping (packet_peeker *packet, uint32_t ifindex,
		       unsigned char *nh_mac, address *addr,
		       uint32_t sender_handle, uint32_t seqno, int pkt_count)
{
  uint32_t ret;
  uint32_t sockfd = 0;
  uint32_t listenfd = 0;

  while ((pkt_count == -1) || (mpls_packets_sent < pkt_count)) {
    mpls_packets_sent++;
    mpls_ping_send_packet(&sockfd, ifindex, nh_mac, packet->stream, packet->length);
    DEBUG("Listen for %d, on %d, with %d handle\n", addr->af, 5309, sender_handle);
    ret = mpls_ping_listen_packet(&listenfd, addr->af, 5309, sender_handle,
				  seqno, mpls_ping_print_ping_info);
    if (ret != MPLS_FEC_EGRESS) {
      printf("Received Unexpected Response: %d\n", ret);
    }
    seqno++;
    mpls_ping_change_seqno_and_time(packet, seqno);
    mpls_packet_build_udp_header_cksum(packet->udphdr,
				       (packet->iphdr != NULL) ? packet->iphdr : packet->ip6hdr,
				       packet->udpdata,
				       packet->length - (packet->udpdata - packet->stream));
  }

  mpls_ping_print_statistics();
}

static void
mpls_ping_send (address *addr, int pkt_count, const char *interface,
		int traceroute)
{
  address daddr;
  route   route;
  packet_peeker packet;
  char buf1[40], buf2[40], buf3[40];
  char ifname[40];
  uint32_t ifindex = 0;
  uint32_t seqno = 0;
  uint32_t sender_handle = 0;
  mpls_label_stack *ls = NULL;
  struct timeval time;
  struct timeval rtv;
  mac_info nh;
  mac_info local;
  uint32_t ttl;
  uint32_t use_mpls;

  memset(&packet, 0, sizeof(packet_peeker));
  packet.length = PACKET_SIZE;

  if (!mpls_packet_get_labeled_route(addr, &route)) {
    printf("Unable to retrieve labeled route for %s\n", mpls_ping);
    exit(-1);
  }

  if (interface == NULL) {
    if(!mpls_packet_get_labeled_intf(addr, ifname)) {
      printf("Unable to retrieve an outgoing interface for %s\n", mpls_ping);
      exit(-1);
    }
  } else {
    strcpy(ifname, interface);
  }
  if (!mpls_packet_get_labeled_nexthop(addr, ifname, &nh.addr)) {
    printf("Unable to retrieve labeled nexthop for %s\n", mpls_ping);
    exit(-1);
  }

  ttl = (traceroute) ? 1 : 255;
  ls = mpls_packet_get_label(&route, ifname, ttl);
  if (!ls) {
    printf("Unable to find usable label for %s/%d on interface %s\n",
	   inet_ntop(route.addr.af, (void *)&route.addr.u.v32, buf1, 40),
	   route.prefix, ifname);
    exit(-1);
  }

  printf("%s Address: %s, Nexthop: %s on interface %s\n",
	 traceroute ? "Tracerouting" : "Pinging",
	 inet_ntop(addr->af, (void *)&addr->u.v32, buf1, 40),
	 inet_ntop(nh.addr.af, (void *)&nh.addr.u.v32, buf2, 40), ifname);
  printf("for label %s decided by route: %s/%d\n",
	 mpls_label_print_ls(ls, buf2, 40), inet_ntop(route.addr.af, (void *)&route.addr.u.v32, buf3, 40),
	 route.prefix);

  mpls_packet_retrieve_local_address(addr, &local.addr, &use_mpls);
  mpls_packet_retrieve_macs(ifname, &nh, local.mac, &ifindex, 0);
  DEBUG("local mac %hhx:%hhx:%hhx:%hhx%hhx:%hhx nh_mac: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx using mpls %d\n",
	local.mac[0], local.mac[1], local.mac[2], local.mac[3], local.mac[4], local.mac[5],
	nh.mac[0], nh.mac[1], nh.mac[2], nh.mac[3], nh.mac[4], nh.mac[5], use_mpls);
  mpls_ping_set_daddr(addr->af, &daddr);
  gettimeofday(&time, NULL);
  time_start = time;

  srand(time.tv_usec);
  seqno = 1;
  sender_handle = rand();

  /*
   * Send in 0's so the values get set to zero
   */
  rtv.tv_sec = 0;
  rtv.tv_usec = 0;
  packet.length = mpls_packet_build_packet(packet.stream, packet.length, &local, &daddr,
					   &nh, ls, seqno, sender_handle, 3503, 5309,
					   &route, MPLS_ECHO_REQUEST, MPLS_REPLY_PACKET,
					   MPLS_NO_RETURN_CODE, MPLS_NO_RETURN_CODE,
					   &time, &rtv, use_mpls, 1,
					   traceroute, NULL, MPLS_DS_MTU_DEFAULT);
  if (!mpls_packet_parse_structures(&packet)) {
    printf("Failure to parse outgoing packet.  Something has gone terribly wrong\n");
    exit(-1);
  }
  if (traceroute) {
    mpls_ping_handle_traceroute(&packet, ifindex, nh.mac, addr, sender_handle, seqno);
  } else {
    mpls_ping_handle_ping(&packet, ifindex, nh.mac, addr, sender_handle, seqno, pkt_count);
  }
}

static void
mpls_ping_signal_handler (int val)
{
  mpls_ping_print_statistics();
  exit(0);
}

static void
mpls_traceroute_signal_handler (int val)
{
  exit(0);
}

static void
mpls_ping_print_help (void)
{
  printf("mpls-ping -[v|V] -h -t <Address>\n");
  printf("\n");
  printf("\t-v = Some debugging information is printed\n");
  printf("\t-V = More Verbose debugging information is printed\n");
  printf("\t-h = This option\n");
  printf("\t-t = Traceroute to the specified address\n");
  printf("\t-I <name> = Specific interface name to use\n");
  printf("\t-c <1-MAXINT> = Number of packets to send in a ping operation\n");
  printf("\n");
  printf("\t<Address> is either an IPv4 or IPv6 address to send towards\n");
}

int
main (int argc, char *argv[])
{
  int c;
  int traceroute  = 0;
  int arg_count   = 1;
  int pkt_count   = -1;
  char *interface = NULL;
  address addr;

  signal(SIGINT, mpls_ping_signal_handler);

  lf = stdout;
  while ((c = getopt(argc, argv, "vVthc:I:")) != -1) {
    switch(c) {
    case 'I':
      interface = optarg;
      arg_count += 2;
      break;
    case 'c':
      pkt_count = atoi(optarg);
      arg_count += 2;
      break;
    case 'v':
      debug = 1;
      arg_count++;
      break;
    case 'V':
      debug = 1;
      debug_detail = 1;
      arg_count++;
      break;
    case 't':
      arg_count++;
      traceroute = 1;
      break;
    case 'h':
    default:
      mpls_ping_print_help();
      exit(-1);
      break;
    }
  }

  signal(SIGINT, traceroute ?
	 mpls_traceroute_signal_handler : mpls_ping_signal_handler);

  if (arg_count == argc) {
    printf("Please Specify a v4 or v6 address to mpls-ping\n");
    exit(-1);
  }

  if (traceroute && (pkt_count != -1)) {
    printf("Traceroute options is incompatible with packet count option\n");
    exit(-1);
  }

  if ((pkt_count != -1) && (pkt_count <= 0)) {
    printf("Specify a legal number of packets to send <1-MAXINT>\n");
    exit(-1);
  }

  mpls_ping = argv[optind];

  if (!mpls_ping_get_address(mpls_ping, &addr)) {
    printf("Unable to convert %s into an address\n", mpls_ping);
    exit(-1);
  }

  mpls_ping_send(&addr, pkt_count, interface, traceroute);

  exit(0);
}

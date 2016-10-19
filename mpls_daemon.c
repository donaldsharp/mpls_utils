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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include "mpls_util.h"
#include "mpls_network.h"
#include "mpls_label.h"
#include "mpls_ping.h"
#include "mpls_packet.h"
#include "mpls_log.h"
#include <sys/ioctl.h>

typedef struct int_sockets_ {
  int ifindex;
  char ifname[100];
  int socket;
  unsigned char mac[6];
} int_sockets;

int_sockets *sockets = NULL;
int socket_number = 0;

int *sock_to_int_socks = NULL;

enum packet_type {
  PACKET_INTERESTING,
  PACKET_NOT_UDP,
  PACKET_NO_ROUTER_ALERT,
  PACKET_INCORRECT_OPTIONS,
  PACKET_TTL_WRONG,
  PACKET_INCORRECT_ADDRESS,
  PACKET_NOT_INTERESTING,
};

FILE *lf = NULL;
uint32_t debug = 0;
uint32_t debug_detail = 0;

static void mpls_daemon_label_stack_validation(packet_peeker *packet);

static void
mpls_daemon_debug_ret_codes (packet_peeker *packet)
{
  DEBUG_DETAIL("Ret Code: %d, Sub Ret Code: %d\n",
	       packet->ret_code, packet->subret_code);
}

/*
 * Section 4.4 Receiving an MPLS Echo Request
 *
 * General packet sanity is verified.  If the packet is not well-
 * formed, LSR X SHOULD send an MPLS Echo Reply with the Return Code
 * set to "Malformed echo request received" and the Subcode to zero.
 * If there are any TLVs not marked as "Ignore" that LSR X does not
 * understand, LSR X SHOULD send an MPLS "TLV not understood" (as
 * appropriate), and the Subcode set to zero.  In the latter case,
 * the misunderstood TLVs (only) are included as sub-TLVs in an
 * Errored TLVs TLV in the reply.  The header fields Sender's Handle,
 * Sequence Number, and Timestamp Sent are not examined, but are
 * included in the MPLS echo reply message.
 */
uint8_t
mpls_daemon_packet_sanity (packet_peeker *packet)
{
  return mpls_packet_parse_tlv(packet);
}

/*
 * mpls_daemon_is_us
 *
 * Raw sockets cause us to gets all packets ingoing or outgoing
 * on the wire.  This check ensures that we are not responding
 * to a ping that we just sent.  Look at the src mac address
 * and if it matches for us, then we sent it( probably ).
 */
uint8_t
mpls_daemon_is_us (packet_peeker *packet)
{
  unsigned char *mac = packet->stream + 6;
  int d = sock_to_int_socks[packet->sock_fd];

  if(memcmp(mac, sockets[d].mac, 6) == 0) {
    return 1;
  } else {
    return 0;
  }
}

#define IP_HEADER_ROUTER_ALERT_LENGTH 6
#define IP_HEADER_OPTION_VALUE 0x94040000
/*
 * Section 4.4 Receiving a MPLS Echo Request
 *
 * Sending an MPLS echo request to the control plane is triggered by one
 * of the following packet processing exceptions: Router Alert option,
 * IP TTL expiration, MPLS TTL expiration, MPLS Router Alert label, or
 * the destination address in the 127/8 address range.  The control
 * plane further identifies it by UDP destination port 3503.
 *
 */
enum packet_type
mpls_daemon_packet_interesting (packet_peeker *packet)
{
  struct iphdr   *iphdr;
  struct udphdr  *udphdr;
  uint32_t       ipheader_options;
  mpls_ping_packet *mpp;

  if (!mpls_packet_parse_structures(packet)) {
    DEBUG_DETAIL("Unable to parse packet\n");
    return PACKET_NOT_INTERESTING;
  }

  if (mpls_daemon_is_us(packet)) {
    DEBUG_DETAIL("is not us!\n");
    return PACKET_NOT_INTERESTING;
  }

  if (mpls_packet_is_mpls(packet)) {
    DEBUG_DETAIL("Packet is mpls\n");
    if (mpls_label_has_router_alert(packet->ls)) {
      DEBUG_DETAIL("\tHas a router alert\n");
      return PACKET_INTERESTING;
    }
    if (mpls_label_has_ttl_expiration(packet->ls)) {
      DEBUG_DETAIL("\tHas Label ttl expiration\n");
      return PACKET_INTERESTING;
    }

    /* If MPLS, TTL has to be 1 or RA label should be there. */
    return PACKET_NOT_INTERESTING ;
  }

  mpp = (mpls_ping_packet *)packet->udpdata;

  if (!mpp || (mpp->msgtype != MPLS_ECHO_REQUEST)) {
    DEBUG_DETAIL("Not an Echo Request\n");
    return PACKET_NOT_INTERESTING;
  }

  if (packet->iphdr) {
    DEBUG_DETAIL("IPv4 Packet\n");
    iphdr = (struct iphdr *)packet->iphdr;
    ipheader_options = ntohl(*(uint32_t *)packet->iphdr + 5);
    if ((iphdr->ihl == IP_HEADER_ROUTER_ALERT_LENGTH) &&
	(ipheader_options != IP_HEADER_OPTION_VALUE)) {
      DEBUG_DETAIL("IP header has Router Alert\n");
      return PACKET_INTERESTING;
    }

    /* IP TTL Expiration */
    if (iphdr->ttl == 1) {
      DEBUG_DETAIL("IP header has ttl 1\n");
      return PACKET_INTERESTING;
    }

    if (iphdr->daddr && 0xFF000000 == 0x7f000000) {
      DEBUG_DETAIL("Expected packet to be 127/8 address space\n");
      return PACKET_INTERESTING;
    }

    udphdr = (struct udphdr *)packet->udphdr;
    if (ntohs(udphdr->dest) == 3503) {
      DEBUG_DETAIL("Packet udp socket is 3503\n");
      return PACKET_INTERESTING;
    }
  } else {
    DEBUG_DETAIL("IPv6 packet\n");
    struct ipv6hdr *ip6hdr = (struct ipv6hdr *)packet->ip6hdr;

    if (ip6hdr->hop_limit == 1) {
      DEBUG_DETAIL("IPv6 header has ttl 1");
      return PACKET_INTERESTING;
    }

    return PACKET_INTERESTING;
  }

  return PACKET_NOT_INTERESTING;
}

void
mpls_daemon_create_sockets (void)
{
  int count = 0;
  struct ifaddrs *addrs, *tmp;
  struct ifreq ifr;
  struct sockaddr_ll sll;

  getifaddrs(&addrs);
  tmp = addrs;

  /*
   * Figure out how many interfaces we are going to have
   * so that we can dynamically create sockets for each one
   */
  while (tmp) {
    if ((tmp->ifa_addr->sa_family == AF_PACKET) && (strncmp(tmp->ifa_name, "swp", 3) == 0)) {
      count++;
    }
    tmp = tmp->ifa_next;
  }

  sockets = malloc(sizeof(int_sockets) * count);
  socket_number = count;
  count = 0;
  tmp = addrs;

  while (tmp) {
    if ((tmp->ifa_addr->sa_family == AF_PACKET) && (strncmp(tmp->ifa_name, "swp", 3) == 0)) {

      strcpy(sockets[count].ifname, tmp->ifa_name);
      sockets[count].socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
      if ( sockets[count].socket < 0 ) {
	DEBUG_DETAIL("Interface %s\n", tmp->ifa_name);
	perror("Failure to create socket\n");
	exit(-1);
      }

      memset(&ifr, 0, sizeof(ifr));
      snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), tmp->ifa_name);

      if ((ioctl(sockets[count].socket, SIOCGIFINDEX, &ifr)) == -1) {
	DEBUG_DETAIL("Interface %s\n", tmp->ifa_name);
	perror("Unable to find inteface index\n");
	exit(-1);
      }

      mpls_packet_retrieve_intf_mac(sockets[count].socket, sockets[count].ifname, sockets[count].mac);

      unsigned char *mac = sockets[count].mac;
      DEBUG_DETAIL("mac: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx for socket %d %s\n ",
	     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], sockets[count].socket, sockets[count].ifname);

      sll.sll_family = AF_PACKET;
      sll.sll_ifindex = ifr.ifr_ifindex;
      sockets[count].ifindex = ifr.ifr_ifindex;
      sll.sll_protocol = htons(ETH_P_ALL);

      if ((bind(sockets[count].socket, (struct sockaddr *)&sll, sizeof(sll))) == -1) {
	DEBUG_DETAIL("Interface: %s\n", tmp->ifa_name);
	perror("Bind failures\n");
	exit(-1);
      }
      count++;
    }
    tmp = tmp->ifa_next;
  }

  INFO("Opened %d sockets for reading/writing\n", count);
  freeifaddrs(addrs);
}

static void
mpls_daemon_send_packet (uint32_t sockfd, unsigned int ifindex, unsigned char *nh_mac,
			 unsigned char *buffer, int length)
{
  struct sockaddr_ll addr;
  
  memset(&addr, 0, sizeof(struct sockaddr_ll));
  addr.sll_family   = AF_PACKET;
  addr.sll_ifindex  = ifindex;
  addr.sll_halen    = ETH_ALEN;
  memcpy(addr.sll_addr, nh_mac, ETH_ALEN);

  DEBUG("Sending packet to ifindex: %d length %d\n", ifindex, length);
  if (sendto(sockfd, buffer, length, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_ll)) <= 0)
    {
      DEBUG("Unable to send packet %d", errno);
    }
}

/*
 * mpls_daemon_get_dest_port
 *
 * The source port for the incoming packet becomes the dest port
 * for the outgoing packet
 */
static uint32_t
mpls_daemon_get_dest_port (packet_peeker *packet)
{
  struct udphdr *uhdr = (struct udphdr *)packet->udphdr;

  return ntohs(uhdr->source);
}

static uint32_t
mpls_daemon_get_sender_handle (packet_peeker *packet)
{
  mpls_ping_packet *pdata = (mpls_ping_packet *)packet->udpdata;

  return ntohl(pdata->sender_handle);
}

static uint32_t
mpls_daemon_get_seqno (packet_peeker *packet)
{
  mpls_ping_packet *pdata = (mpls_ping_packet *)packet->udpdata;

  return ntohl(pdata->seq_number);
}

static void
mpls_daemon_get_sender_tv (packet_peeker *packet, struct timeval *tv)
{
  ntp_time_t ntp;

  mpls_ping_packet *pdata = (mpls_ping_packet *)packet->udpdata;

  ntp.seconds  = ntohl(pdata->secs_sent);
  ntp.fraction = ntohl(pdata->msecs_sent);

  mpls_util_ntp_to_unix_time(&ntp, tv);
}

/*
 * mpls_daemon_send_reply_packet
 *
 * Sending an MPLS Echo Reply
 *
 * An MPLS echo reply is a UDP packet.  It MUST ONLY be sent in response
 * to an MPLS echo request.  The source IP address is a routable address
 * of the replier; the source port is the well-known UDP port for LSP
 * ping.  The destination IP address and UDP port are copied from the
 * source IP address and UDP port of the echo request.  The IP TTL is
 * set to 255.  If the Reply Mode in the echo request is "Reply via an
 * IPv4 UDP packet with Router Alert", then the IP header MUST contain
 * the Router Alert IP option.  If the reply is sent over an LSP, the
 * topmost label MUST in this case be the Router Alert label (1) (see
 * [LABEL-STACK]).
 *
 * The format of the echo reply is the same as the echo request.  The
 * Sender's Handle, the Sequence Number, and TimeStamp Sent are copied
 * from the echo request; the TimeStamp Received is set to the time-of-
 * day that the echo request is received (note that this information is
 * most useful if the time-of-day clocks on the requester and the
 * replier are synchronized).  The FEC Stack TLV from the echo request
 * MAY be copied to the reply.
 *
 * The replier MUST fill in the Return Code and Subcode, as determined
 * in the previous subsection.
 *
 * If the echo request contains a Pad TLV, the replier MUST interpret
 * the first octet for instructions regarding how to reply.
 *
 * If the replying router is the destination of the FEC, then Downstream
 * Mapping TLVs SHOULD NOT be included in the echo reply.
 *
 * If the echo request contains a Downstream Mapping TLV, and the
 * replying router is not the destination of the FEC, the replier SHOULD
 * compute its downstream routers and corresponding labels for the
 * incoming label, and add Downstream Mapping TLVs for each one to the
 * echo reply it sends back.
 *
 * If the Downstream Mapping TLV contains Multipath Information
 * requiring more processing than the receiving router is willing to
 * perform, the responding router MAY choose to respond with only a
 * subset of multipaths contained in the echo request Downstream
 * Mapping.  (Note: The originator of the echo request MAY send another
 * echo request with the Multipath Information that was not included in
 * the reply.)
 *
 * Except in the case of Reply Mode 4, "Reply via application level
 * control channel", echo replies are always sent in the context of the
 * IP/MPLS network.
 *
 */
static void
mpls_daemon_send_reply_packet (packet_peeker *packet)
{
  unsigned char buffer[1000];
  char buf1[40], buf2[40], buf3[40], buf4[40];
  uint32_t length = 1000;
  address daddr;
  route   route;
  uint32_t dport;
  char ifname[40], ilm_ifname[40];
  uint32_t ifindex = 0;
  uint32_t seqno;
  uint32_t sender_handle;
  mpls_label_stack *ls = NULL;
  struct timeval stv, rtv;
  int connected;
  mac_info nh;
  mac_info local;
  uint32_t mtu = MPLS_DS_MTU_DEFAULT;
  uint32_t use_mpls = 0;

  INFO("Sending Reply Packet ");
  memset(buffer, 0, 1000);
  /*
   * Where should I send the response to?
   */
  dport = mpls_daemon_get_dest_port(packet);
  seqno = mpls_daemon_get_seqno(packet);
  sender_handle = mpls_daemon_get_sender_handle(packet);
  mpls_packet_get_src_addr(packet, &daddr);
  if (!mpls_network_get_route(&daddr, &route)) {
    DEBUG("Unable to retrieve route for %s\n",
	  inet_ntop(daddr.af, (void *)&daddr.u.v32, buf1, 40));
    return;
  }
  connected = mpls_network_get_connected(&daddr);
  mpls_network_get_intf(&daddr, ifname, connected);
  if (!connected) {
    if (!mpls_network_get_nexthop(&daddr, ifname, &nh.addr)) {
      DEBUG("Unable to get nexthop for %s\n",
	    inet_ntop(daddr.af, (void *)&daddr.u.v32, buf1, 40));
      return;
    }
  } else {
    /*
     * What?  If we are connected the destination is this dude
     */
    nh.addr = daddr;
  }

  mpls_daemon_get_sender_tv(packet, &stv);
  gettimeofday(&rtv, NULL);
  ls = mpls_packet_get_label(&route, ifname, 255);

  INFO("To Address: %s, Nexthop: %s from incoming interface %s\n",
       inet_ntop(daddr.af, (void *)&daddr.u.v32, buf1, 40),
       inet_ntop(nh.addr.af, (void *)&nh.addr.u.v32, buf2, 40),
       ifname);
  INFO("for label %s decided by route: %s/%d\n",
       mpls_label_print_ls(ls, buf3, 40),
       inet_ntop(route.addr.af, (void *)&route.addr.u.v32, buf4, 40),
       route.prefix);

  mpls_packet_retrieve_local_address(&daddr, &local.addr, &use_mpls);
  mpls_packet_retrieve_macs(ifname, &nh, local.mac, &ifindex, 0);

  /*
   * If packet->ilm == NULL then we know we are at the end of the chain,
   * There is no mtu to send back for an outgoing link, so just send
   * the default since it won't be displayed.
   */
  if (packet->ilm) {
    mpls_network_get_intf(&packet->ilm->nh, ilm_ifname, 1);
    mtu = mpls_packet_retrieve_intf_mtu(ilm_ifname);
  }
  INFO("OIfname: %s, laddr: %s nh: %s, lmac: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx nhmac: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx connected: %d mtu: %d use_mpls: %d\n",
       ilm_ifname, inet_ntop(local.addr.af, (void *)&local.addr.u.v32, buf1, 40),
       inet_ntop(nh.addr.af, (void *)&nh.addr.u.v32, buf2, 40),
       local.mac[0], local.mac[1], local.mac[2], local.mac[3], local.mac[4], local.mac[5],
       nh.mac[0], nh.mac[1], nh.mac[2], nh.mac[3], nh.mac[4], nh.mac[5], connected, mtu, use_mpls);

  length = mpls_packet_build_packet(buffer, length, &local, &daddr,
				    &nh, ls, seqno, sender_handle,
				    dport, 3503, &route, MPLS_ECHO_REPLY,
				    MPLS_REPLY_PACKET, packet->ret_code,
				    packet->subret_code, &stv, &rtv, use_mpls,
				    (packet->replymode == MPLS_REPLY_PACKET_RA),
				    1, packet->ilm, mtu);

  mpls_daemon_send_packet(packet->sock_fd, ifindex, nh.mac, buffer,length);

  ls = mpls_label_free_stream(ls);
}

/*
 * mpls_daemon_egress_processing
 *
 *  5. Egress Processing:
 *
 *    // These steps are performed by the LSR that identified itself
 *    //   as the tail-end LSR for an LSP.
 *
 *    If received echo request contains no Downstream Mapping TLV, or
 *       the Downstream IP Address is set to 127.0.0.1 or 0::1
 *          go to step 6 (Egress FEC Validation).
 *
 *    Verify that the IP address, interface address, and label stack in
 *    the Downstream Mapping TLV match Interface-I and Stack-R.  If
 *    not, set Best-return-code to 5, "Downstream Mapping
 *    Mis-match".  A Received Interface and Label Stack TLV SHOULD be
 *    created for the echo response packet.  Go to step 7 (Send Reply
 *    Packet).
 *
 */
static void
mpls_daemon_egress_processing (packet_peeker *packet)
{
  mpls_daemon_send_reply_packet(packet);
  DEBUG("%s\n", __FUNCTION__);

}

/*
 * mpls_daemon_label_operation_check
 *
 * 4. Label Operation Check
 *
 *    If the label operation is "Pop and Continue Processing" {
 *
 *    // Includes Explicit Null and Router Alert label cases
 *
 *       Iterate to the next label by decrementing Label-stack-depth
 *       and loop back to step 3 (Label Validation).
 *    }
 *
 *    If the label operation is "Swap or Pop and Switch based on Popped
 *       Label" {
 *
 *       Set Best-return-code to 8 ("Label switched at stack-depth")
 *       and Best-rtn-subcode to Label-stack-depth to report transit
 *       switching.
 *
 *       If a Downstream Mapping TLV is present in the received echo
 *       request {
 *
 *          If the IP address in the TLV is 127.0.0.1 or 0::1 {
 *             Set Best-return-code to 6 ("Upstream Interface Index
 *             Unknown").  An Interface and Label Stack TLV SHOULD be
 *             included in the reply and filled with Interface-I and
 *             Stack-R.
 *          }
 *
 *          Else {
 *
 *             Verify that the IP address, interface address, and label
 *             stack in the Downstream Mapping TLV match Interface-I
 *             and Stack-R.  If there is a mismatch, set
 *             Best-return-code to 5, "Downstream Mapping Mismatch".
 *             An Interface and Label Stack TLV SHOULD be included in
 *             the reply and filled in based on Interface-I and
 *             Stack-R.  Go to step 7 (Send Reply Packet).
 *          }
 *       }
 *
 *       For each available downstream ECMP path {
 *
 *          Retrieve output interface from the NHLFE entry.
 *
 *          // Note: this return code is set even if Label-stack-depth
 *           //   is one 
 *
 *            If the output interface is not MPLS enabled {
 *
 *             Set Best-return-code to Return Code 9, "Label switched
 *             but no MPLS forwarding at stack-depth" and set
 *             Best-rtn-subcode to Label-stack-depth and goto
 *             Send_Reply_Packet.
 *          }
 *
 *          If a Downstream Mapping TLV is present {
 *
 *            A Downstream Mapping TLV SHOULD be included in the echo
 *            reply (see section 3.3) filled in with information about
 *            the current ECMP path.
 *          }
 *       }
 *
 *       If no Downstream Mapping TLV is present, or the Downstream IP
 *          Address is set to the ALLROUTERS multicast address,
 *             go to step 7 (Send Reply Packet).
 *
 *       If the "Validate FEC Stack" flag is not set and the LSR is not
 *       configured to perform FEC checking by default, go to step 7
 *       (Send Reply Packet).
 *
 *       // Validate the Target FEC Stack in the received echo request.
 *
 *       First determine FEC-stack-depth from the Downstream Mapping
 *       TLV.  This is done by walking through Stack-D (the Downstream
 *       labels) from the bottom, decrementing the number of labels
 *       for each non-Implicit Null label, while incrementing
 *       FEC-stack-depth for each label.  If the Downstream Mapping TLV
 *       contains one or more Implicit Null labels, FEC-stack-depth
 *       may be greater than Label-stack-depth.  To be consistent with
 *       the above stack-depths, the bottom is considered to entry 1.
 *
 *       Set FEC-stack-depth to 0.  Set i to Label-stack-depth.
 *
 *       While (i > 0 ) do {
 *          ++FEC-stack-depth.
 *          if Stack-D[FEC-stack-depth] != 3 (Implicit Null)
 *             --i.
 *       }
 *
 *       If the number of labels in the FEC stack is greater
 *          than or equal to FEC-stack-depth {
 *
 *          Perform the FEC Checking procedure (see subsection 4.4.1
 *          below).
 *
 *          If FEC-status is 2, set Best-return-code to 10 ("Mapping
 *          for this FEC is not the given label at stack-depth").
 *
 *          If the return code is 1, set Best-return-code to
 *          FEC-return-code and Best-rtn-subcode to FEC-stack-depth.
 *       }
 *
 *       Go to step 7 (Send Reply Packet).
 *    }
 *
 */
void mpls_daemon_label_operation_check(packet_peeker *packet)
{
  uint32_t label_operation;

  DEBUG_DETAIL("%s\n", __FUNCTION__);

  label_operation = mpls_label_get_label_operation(packet->ilm);

  DEBUG_DETAIL("%s operation: %d\n", __FUNCTION__, label_operation);
  if (label_operation == MPLS_LABEL_POP_AND_CONTINUE_PROCESSING) {
    packet->label_stack_depth--;
    mpls_daemon_label_stack_validation(packet);
  }

  if (label_operation == MPLS_LABEL_SWAP_OR_POP_AND_SWITCH) {
    packet->ret_code = MPLS_LABEL_SWITCHED_AT_DEPTH;
    packet->subret_code = packet->label_stack_depth;
    mpls_daemon_debug_ret_codes(packet);
    if (mpls_packet_downstream_mapping_present(packet)) {
    }

    mpls_daemon_egress_processing(packet);
  }
}

/*
 * mpls_daemon_label_stack_validation
 *
 * 3. Label Validation:
 *
 *    If Label-stack-depth is 0 {
 *
 *    // The LSR needs to report its being a tail-end for the LSP
 *
 *       Set FEC-stack-depth to 1, set Label-L to 3 (Implicit Null).
 *        Set Best-return-code to 3 ("Replying router is an egress for
 *        the FEC at stack depth"), set Best-rtn-subcode to the
 *        value of FEC-stack-depth (1) and go to step 5 (Egress
 *        Processing).
 *     }
 *
 *    // This step assumes there is always an entry for well-known
 *     //   label values 
 *
 *    Set Label-L to the value extracted from Stack-R at depth
 *    Label-stack-depth.  Look up Label-L in the Incoming Label Map
 *    (ILM) to determine if the label has been allocated and an
 *    operation is associated with it.
 *
 *    If there is no entry for L {
 *
 *    // Indicates a temporary or permanent label synchronization
 *    //   problem the LSR needs to report an error 
 *
 *        Set Best-return-code to 11 ("No label entry at stack-depth")
 *       and Best-rtn-subcode to Label-stack-depth.  Go to step 7
 *       (Send Reply Packet).
 *    }
 *
 *    Else {
 *
 *       Retrieve the associated label operation from the
 *       corresponding NLFE and proceed to step 4 (Label Operation
 *       check).
 *      }
 *
 */
static void
mpls_daemon_label_stack_validation (packet_peeker *packet)
{
  mpls_label_ilm *ilm;
  DEBUG("%s for packet\n", __FUNCTION__);

  if (packet->label_stack_depth == 0) {
    DEBUG_DETAIL("%s No label stack, egress Processing\n", __FUNCTION__)

    packet->fec_stack_depth = 1;
    packet->labell = 3;
    packet->ret_code = MPLS_FEC_EGRESS;
    packet->subret_code = packet->fec_stack_depth;
    mpls_daemon_debug_ret_codes(packet);
    mpls_daemon_egress_processing(packet);
    return;
  }

  packet->labell = mpls_label_stack_value_at_depth(packet->ls, packet->label_stack_depth);

  ilm = mpls_label_lookup_ilm(packet->labell);
  DEBUG_DETAIL("%s: fec_stack_depth: %d labell: %d\n", __FUNCTION__,
	       packet->fec_stack_depth, packet->labell);

  if (!ilm) {
    DEBUG("%s No Label at Depth\n", __FUNCTION__);
    packet->ret_code = MPLS_NO_LABEL_AT_DEPTH;
    packet->subret_code = packet->fec_stack_depth;
    mpls_daemon_debug_ret_codes(packet);
    mpls_daemon_egress_processing(packet);
    return;
  }

  packet->ilm = ilm;
  mpls_daemon_label_operation_check(packet);
}

/*
 * mpls_daemon_start_receving
 *
 * Create sockets and start listening for incoming data
 *
 */
void
mpls_daemon_start_receiving (void)
{
  struct timeval tv_sent;
  fd_set active_fd_set, read_fd_set;
  int high_fd = 0;
  int i;
  packet_peeker packet;

  memset(&packet, 0, sizeof(packet));

  /*
   * Shouldn't this be AF_MPLS?
   *
   * Not necessarily because the packet may still reach us if the
   * label has been popped and forwarded to us.
   */
  mpls_daemon_create_sockets();

  FD_ZERO(&active_fd_set);
  for (i=0; i < socket_number; i++) {
    if (sockets[i].socket > high_fd) {
      high_fd = sockets[i].socket;
    }
    FD_SET(sockets[i].socket, &active_fd_set);
  }

  high_fd++;
  /*
   * Let's setup our reverse search from sock_to_ifindex
   */
  sock_to_int_socks = malloc(sizeof(int)*high_fd);
  if (!sock_to_int_socks) {
    perror("Malloc Failure reverse lookup\n");
    exit(-1);
  }

  for (i=0; i < socket_number; i++) {
    sock_to_int_socks[sockets[i].socket] = i;
  }

  while(1) {
    read_fd_set = active_fd_set;
    if (select(high_fd, &read_fd_set, NULL, NULL, NULL) < 0) {
      perror("Select failed\n");
      exit(-1);
    }

    DEBUG_DETAIL("%s Received incoming packet checking FD: \n", __FUNCTION__);
    for (i=0; i < high_fd; i++) {
      if (FD_ISSET(i, &read_fd_set)) {
	mpls_packet_clean(&packet);
	packet.length  = read(i, &packet.stream, PACKET_SIZE);
 
	DEBUG_DETAIL("\nRead bytes: %d on %d %s", packet.length, i, sockets[sock_to_int_socks[i]].ifname);
	packet.sock_fd = i;
	packet.ifindex = sock_to_int_socks[i];
	/*
	 * If the parsing of the data structure fails then this is not
	 * a mpls ping packet of some sort.
	 */
	if (mpls_daemon_packet_interesting(&packet) != PACKET_INTERESTING) {
	  continue;
	}

	DEBUG_DETAIL(" Parsed\n");

	if (packet.replymode != MPLS_NO_REPLY) {
	  uint8_t ret_code;
	  ret_code = mpls_daemon_packet_sanity(&packet);
	  if (ret_code != MPLS_NO_RETURN_CODE) {
	    DEBUG_DETAIL("Packet is not sane: %d\n", ret_code);
	    packet.ret_code = ret_code;
	    packet.subret_code = 0;
	  } else {
	    packet.label_stack_depth = mpls_label_stack_depth(packet.ls);
	    mpls_daemon_label_stack_validation(&packet);
	  }
	} else {
	  /*
	   * An MPLS echo request with 1 (Do not reply) in the Reply Mode field
	   * may be used for one-way connectivity tests; the receiving router may
	   * log gaps in the Sequence Numbers and/or maintain delay/jitter
	   * statistics.
	   *
	   */
	  address sender;
	  uint32_t seq_no;
	  mpls_ping_packet *mpp;
	  struct timeval now;
	  struct timeval result;
	  char buf1[40];

	  mpp = (mpls_ping_packet *)packet.udphdr;
	  seq_no = ntohl(mpp->seq_number);
	  gettimeofday(&now, NULL);
	  mpls_packet_get_time_sent(&packet, &tv_sent);
	  mpls_packet_get_src_addr(&packet, &sender);
	  mpls_util_timeval_subtract(&result, &now, &tv_sent);
	  DEBUG("Received packet from %s, seq_no: %d packet received in %ld.%3ld\n",
		inet_ntop(sender.af, (void *)&sender.u.v32, buf1, 40), seq_no,
		result.tv_sec, result.tv_usec * 1000);
	}
      }
    }
  }
}

int
main (int argc, char *argv[])
{
  pid_t pid;
  int c;
  int daemonize = 0;
  char *logfile;

  while ((c = getopt(argc, argv, "dvVf:")) != -1) {
    switch(c) {
    case 'f':
      logfile = optarg;
      break;
    case 'd':
      daemonize = 1;
      break;
    case 'v':
      debug = 1;
      break;
    case 'V':
      debug = 1;
      debug_detail =1;
      break;
    default:
      printf("Specified option %c is unknown\n", c);
      exit(-1);
    }
  }

  if (!logfile) {
    lf = stdout;
  } else {
    lf = fopen(logfile, "w+");
    if (!lf) {
      printf("Unable to open log file for writing\n");
      exit(-1);
    }
  }

  INFO("Daemon for listening to all incoming MPLS ping/traceroute packets\n");

  if (daemonize) {
    pid = fork();
    if (pid == -1) {
      perror("Danger Will-Robinson!  Unable to fork\n");
      exit(-1);
    }

    if (pid != 0) {
      DEBUG_DETAIL("Child successfully started\n");
      exit(0);
    }
  }

  mpls_daemon_start_receiving();

  exit(0);
}

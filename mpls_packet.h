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
#if !defined(__MPLS_PACKET_H__)
#define __MPLS_PACKET_H__

struct mpls_label_stack;
#define PACKET_SIZE 10000

typedef struct packet_peeker_ {
  unsigned char stream[PACKET_SIZE];
  uint32_t length;
  unsigned char *ethhdr;
  unsigned char *lhdr;
  unsigned char *iphdr;
  unsigned char *ip6hdr;
  unsigned char *udphdr;
  unsigned char *udpdata;
  unsigned char *tlvdata;

  mpls_label_stack *ls;

  uint32_t sock_fd;
  uint32_t ifindex;

  uint32_t fec_stack_depth;
  uint32_t label_stack_depth;
  uint32_t labell;
  uint32_t replymode;
  uint32_t ret_code;
  uint32_t subret_code;
  uint32_t best_ret_code;
  uint32_t best_subret_code;

  mpls_label_ilm *ilm;
  mpls_ping_tlv *tlv_fec_stack;
  mpls_downstream_mapping *tlv_downstream_mapping;
} packet_peeker;

#define MPLS_PACKET_IP_LEN_WORDS     5
#define MPLS_PACKET_IP_LEN_RA_WORDS  6
#define MPLS_PACKET_IP_LEN_BYTES     20
#define MPLS_PACKET_IP_LEN_RA_BYTES  24
#define MPLS_PACKET_IP6_LEN_BYTES    40
#define MPLS_PACKET_IP6_LEN_RA_BYTES 48

int mpls_packet_is_mpls(packet_peeker *packet);
int mpls_packet_parse_structures(packet_peeker *packet);

int mpls_packet_addr_retrieve(char *string, address *addr);

int mpls_packet_retrieve_local_address(address *dest, address *laddr, uint32_t *use_mpls);

void mpls_packet_build_udp_header(unsigned char *buffer, int length, uint16_t dport, uint16_t sport);
void mpls_packet_build_udp_header_cksum(unsigned char *stream_udphdr,
					unsigned char *stream_iphdr,
					unsigned char *data, uint32_t len);
void mpls_packet_build_ip_header(unsigned char *buffer, address *saddr,
				 address *daddr, int length, int ra);
void mpls_packet_build_ip6_header(unsigned char *buffer, address *saddr,
				  address *daddr, int length, int ra);
void mpls_packet_build_mac_header(unsigned char *buffer,
				  unsigned char dest[ETH_ALEN],
				  unsigned char src[ETH_ALEN],
				  uint16_t protocol);
unsigned int
mpls_packet_build_packet (unsigned char *buffer, int length, mac_info *source,
			  address *daddr, mac_info *nh,
			  mpls_label_stack *ls, uint32_t seqno,
			  uint32_t sender_handle, uint16_t dport, uint16_t sport,
			  route *route, uint32_t msgtype, uint32_t replymode,
			  uint32_t rcode, uint32_t rsubcode, 
			  struct timeval *stv, struct timeval *rtv, int include_ls,
			  int include_ra, int downstream_mapping, mpls_label_ilm *ilm,
			  uint32_t mtu);

void mpls_packet_get_src_addr(packet_peeker *packet , address *addr);

int mpls_packet_get_labeled_route(address *addr, route *route);
int mpls_packet_get_route(address *addr, route *route);
int mpls_packet_get_labeled_nexthop(address *addr, char *intf, address *nh);
int mpls_packet_get_labeled_intf(address *addr, char *intf);

mpls_label_stack *mpls_packet_get_label(route *route, char *intf, uint32_t ttl);

int mpls_packet_retrieve_intf_mac(int s, char *interface, unsigned char *mac);
uint32_t mpls_packet_retrieve_intf_mtu(char *interface);

int mpls_packet_retrieve_macs(char *interface, mac_info *nh,
			      unsigned char *local_mac,
			      unsigned int *ifindex, int connected);

void mpls_packet_get_time_sent(packet_peeker *packet, struct timeval *time);
uint32_t mpls_packet_get_return_code(packet_peeker *packet);
uint32_t mpls_packet_get_sub_return_code(packet_peeker *packet);

uint32_t mpls_packet_downstream_mapping_present(packet_peeker *packet);

char *mpls_packet_print_ret_code_info(packet_peeker *packet, char *buff);

uint32_t mpls_packet_parse_tlv(packet_peeker *packet);

void mpls_packet_clean(packet_peeker *packet);

uint32_t mpls_packet_get_downstream_mtu(packet_peeker *packet);
uint32_t mpls_packet_get_downstream_label(packet_peeker *packet);
#endif

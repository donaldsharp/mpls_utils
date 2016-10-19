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
#if !defined(__MPLS_NETWORK_H__)
#define __MPLS_NETWORK_H__

#include <linux/if_ether.h>

struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8                    priority:4,
                                version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
        __u8                    version:4,
                                priority:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
        __u8                    flow_lbl[3];

        __be16                  payload_len;
        __u8                    nexthdr;
        __u8                    hop_limit;

        struct  in6_addr        saddr;
        struct  in6_addr        daddr;
};


struct ipv6_opt_hdr {
        __u8            nexthdr;
        __u8            hdrlen;
        /* 
         * TLV encoded option data follows.
         */
} __attribute__((packed));      /* required for some archs */

typedef struct address_ {
  int af;
  uint8_t prefix;
  union {
    unsigned int  v32;
    struct in_addr v4;
    struct in6_addr v6;
  } u;
} address;

typedef struct route_ {
  address addr;
  uint32_t prefix;
} route;

typedef struct mac_info_ {
  address addr;
  unsigned char mac[ETH_ALEN];
} mac_info;

int mpls_network_addr_retrieve(char *string, address *addr);
void mpls_network_get_intf(address *addr, char *intf, int connected);
int mpls_network_get_connected(address *addr);
int mpls_network_get_nexthop(address *addr, char *intf, address *nh);
int mpls_network_get_route(address *addr, route *route);

#endif

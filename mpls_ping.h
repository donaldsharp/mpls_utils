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
#if !defined(__MPLS_PING_H__)
#define __MPLS_PING_H__
#include <stdint.h>
#include <netinet/in.h>

#define PACKED __attribute__ ((__packed__))

/*
 * TLV format, Section 3, RFC 4379
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |             Type              |            Length             |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                             Value                             |
 *    .                                                               .
 *    .                                                               .
 *    .                                                               .
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct PACKED mpls_ping_tlv_ {
  uint16_t type;
  uint16_t length;
  uint8_t  data[0];
} mpls_ping_tlv;

/*
 *
 * A description of the Types and Values of the top-level TLV's
 * for LSP ping are given below:
 *
 */
typedef enum mpls_tlv_types_ {
  MPLS_TLV_TYPE_FEC_STACK = 1,
  MPLS_TLV_TYPE_DOWNSTREAM_MAPPING,
  MPLS_TLV_TYPE_PAD,
  MPLS_TLV_NOT_ASSIGNED1,
  MPLS_TLV_VENDOR_ENT_NUM,
  MPLS_TLV_NOT_ASSIGNED2,
  MPLS_TLV_INT_AND_LABEL_STACK,
  MPLS_TLV_NOT_ASSIGNED3,
  MPLS_TLV_ERRORED_TLVS,
  MPLS_TLV_REPLY_TOS_BYTE,
} mpls_tlv_types;

/*
 * Types less than 32768 are mandatory TLV's
 * that MUST either be supported by an
 * implementation or result in the return code of 2
 *
 * Types greater than 32768 SHOULD be ignored if the
 * implementation does not understand or support them.
 *
 */
#define MPLS_TLV_MUST_UNDERSTAND 32768


/*
 * 3.2 Target FEC Stack
 *
 * A Target FEC statck is a list of sub-TLVs.  The number of 
 * elements is determined by looking at the sub-TLV-length fields
 *
 */
#define MPLS_TFS_LDP_V4_PREFIX_ST         1
#define MPLS_TFS_LDP_V4_PREFIX_L          5
#define MPLS_TFS_LDP_V6_PREFIX_ST         2
#define MPLS_TFS_LDP_V6_PREFIX_L         17
#define MPLS_TFS_RSVP_V4_LSP_PREFIX_ST    3
#define MPLS_TFS_RSVP_V4_LSP_PREFIX_L    20
#define MPLS_TFS_RSVP_V6_LSP_PREFIX_ST    4
#define MPLS_TFS_RSVP_V6_LSP_PREFIX_L    56
#define MPLS_TFS_VPN_V4_PREFIX_ST         6
#define MPLS_TFS_VPN_V4_PREFIX_L         13
#define MPLS_TFS_VPN_V6_PREFIX_ST         7
#define MPLS_TFS_VPN_V6_PREFIX_L         25
#define MPLS_TFS_L2_VPN_END_ST            8
#define MPLS_TFS_L2_VPN_END_L            14
#define MPLS_TFS_FEC_128_DEP_ST           9
#define MPLS_TFS_FEC_128_DEP_L           10
#define MPLS_TFS_FEC_128_ST              10
#define MPLS_TFS_FEC_128_L               14
#define MPLS_TFS_FEC_129_ST              11
#define MPLS_TFS_FEC_129_L               16
#define MPLS_TFS_BGP_V4_PREFIX_ST        12
#define MPLS_TFS_BGP_V4_PREFIX_L          5
#define MPLS_TFS_BGP_V6_PREFIX_ST        13
#define MPLS_TFS_BGP_V6_PREFIX_L         17
#define MPLS_TFS_GEN_V4_PREFIX_ST        14
#define MPLS_TFS_GEN_V4_PREFIX_L          5
#define MPLS_TFS_GEN_V6_PREFIX_ST        15
#define MPLS_TFS_GEN_V6_PREFIX_L         17
#define MPLS_TFS_NIL_FEC_ST              16
#define MPLS_TFS_NIL_FEC_L                4

/*
 *
 * Packet format for a UDP packet.  Section 3, RFC 4379
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |         Version Number        |         Global Flags          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |  Message Type |   Reply mode  |  Return Code  | Return Subcode|
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        Sender's Handle                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        Sequence Number                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                    TimeStamp Sent (seconds)                   |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                  TimeStamp Sent (microseconds)                |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                  TimeStamp Received (seconds)                 |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                TimeStamp Received (microseconds)              |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                            TLVs ...                           |
 *    .                                                               .
 *    .                                                               .
 *    .                                                               .
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct PACKED mpls_ping_packet_ {
  uint16_t version;
  uint16_t gflags;
  uint8_t  msgtype;
  uint8_t  replymode;
  uint8_t  rcode;
  uint8_t  rsubcode;
  uint32_t sender_handle;
  uint32_t seq_number;
  uint32_t secs_sent;
  uint32_t msecs_sent;
  uint32_t secs_received;
  uint32_t msecs_received;
  mpls_ping_tlv  tlv[0];
} mpls_ping_packet;

#define MPLS_PING_VERSION_NUMBER 0x0001
 
/*
 * Global Flag Must be zero except for last bit
 * 16 bits of data
 */
#define GLOBAL_FLAG_V_FEC_VALIDATION    0x0001
#define GLOBAL_FLAG_V_NO_FEC_VALIDATION 0x0000

/*
 * Message Type must be either values
 * 8 bits of data
 */
#define MPLS_ECHO_REQUEST 0x1 
#define MPLS_ECHO_REPLY   0x2

/*
 * Reply mode values
 * 8 bits of data
 */
#define MPLS_NO_REPLY         0x01
#define MPLS_REPLY_PACKET     0x02
#define MPLS_REPLY_PACKET_RA  0x03
#define MPLS_REPLY_ALC        0x04

/*
 * Return codes as defined by section 3.1
 * 8 bits of data
 */
#define MPLS_NO_RETURN_CODE              0x00
#define MPLS_MALFORMED_ECHO_REQUEST      0x01
#define MPLS_TLV_NOT_UNDERSTOOD          0x02
#define MPLS_FEC_EGRESS                  0x03
#define MPLS_NO_FEC_MAPPING              0x04
#define MPLS_MAPPING_MISSMATCH           0x05
#define MPLS_UPSTREAM_INTERFACE_UNKNOWN  0x06
#define MPLS_RESERVED                    0x07
#define MPLS_LABEL_SWITCHED_AT_DEPTH     0x08
#define MPLS_LABEL_SWITCHED_NO_MPLS      0x09
#define MPLS_FEC_MAPPING_INCORRECT       0x0a
#define MPLS_NO_LABEL_AT_DEPTH           0x0b
#define MPLS_WRONG_PROTO_AT_DEPTH        0x0c
#define MPLS_PREMATURE_SHRINKAGE         0x0d

/*
 * 3.2.1 LDP IPv4 Prefix
 * 3.2.11 BGP Labeled IPv4 Prefix
 * 3.2.13 Generic IPv4 Prefix
 */
typedef struct PACKED mpls_ipv4_prefix_ {
  mpls_ping_tlv  tlv;
  struct in_addr ipv4_prefix;
  uint8_t        plength;
  uint8_t        zero1;        // Padding must be zero
  uint16_t       zero2;        // Padding again
} mpls_ipv4_prefix;

/*
 * 3.2.2 LDP IPv6 Prefix
 * 3.2.12 BGP Labeled IPv6 Prefix
 * 3.2.14 Generic IPv6 Prefix
 */
typedef struct PACKED mpls_ipv6_prefix_ {
  mpls_ping_tlv   tlv;
  struct in6_addr ipv6_prefix;
  uint8_t         plength;
  uint8_t         zero1;       // Padding must be zero
  uint16_t        zero2;       // Padding again
} mpls_ipv6_prefix;

/*
 * 3.2.3 RSVP IPv4 LSP
 */
typedef struct PACKED mpls_rsvp_ipv4_lsp_ {
  struct in_addr tunnel_end;
  uint16_t       zero1;
  uint16_t       tunnel_id;
  uint32_t       extended_tunnel_id;
  struct in_addr sender_address;
  uint16_t       zero2;
  uint16_t       lsp_id;
} mpls_rsvp_ipv4_lsp;

/*
 * 3.2.4 RSVP IPv6 LSP
 */
typedef struct PACKED mpls_rsvp_ipv6_lsp_ {
  struct in6_addr tunnel_end;
  uint16_t        zero1;
  uint16_t        tunnel_id;
  struct in6_addr extended_tunnel_id;
  struct in6_addr sender_address;
  uint16_t        zero2;
  uint16_t        lsp_id;
} mpls_rsvp_ipv6_lsp;

/*
 * 3.2.5 VPN IPv4 Prefix
 */
typedef struct PACKED mpls_vpn_ipv4_prefix_ {
  uint64_t       route_distinguisher;
  struct in_addr prefix;
  uint8_t        plength;
  uint8_t        zero1;
  uint16_t       zero2;
} mpls_vpn_ipv4_prefix;

/*
 * 3.2.6 VPN IPv6 Prefix
 */
typedef struct PACKED mpls_vpn_ipv6_prefix_ {
  uint64_t        route_distinguisher;
  struct in6_addr prefix;
  uint8_t         plength;
  uint8_t         zero1;
  uint16_t        zero2;
} mpls_vpn_ipv6_prefix;

/*
 * 3.2.7 L2 VPN Endpoint
 */
typedef struct PACKED mpls_l2_vpn_endpoint_ {
  uint64_t        route_distinguisher;
  uint16_t        senders_ve_id;
  uint16_t        receiver_ve_id;
  uint16_t        encap_type;
  uint16_t        zero;
} mpls_l2_vpn_endpoint;

/*
 * 3.2.8 FEC 128 Pseudowire (Deprecated)
 */
typedef struct PACKED mpls_fec_128_deprecated_ {
  struct in_addr  remote_pe_address;
  uint32_t        pw_id;
  uint16_t        pw_type;
  uint16_t        zero;
} mpls_fec_128_deprecated;

/*
 * 3.2.9 FEC 128 Pseudowire (Current)
 */
typedef struct PACKED mpls_fec_128_ {
  struct in_addr  sender_pe_address;
  struct in_addr  remote_pe_address;
  uint32_t        pw_id;
  uint16_t        pw_type;
  uint16_t        zero;
} mpls_fec_128;

/*
 * 3.2.10 FEC 129 Pseudowire
 * TODO : This is wrong, Need to subtype the aii_type... stuff to handle properly in
 *         packed structure.  Until it's implemented who cares?
 */
typedef struct PACKED mpls_fec_129_ {
  struct in_addr  sender_pe_address;
  struct in_addr  remote_pe_address;
  uint16_t        pw_type;
  uint8_t         agi_type;
  uint8_t         agi_length;
  uint8_t         agi_value[0];  /* Length specified in agi_length */
  uint8_t         aii_type1;
  uint8_t         saii_length;
  uint8_t         saii_value[0]; /* Length specified in saii_length */
  uint8_t         aii_type2;
  uint8_t         taii_length;
  uint8_t         taii_value[0]; /* Length specified in taii_length */
  uint8_t         zero[0];       /* 0-3 octets of zero padding */
} mpls_fec_129;

/*
 * 3.2.15 Nil FEC
 */
typedef struct PACKED mpls_nil_fec_ {
  uint32_t         label;        /* Last 12 bits must be zero */
} mpls_nil_fec;

/*
 * 3.3 Downstream Mapping
 * Deprecated by RFC 6424, in favor of a new TLV
 */
typedef struct PACKED mpls_multipath_information_ {
  uint8_t          type;
  uint8_t          depth_limit;
  uint16_t         length;
  uint8_t          data[0];
} mpls_multipath_information;

#define MPLS_DOWNSTREAM_PROTOCOL_UNKNOWN  0x00
#define MPLS_DOWNSTREAM_PROTOCOL_STATIC   0x01
#define MPLS_DOWNSTREAM_PROTOCOL_BGP      0x02
#define MPLS_DOWNSTREAM_PROTOCOL_LDP      0x03
#define MPLS_DOWNSTREAM_PROTOCOL_RSVPTE   0x04

#define MPLS_DS_ADDR_TYPE_IPV4_NUMBERED     1
#define MPLS_DS_ADDR_TYPE_IPV4_K            16
#define MPLS_DS_ADDR_TYPE_IPV4_UNNUMBERED   2
#define MPLS_DS_ADDR_TYPE_IPV6_NUMBERED     3
#define MPLS_DS_ADDR_TYPE_IPV6_NUMBERED_K   40
#define MPLS_DS_ADDR_TYPE_IPV6_UNNUMBERED   4
#define MPLS_DS_ADDR_TYPE_IPV6_UNNUMBERED_K 28

typedef struct PACKED mpls_downstream_mapping_ {
  mpls_ping_tlv     tlv;
  uint16_t          mtu;
  uint8_t           address_type;
  uint8_t           ds_flags;
  uint32_t          data[0];
} mpls_downstream_mapping;

#define MPLS_DS_MTU_DEFAULT 1500

/*
 * 3.3 Downstream Detailed Mapping
 * RFC 6424
 */

typedef struct PACKED mpls_downstream_ipv4_address_ {
  struct in_addr    downstream;
  struct in_addr    downstream_interface;
} mpls_downstream_ipv4_address;

typedef struct PACKED mpls_downstream_ipv6_address_ {
  struct in6_addr   downstream;
  struct in6_addr   downstream_interface;
} mpls_downstream_ipv6_address;

#define MPLS_MP_NONE                       0
#define MPLS_MP_IPV4                       2
#define MPLS_MP_IPV4_RANGE                 4
#define MPLS_MP_BIT_MASK_IP                8
#define MPLS_MP_BIT_MASK_LABEL             9

typedef struct PACKED mpls_downstream_multipath_ {
  uint8_t            mtype;
  uint8_t            dlimit;
  uint16_t           mlength;
  unsigned char      data[0];
} mpls_downstream_multipath;

typedef struct PACKED mpls_downstream_label_ {
  uint32_t hlabel:16;
#if defined(__LITTLE_ENDIAN_BITFIELD)
  uint32_t bos:1;
  uint32_t exp:3;
  uint32_t llabel:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
  uint32_t llabel:4;
  uint32_t exp:3;
  uint32_t bos:1;
#else
#error "Please fix endianess"
#endif
  uint32_t protocol:8;
} mpls_downstream_label;

#endif

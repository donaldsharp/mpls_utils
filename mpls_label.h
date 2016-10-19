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
#if !defined(__MPLS_LABEL_H__)
#define __MPLS_LABEL_H__
#include <asm/byteorder.h>

enum {
  MPLS_LABEL_ERROR,
  MPLS_LABEL_POP_AND_CONTINUE_PROCESSING,
  MPLS_LABEL_SWAP_OR_POP_AND_SWITCH,
};

struct mpls_label {
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
    uint32_t ttl:8;
} __attribute__((packed));

typedef struct mpls_label_stack_ {
  struct mpls_label_stack_ *next;
  union {
    struct mpls_label l;
    uint32_t l32;
  } u;
} mpls_label_stack;

typedef struct mpls_label_ilm_ {
  uint32_t incoming;
  uint32_t operation;
  address nh;
} mpls_label_ilm;

static inline uint32_t mpls_get_hdr_label(const struct mpls_label *label)
{
  return((ntohs(label->hlabel) << 4) | label->llabel);
}

static inline void mpls_set_hdr_label(struct mpls_label *label, uint32_t lvalue)
{
  label->hlabel = htons(lvalue >> 4);
  label->llabel = lvalue & 0xf;
}

void mpls_label_build_stream(unsigned char *buff, mpls_label_stack *ls);

unsigned char *mpls_label_read_stream(unsigned char *stream, mpls_label_stack **ls);

mpls_label_stack *mpls_label_add(mpls_label_stack *stack, uint32_t label,
				 uint8_t exp, uint8_t ttl);

int mpls_label_has_ttl_expiration(mpls_label_stack *stack);

int mpls_label_has_router_alert(mpls_label_stack *stack);

mpls_label_stack *mpls_label_free_stream(mpls_label_stack *ls);

uint32_t mpls_label_stack_depth(mpls_label_stack *stack);

uint32_t mpls_label_stack_value_at_depth(mpls_label_stack *stack, uint32_t depth);

mpls_label_ilm *mpls_label_lookup_ilm(uint32_t label);

uint32_t mpls_label_ls_size(mpls_label_stack *ls);

uint32_t mpls_label_get_label_operation(mpls_label_ilm *ilm);

char *mpls_label_print_info(uint32_t label, char *buff, int len);
char *mpls_label_print_ls(mpls_label_stack *ls, char *buff, int len);
#endif

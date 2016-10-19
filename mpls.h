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
#if !defined(__MPLS_H__)
#include <asm/byteorder.h>

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

struct mpls_label_stack {
  struct mpls_label_stack *next;
  union {
    struct mpls_label l;
    uint32_t l32;
  } u;
};

static inline uint32_t mpls_get_hdr_label(const struct mpls_label *label)
{
  return((ntohs(label->hlabel) << 4) | label->llabel);
}

static inline void mpls_set_hdr_label(struct mpls_label *label, uint32_t lvalue)
{
  label->hlabel = htons(lvalue >> 4);
  label->llabel = lvalue & 0xf;
}

struct mpls_label_stack *
mpls_add_label(struct mpls_label_stack *stack, uint32_t label,
	       uint8_t exp, uint8_t ttl);


#endif

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
#if !defined(__MPLS_UTIL_H__)
#define __MPLS_UTIL_H__

typedef struct ntp_time_t_ {
  uint32_t seconds;
  uint32_t fraction;
} ntp_time_t;

void mpls_util_ntp_to_unix_time(ntp_time_t *, struct timeval *);
void mpls_util_unix_to_ntp_time(struct timeval *, ntp_time_t *);

void mpls_util_timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y);

#endif

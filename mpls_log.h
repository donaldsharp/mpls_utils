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
#if !defined(__MPLS_LOG_H__)
#define __MPLS_LOG_H__

extern FILE *lf;
extern uint32_t debug;
extern uint32_t debug_detail;

#define INFO(fmt, args...) { fprintf(lf, fmt, ## args); fflush(lf); }
#define DEBUG(fmt, args...) if(debug) { fprintf(lf, fmt, ## args); fflush(lf); }
#define DEBUG_DETAIL(fmt, args...) if(debug_detail) { fprintf(lf, fmt, ## args); fflush(lf); }
#endif

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
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include "mpls_network.h"

int
mpls_network_addr_retrieve (char *string, address *addr)
{
  int result;

  result = inet_pton(AF_INET, string, &addr->u.v4);
  if (result < 1) {
    result = inet_pton(AF_INET6, string, &addr->u.v6);

    if (result < 1) {
      return(0);
    } else {
      addr->af = AF_INET6;
    }
  } else {
    addr->af = AF_INET;
  }
  return(1);
}

void
mpls_network_get_intf (address *addr, char *intf, int connected)
{
  FILE *fp;
  char buffer[1000];
  char buf1[100];

  if (connected) {
    sprintf(buffer, "vtysh -c \"show %s route %s\" | grep directly | cut -d \",\" -f 2 | cut -d \" \" -f 2 > /tmp/intf.tmp",
	    (addr->af == AF_INET) ? "ip" : "ipv6",
	    inet_ntop(addr->af, (void *)&addr->u.v32, buf1, 100));
  } else {
    sprintf(buffer, "vtysh -c \"show %s route %s\" | grep via | grep -v distance | cut -d \",\" -f 2 | cut -d \" \" -f 3 > /tmp/intf.tmp",
	    (addr->af == AF_INET) ? "ip" : "ipv6",
	    inet_ntop(addr->af, (void *)&addr->u.v32, buf1, 100));
  }
  system(buffer);

  fp = fopen("/tmp/intf.tmp", "r+");
  fscanf(fp, "%s", intf);
  fclose(fp);
  unlink("/tmp/intf.tmp");
}



int
mpls_network_get_connected (address *addr)
{
  FILE *fp;
  char buffer[1000];
  char buf1[100];
  char *sub;

  sprintf(buffer, "vtysh -c \"show %s route %s\" | grep \"directly connected\" | cut -d \" \" -f 5 | cut -d \",\" -f 1 > /tmp/connected.tmp",
	  (addr->af == AF_INET) ? "ip" : "ipv6",
	  inet_ntop(addr->af, (void *)&addr->u.v32, buf1, 100));

  system(buffer);

  fp = fopen("/tmp/connected.tmp", "r+");
  memset(buffer, 0, 1000);
  fscanf(fp, "%s", buffer);
  fclose(fp);
  unlink("/tmp/connected.tmp");

  sub = strstr(buffer, "connected");
  if (sub) {
    return(1);
  } else {
    return(0);
  }
}

int
mpls_network_get_nexthop (address *addr, char *intf, address *nh)
{
  FILE *fp;
  char buffer[1000];
  char buf1[100];

  sprintf(buffer, "vtysh -c \"show %s route %s\" | grep via | grep -v distance | grep %s | cut -d \",\" -f 1 | cut -d \" \" -f 4 > /tmp/nh.tmp",
	  (addr->af == AF_INET) ? "ip" : "ipv6",
	  inet_ntop(addr->af, (void *)&addr->u.v32, buf1, 100),
	  intf);

  system(buffer);

  fp = fopen("/tmp/nh.tmp", "r+");
  fscanf(fp, "%s", buffer);

  fclose(fp);
  unlink("/tmp/nh.tmp");
  if (!mpls_network_addr_retrieve(buffer, nh)) {
    return(0);
  } else {
    return(1);
  }
}

int
mpls_network_get_route (address *addr, route *route)
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
  sprintf(buffer, "vtysh -c \"show %s route %s\" | grep \"Routing\" | cut -d \" \" -f 4 > /tmp/route.tmp",
	  (addr->af == AF_INET) ? "ip" : "ipv6",
	  inet_ntop(addr->af, (void *)&addr->u.v32, buf1, 100));

  system(buffer);

  fp = fopen("/tmp/route.tmp", "r+");
  fscanf(fp, "%s" , buffer);

  address = strtok(buffer, "/");
  prefix = strtok(NULL, "/");

  sscanf(prefix, "%d", &route->prefix);
  
  fclose(fp);
  unlink("/tmp/route.tmp");
  if (!mpls_network_addr_retrieve(address, &route->addr)) {
    return(0);
  } else {
    return(1);
  }
}

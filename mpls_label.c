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
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <unistd.h>
#include <linux/ip.h>
#include "mpls_network.h"
#include "mpls_label.h"
#include "mpls_log.h"

/*
 * mpls_label_get_label_operation
 *
 * Given a ilm what is the label operation associated with it(nhlfe)
 * This is hardcoded currently.
 *
 */
uint32_t
mpls_label_get_label_operation (mpls_label_ilm *ilm) {
  switch(ilm->operation) {
  case 0:
  case 1:
  case 2:
    return MPLS_LABEL_POP_AND_CONTINUE_PROCESSING;
    break;
  default:
    return MPLS_LABEL_SWAP_OR_POP_AND_SWITCH;
    break;
  }

  return MPLS_LABEL_ERROR;            // Something has gone terribly wrong
}

/*
 * mpls_label_free_stream
 *
 * Clean up the label stream
 */
mpls_label_stack *
mpls_label_free_stream (mpls_label_stack *ls)
{
  int cont = 1;
  mpls_label_stack *iterate = ls;
  mpls_label_stack *next;

  if (ls == NULL) {
    return NULL;
  }

  next = iterate->next;

  while(cont) {
    free(iterate);
    iterate = next;
    if (iterate) {
      next = iterate->next;
    } else {
      cont = 0;
    }
  }
  return NULL;

}


/*
 * mpls_label_build_stream
 *
 * Given a label stack, generate the network ordered byte stream
 * from it.
 */
void
mpls_label_build_stream (unsigned char *buff, mpls_label_stack *ls)
{
  mpls_label_stack *iterate;
  unsigned char *stream;
  uint32_t bytes_written = 0;

  stream = buff;
  iterate = ls;
  while (iterate != NULL) {
    memcpy(stream, &iterate->u.l32, sizeof(struct mpls_label));
    bytes_written += sizeof(struct mpls_label);
    stream = buff + bytes_written;
    iterate = iterate->next;
  }

  return;
}

/*
 * mpls_label_read_stream
 *
 * Given a stream of bytes convert to labels
 * This code assumes that the passed in poiner 
 * in stream is already correctly set and
 * the label_stack has correctly set the BOS bit
 */
unsigned char *
mpls_label_read_stream(unsigned char *stream, mpls_label_stack **labels)
{
  int cont = 1;
  mpls_label_stack *iterate = NULL;
  mpls_label_stack *top = NULL;
  mpls_label_stack *ls = NULL;
  uint32_t *buff = (uint32_t *)stream;

  if (*labels != NULL) {
    printf("Reading Labels, Something has gone terribly wrong\n");
    return NULL;
  }

  while (cont) {
    iterate = malloc(sizeof(*iterate));
    if (!iterate) {
      while(top) {
	/*
	 * Out of memory unwind and get out of here
	 */
	iterate = top->next;
	free(top);
	top = iterate;
      }
      return NULL;
    }

    if (top == NULL) {
      top = iterate;
    }

    memcpy(&iterate->u.l32,  buff, sizeof(*buff));

    iterate->next = NULL;
    if (ls) {
      ls->next = iterate;
    }
    ls = iterate;
    
    if (!iterate->u.l.bos) {
      buff++;
    } else {
      cont = 0;
    }
  }

  buff++;
  *labels = top;
  return (unsigned char *)buff;
}

/*
 * mpls_label_stack
 *
 * Code assumes that label, exp, bos and ttl are valid values checked elsewhere
 *
 * Returns the modified label stack.
 */
mpls_label_stack *
mpls_label_add (mpls_label_stack *ls, uint32_t label,
		uint8_t exp, uint8_t ttl)
{
  mpls_label_stack *nls;

  nls = malloc(sizeof(mpls_label_stack));
  if (nls == NULL) {
    return NULL;
  }

  memset(nls, 0, sizeof(mpls_label_stack));

  nls->next  = ls;
  mpls_set_hdr_label(&nls->u.l, label);
  nls->u.l.exp   = exp;
  if (ls == NULL) {
    nls->u.l.bos = 1;
  } else {
    nls->u.l.bos = 0;
  }

  nls->u.l.ttl   = ttl;
  return nls;
}

int
mpls_label_has_ttl_expiration (mpls_label_stack *stack)
{
  mpls_label_stack *ls = stack;

  while(ls->next != NULL) {
    ls = ls->next;
  }

  if (ls->u.l.ttl == 1) {
    return 1;
  }

  return 0;
}

/*
 * mpls_label_has_router_alert
 *
 * Do any of the labels have router alert set?
 * Do we care about all of them?  I think so - DBS
 *
 */
int
mpls_label_has_router_alert (mpls_label_stack *stack)
{
  mpls_label_stack *ls = stack;

  while(ls->next != NULL) {
    if (mpls_get_hdr_label(&ls->u.l) == 1) {
      return 1;
    }

    ls = ls->next;
  }

  return 0;
}

uint32_t
mpls_label_stack_depth (mpls_label_stack *stack)
{
  mpls_label_stack *ls = stack;
  uint32_t depth = 0;

  while(ls) {
    depth++;
    ls = ls->next;
  }

  return depth;
}

uint32_t
mpls_label_stack_value_at_depth (mpls_label_stack *stack, uint32_t depth)
{
  mpls_label_stack *ls = stack;

  depth--;
  while(depth) {
    if (ls) {
      ls = ls->next;
      depth--;
    } else {
      return 0;
    }
  }

  if (ls) {
    return(mpls_get_hdr_label(&ls->u.l));
  }

  return 0;
}

/*
 * mpls_label_lookup_ilm
 *
 * Given a particular label, convert that label
 * into a mpls_label_ilm data structure.
 *
 */
mpls_label_ilm *
mpls_label_lookup_ilm (uint32_t label)
{
  FILE *fp;
  char buffer[1000];
  char rlabel[100];
  char nh[100];
  uint32_t ret;
  mpls_label_ilm *ilm;

#define LABELTMP "/tmp/label.tmp"

  sprintf(buffer, "vtysh -c \"show mpls table %d\" | grep 'Local label' | cut -d \" \" -f 3 > " LABELTMP, label);
  system(buffer);

  ilm = malloc(sizeof(mpls_label_ilm));
  fp = fopen(LABELTMP, "r+");
  ret = fscanf(fp, "%d", &ilm->incoming);
  if (!ret) {                          // If we didn't read anything nothing
    unlink(LABELTMP);
    free(ilm);                         // is there
    return NULL;
  }
  fclose(fp);
  unlink(LABELTMP);

  DEBUG_DETAIL("In label from ILM %d\n", ilm->incoming);

  sprintf(buffer, "vtysh -c \"show mpls table %d\" | grep 'remote label' | cut -d \" \" -f 6 > " LABELTMP, label);
  system(buffer);

  fp = fopen(LABELTMP, "r+");
  ret = fscanf(fp, "%s", rlabel);
  if (!ret) {                          // If we didn't read anything nothing
    unlink(LABELTMP);
    free(ilm);                         // is there
    return NULL;
  }
  fclose(fp);
  unlink(LABELTMP);

  sprintf(buffer, "vtysh -c \"show mpls table %d\" | grep 'via' | cut -d \" \" -f 4 > " LABELTMP, label);
  system(buffer);

  fp = fopen(LABELTMP, "r+");
  ret = fscanf(fp, "%s", nh);
  if (!ret) {                          // If we didn't read anything nothing
    unlink(LABELTMP);
    free(ilm);                         // is there
    return NULL;
  }
  fclose(fp);
  unlink(LABELTMP);

  DEBUG_DETAIL("rlabel %s nh %s\n", rlabel, nh);

  if (rlabel[0] == 'i') {                // Implicit-Null
    ilm->operation = 3;
  } else {
    sscanf(rlabel, "%d", &ilm->operation);
  }

  if (!mpls_network_addr_retrieve(nh, &ilm->nh)) {
    free(ilm);
    unlink(LABELTMP);
    return NULL;
  }

  unlink(LABELTMP);
  return ilm;
}

uint32_t
mpls_label_ls_size (mpls_label_stack *ls)
{
  int items = 0;
  mpls_label_stack *iterate = ls;

  while(iterate != NULL) {
    items++;
    iterate = iterate->next;
  }

  return sizeof(struct mpls_label) * items;
}

char *mpls_label_print_info (uint32_t label, char *buff, int len)
{

  switch(label) {
  case 0:
    strncpy(buff, "IPv4 Explicit Null", len);
    return buff;
    break;
  case 1:
    strncpy(buff, "Router Alert Label", len);
    return buff;
    break;
  case 2:
    strncpy(buff, "IPv6 Explict Null", len);
    return buff;
    break;
  case 3:
    strncpy(buff, "implicit-null", len);
    return buff;
    break;
  case 14:
    /* RFC 3429 */
    strncpy(buff, "OAM Alert", len);
    return buff;
    break;
    /*
     * Do further RFC's add to these values?
     *
     * TODO - dbs
     */
  case 4:
  case 5:
  case 6:
  case 7:
  case 8:
  case 9:
  case 10:
  case 11:
  case 12:
  case 13:
  case 15:
    strncpy(buff, "Reserved", len);
    return buff;
    break;
  default:
    sprintf(buff, "%u", label);
    return buff;
  }

  strncpy(buff, "Error", len);
  return buff;
}

char *mpls_label_print_ls (mpls_label_stack *ls, char *buff, int len)
{
  char buff1[100];
  mpls_label_stack *iterate = ls;
  uint32_t print_slash = 0;

  buff[0] = '\0';
  while(iterate != NULL) {
    if (print_slash)
      buff = strcat(buff, "/");

    buff = strcat(buff, mpls_label_print_info(mpls_get_hdr_label(&iterate->u.l), buff1, 100));

    print_slash = 1;
    iterate = iterate->next;
  }

  return buff;
}

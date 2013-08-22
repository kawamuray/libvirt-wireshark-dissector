/* packet-libvirt.h --- Libvirt packet dissector header file.
 *
 * Copyright (C) 2013 Yuto Kawamura(kawamuray) <kawamuray.dadada@gmail.com>
 *
 * Author: Yuto Kawamura(kawamuray)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef _PACKET_LIBVIRT_H_
#define _PACKET_LIBVIRT_H_

#ifndef LIBVIRT_PORT
#define LIBVIRT_PORT 16509
#endif

#define VIR_HEADER_LEN 28

typedef gboolean (*vir_xdr_dissector_t)(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);

typedef struct vir_dissector_index vir_dissector_index_t;
struct vir_dissector_index {
    guint32             proc;
    vir_xdr_dissector_t args;
    vir_xdr_dissector_t ret;
    vir_xdr_dissector_t msg;
};

enum vir_net_message_type {
    VIR_NET_CALL           = 0,
    VIR_NET_REPLY          = 1,
    VIR_NET_MESSAGE        = 2,
    VIR_NET_STREAM         = 3,
    VIR_NET_CALL_WITH_FDS  = 4,
    VIR_NET_REPLY_WITH_FDS = 5,
};

enum vir_net_message_status {
    VIR_NET_OK       = 0,
    VIR_NET_ERROR    = 1,
    VIR_NET_CONTINUE = 2,
};

static const value_string type_strings[] = {
    { VIR_NET_CALL,           "CALL"           },
    { VIR_NET_REPLY,          "REPLY"          },
    { VIR_NET_MESSAGE,        "MESSAGE"        },
    { VIR_NET_STREAM,         "STREAM"         },
    { VIR_NET_CALL_WITH_FDS,  "CALL_WITH_FDS"  },
    { VIR_NET_REPLY_WITH_FDS, "REPLY_WITH_FDS" },
    { -1, NULL }
};

static const value_string status_strings[] = {
    { VIR_NET_OK,       "OK"       },
    { VIR_NET_ERROR,    "ERROR"    },
    { VIR_NET_CONTINUE, "CONTINUE" },
    { -1, NULL }
};

/* TODO: These symbols will automatically included in generated headers in the feature */
#define VIR_SECURITY_MODEL_BUFLEN (256 + 1)
#define VIR_SECURITY_LABEL_BUFLEN (4096 + 1)
#define VIR_SECURITY_DOI_BUFLEN (256 + 1)
#define VIR_UUID_BUFLEN (16)
enum {
    VIR_TYPED_PARAM_INT     = 1, /* integer case */
    VIR_TYPED_PARAM_UINT    = 2, /* unsigned integer case */
    VIR_TYPED_PARAM_LLONG   = 3, /* long long case */
    VIR_TYPED_PARAM_ULLONG  = 4, /* unsigned long long case */
    VIR_TYPED_PARAM_DOUBLE  = 5, /* double case */
    VIR_TYPED_PARAM_BOOLEAN = 6, /* boolean(character) case */
    VIR_TYPED_PARAM_STRING  = 7, /* string case */
};
/* / */

#define VIR_ERROR_MESSAGE_DISSECTOR dissect_xdr_remote_error
/* XXX: consider location */
static gboolean dissect_xdr_int(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_u_int(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_short(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_u_short(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_char(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_u_char(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_hyper(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_u_hyper(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_float(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_double(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_bool(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_string(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf, gint32 maxlen);
static gboolean dissect_xdr_opaque(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf, gint32 size);
static gboolean dissect_xdr_bytes(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf, gint32 maxlen);
static gboolean dissect_xdr_pointer(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf,
                                    vir_xdr_dissector_t dp);
static gboolean dissect_xdr_vector(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf,
                                   gint ett, int rhf, gint32 size, vir_xdr_dissector_t dp);
static gboolean dissect_xdr_array(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf,
                                  gint ett, int rhf, gint32 maxlen, vir_xdr_dissector_t dp);

#include "libvirt/protocol.h"

#endif /* _PACKET_LIBVIRT_H_ */

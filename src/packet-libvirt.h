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

typedef struct vir_xdrdef vir_xdrdef_t;
struct vir_xdrdef {
    const guint    type;
    const void    *typeref;
    const gintptr  metainfo;
};

typedef struct vir_named_xdrdef vir_named_xdrdef_t;
struct vir_named_xdrdef {
    const gchar   *name; /* TODO: to guchar? */
    const guint    type;
    const void    *typeref;
    const gintptr  metainfo;
};
#define VIR_NAMED_XDRDEF_NULL { NULL, 0, NULL, 0 }
#define VIR_XDRDEF_STRIP(def) ((vir_xdrdef_t *)&(def)->type)

typedef struct vir_proc_payload vir_proc_payload_t;
struct vir_proc_payload {
    guint32             proc;
    vir_named_xdrdef_t *args;
    vir_named_xdrdef_t *ret;
    vir_named_xdrdef_t *msg;
};

#define VIR_ARR_W_SIZE(ary) (ary), array_length(ary)

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

enum {
    VIR_PDIC_PROC_STRINGS = 1,
    VIR_PDIC_HF,
    VIR_PDIC_XDRDEF,
    VIR_PDIC_XDRDEF_LEN,
    VIR_PDIC_LAST
};

enum vir_xdr_type {
    XDR_INT = 1,
    XDR_UINT,
    XDR_ENUM,
    XDR_BOOL,
    XDR_SHORT,
    XDR_USHORT,
    XDR_HYPER,
    XDR_UHYPER,
    XDR_CHAR,
    XDR_UCHAR,
    XDR_FLOAT,
    XDR_DOUBLE,
    XDR_QUADRUPLE,
    XDR_OPAQUE,
    XDR_BYTES,
    XDR_STRING,
    XDR_VECTOR,
    XDR_ARRAY,
    XDR_STRUCT,
    XDR_UNION,
    XDR_POINTER,
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

#define VIR_ERROR_MESSAGE_PAYLOAD_DEF struct_remote_error_members_def
#include "libvirt/protocol.h"

#endif /* _PACKET_LIBVIRT_H_ */

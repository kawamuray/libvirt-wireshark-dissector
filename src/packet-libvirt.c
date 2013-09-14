/* packet-libvirt.c --- Libvirt packet dissector routines.
 *
 * Copyright (C) 2013 Yuto Kawamura(kawamuray) <kawamuray.dadada@gmail.com>
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
 *
 * Authors:
 *     Michal Privoznik         <mprivozn redhat com>
 *     Yuto Kawamura(kawamuray) <kawamuray.dadada gmail.com>
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <wireshark/config.h>
#include <wireshark/epan/proto.h>
#include <wireshark/epan/packet.h>
#include <wireshark/epan/dissectors/packet-tcp.h>
#include <glib.h>
#ifdef HAVE_RPC_TYPES_H
#include <rpc/types.h>
#endif
#include <rpc/xdr.h>
#include "packet-libvirt.h"

static int proto_libvirt = -1;
static int hf_libvirt_length = -1;
static int hf_libvirt_program = -1;
static int hf_libvirt_version = -1;
static int hf_libvirt_type = -1;
static int hf_libvirt_serial = -1;
static int hf_libvirt_status = -1;
static int hf_libvirt_payload = -1;
static int hf_libvirt_stream = -1;
static int hf_libvirt_num_of_fds = -1;
static gint ett_libvirt = -1;

#define XDR_PRIMITIVE_DISSECTOR(xtype, ctype, ftype)                    \
    static gboolean                                                     \
    dissect_xdr_##xtype(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf)    \
    {                                                                   \
        goffset start;                                                  \
        ctype val;                                                      \
        start = xdr_getpos(xdrs);                                       \
        if (xdr_##xtype(xdrs, &val)) {                                  \
            proto_tree_add_##ftype(tree, hf, tvb, start, xdr_getpos(xdrs) - start, val); \
            return TRUE;                                                \
        } else {                                                        \
            proto_tree_add_text(tree, tvb, start, -1, "(unknown)");     \
            return FALSE;                                               \
        }                                                               \
    }

XDR_PRIMITIVE_DISSECTOR(int,     gint32,  int)
XDR_PRIMITIVE_DISSECTOR(u_int,   guint32, uint)
XDR_PRIMITIVE_DISSECTOR(short,   gint16,  int)
XDR_PRIMITIVE_DISSECTOR(u_short, guint16, uint)
XDR_PRIMITIVE_DISSECTOR(char,    gchar,   int)
XDR_PRIMITIVE_DISSECTOR(u_char,  guchar,  uint)
XDR_PRIMITIVE_DISSECTOR(hyper,   gint64,  int64)
XDR_PRIMITIVE_DISSECTOR(u_hyper, guint64, uint64)
XDR_PRIMITIVE_DISSECTOR(float,   gfloat,  float)
XDR_PRIMITIVE_DISSECTOR(double,  gdouble, double)
XDR_PRIMITIVE_DISSECTOR(bool,    bool_t,  boolean)

static gboolean
dissect_xdr_string(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf,
                   gint32 maxlen)
{
    goffset start;
    gchar *val = NULL;

    start = xdr_getpos(xdrs);
    if (xdr_string(xdrs, &val, maxlen)) {
        proto_tree_add_string(tree, hf, tvb, start, xdr_getpos(xdrs) - start, val);
        xdr_free((xdrproc_t)xdr_string, (char *)&val);
        return TRUE;
    } else {
        proto_tree_add_text(tree, tvb, start, -1, "(unknown)");
        return FALSE;
    }
}

static gboolean
dissect_xdr_opaque(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf,
                   gint32 size)
{
    goffset start;
    gboolean rc;
    guint8 *val;

    val = g_malloc(size);
    start = xdr_getpos(xdrs);
    if ((rc = xdr_opaque(xdrs, (caddr_t)val, size))) {
        proto_tree_add_bytes(tree, hf, tvb, start, xdr_getpos(xdrs) - start, val);
    } else {
        proto_tree_add_text(tree, tvb, start, -1, "(unknown)");
    }

    g_free(val);
    return rc;
}

static gboolean
dissect_xdr_bytes(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf,
                  gint32 maxlen)
{
    goffset start;
    guint8 *val = NULL;
    guint32 length;

    start = xdr_getpos(xdrs) + sizeof(length);
    if (xdr_bytes(xdrs, (char **)&val, &length, maxlen)) {
        proto_tree_add_bytes(tree, hf, tvb, start, xdr_getpos(xdrs) - start, val);
        /* Seems I can't call xdr_free() for this case.
           It will raises SEGV by referencing out of bounds argument stack */
        xdrs->x_op = XDR_FREE;
        xdr_bytes(xdrs, (char **)&val, &length, maxlen);
        xdrs->x_op = XDR_DECODE;
        return TRUE;
    } else {
        proto_tree_add_text(tree, tvb, start, -1, "(unknown)");
        return FALSE;
    }
}

static gboolean
dissect_xdr_pointer(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf,
                    vir_xdr_dissector_t dissect)
{
    goffset start;
    bool_t isnull;

    start = xdr_getpos(xdrs);
    if (!xdr_bool(xdrs, &isnull)) {
        proto_tree_add_text(tree, tvb, start, -1, "(unknown)");
        return FALSE;
    }
    if (isnull) {
        proto_item *ti;
        ti = proto_tree_add_item(tree, hf, tvb, start, xdr_getpos(xdrs) - start, ENC_NA);
        proto_item_append_text(ti, ": (null)");
        return TRUE;
    } else {
        return dissect(tvb, tree, xdrs, hf);
    }
}

static void annotate_index(proto_node *ch, gpointer ip)
{
    proto_item_prepend_text((proto_item *)ch, "[%d]", (*(gint *)ip)++);
}

static gboolean
dissect_xdr_vector(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf, gint ett,
                   int rhf, gchar *rtype, gint32 size, vir_xdr_dissector_t dissect)
{
    goffset start;
    proto_item *ti;
    gint i;

    start = xdr_getpos(xdrs);
    ti = proto_tree_add_item(tree, hf, tvb, start, -1, ENC_NA);
    proto_item_append_text(ti, " :: %s[%d]", rtype, size);
    tree = proto_item_add_subtree(ti, ett);
    for (i = 0; i < size; i++) {
        if (!dissect(tvb, tree, xdrs, rhf))
            return FALSE;
    }
    proto_item_set_len(ti, xdr_getpos(xdrs) - start);
    i = 0;
    proto_tree_children_foreach(tree, annotate_index, &i);
    return TRUE;
}

static gboolean
dissect_xdr_array(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf, gint ett,
                  int rhf, gchar *rtype, gint32 maxlen, vir_xdr_dissector_t dissect)
{
    gint32 length;

    if (!xdr_int(xdrs, &length))
        return FALSE;
    if (length > maxlen)
        return FALSE;
    return dissect_xdr_vector(tvb, tree, xdrs, hf, ett, rhf, rtype, length, dissect);
}

static vir_xdr_dissector_t
find_payload_dissector(guint32 proc, guint32 type,
                       const vir_dissector_index_t *pds, gsize length)
{
    const vir_dissector_index_t *pd;
    guint32 first, last, direction;

    if (pds == NULL || length < 1)
        return NULL;

    first = pds[0].proc;
    last = pds[length-1].proc;
    if (proc < first || proc > last) {
        return NULL;
    }

    pd = &pds[proc-first];
    /* There is no guarantee to proc numbers has no gap */
    if (pd->proc != proc) {
        direction = (pd->proc < proc) ? 1 : -1;
        while (pd->proc != proc) {
            if (pd->proc == first || pd->proc == last)
                return NULL;
            pd += direction;
        }
    }

    switch (type) {
    case VIR_NET_CALL:
    case VIR_NET_CALL_WITH_FDS:
        return pd->args;
    case VIR_NET_REPLY:
    case VIR_NET_REPLY_WITH_FDS:
        return pd->ret;
    case VIR_NET_MESSAGE:
        return pd->msg;
    default:
        dbg("ERROR: type = %u is not implemented", type);
        return NULL;
    }
}

static void
dissect_libvirt_stream(tvbuff_t *tvb, proto_tree *tree, gint plsize)
{
    proto_tree_add_item(tree, hf_libvirt_stream, tvb, VIR_HEADER_LEN,
                        plsize - VIR_HEADER_LEN, ENC_NA);
}

static gint32
dissect_libvirt_num_of_fds(tvbuff_t *tvb, proto_tree *tree)
{
    gint32 nfds;
    nfds = tvb_get_ntohl(tvb, VIR_HEADER_LEN);
    proto_tree_add_int(tree, hf_libvirt_num_of_fds, tvb, VIR_HEADER_LEN, 4, nfds);
    return nfds;
}

static void
dissect_libvirt_fds(tvbuff_t *tvb, gint start, gint32 nfds)
{
    /* TODO: NOP for now */
}

static void
dissect_libvirt_payload_xdr_data(tvbuff_t *tvb, proto_tree *tree, gint plsize,
                                 gint32 status, vir_xdr_dissector_t dissect)
{
    gint32 nfds = 0;
    gint start = VIR_HEADER_LEN;
    tvbuff_t *payload_tvb;
    caddr_t payload_data;
    XDR xdrs;

    if (status == VIR_NET_CALL_WITH_FDS ||
        status == VIR_NET_REPLY_WITH_FDS) {
        nfds = dissect_libvirt_num_of_fds(tvb, tree);
        start += 4;
        plsize -= 4;
    }

    payload_tvb = tvb_new_subset(tvb, start, -1, plsize);
    payload_data = (caddr_t)tvb_memdup(payload_tvb, 0, plsize);
    xdrmem_create(&xdrs, payload_data, plsize, XDR_DECODE);

    dissect(payload_tvb, tree, &xdrs, hf_libvirt_payload);

    xdr_destroy(&xdrs);
    g_free(payload_data);

    if (nfds != 0) {
        dissect_libvirt_fds(tvb, start, nfds); /* XXX: start? */
    }
}

static void
dissect_libvirt_payload(tvbuff_t *tvb, proto_tree *tree,
                        guint32 prog, guint32 proc, guint32 type, guint32 status)
{
    gssize payload_length;

    payload_length = tvb_length(tvb) - VIR_HEADER_LEN;
    if (payload_length <= 0)
        return; /* No payload */

    if (status == VIR_NET_OK) {
        vir_xdr_dissector_t xd = find_payload_dissector(proc, type, get_program_data(prog, VIR_PROGRAM_DISSECTORS),
                                                        *(gsize *)get_program_data(prog, VIR_PROGRAM_DISSECTORS_LEN));
        if (xd == NULL) {
            dbg("ERROR: cannot find payload definition: Prog=%u, Proc=%u", prog, proc);
            return;
        }
        dissect_libvirt_payload_xdr_data(tvb, tree, payload_length, status, xd);
    } else if (status == VIR_NET_ERROR) {
        dissect_libvirt_payload_xdr_data(tvb, tree, payload_length, status, VIR_ERROR_MESSAGE_DISSECTOR);
    } else if (type == VIR_NET_STREAM) { /* implicitly, status == VIR_NET_CONTINUE */
        dissect_libvirt_stream(tvb, tree, payload_length);
    } else {
        dbg("ERROR: unknown status = %u is not implemented", status);
    }
}

static void
dissect_libvirt_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    goffset offset;
    guint32 prog, proc, type, serial, status;
    const value_string *vs;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Libvirt");
    col_clear(pinfo->cinfo, COL_INFO);

    offset = 4; /* End of length field */
    prog   = tvb_get_ntohl(tvb, offset); offset += 4;
    offset += 4; /* Ignore version header field */
    proc   = tvb_get_ntohl(tvb, offset); offset += 4;
    type   = tvb_get_ntohl(tvb, offset); offset += 4;
    serial = tvb_get_ntohl(tvb, offset); offset += 4;
    status = tvb_get_ntohl(tvb, offset); offset += 4;

    col_add_fstr(pinfo->cinfo, COL_INFO, "Prog=%s",
                 val_to_str(prog, program_strings, "%x"));

    vs = get_program_data(prog, VIR_PROGRAM_PROCSTRINGS);
    if (vs == NULL) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Proc=%u", proc);
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Proc=%s", val_to_str(proc, vs, "%d"));
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " Type=%s Serial=%u Status=%s",
                    val_to_str(type, type_strings, "%d"), serial,
                    val_to_str(status, status_strings, "%d"));

    if (tree) {
        gint hf_proc;
        proto_item *ti;
        proto_tree *libvirt_tree;

        ti = proto_tree_add_item(tree, proto_libvirt, tvb, 0, tvb_length(tvb), ENC_NA);
        libvirt_tree = proto_item_add_subtree(ti, ett_libvirt);

        offset = 0;
        proto_tree_add_item(libvirt_tree, hf_libvirt_length,  tvb, offset, 4, ENC_NA); offset += 4;
        proto_tree_add_item(libvirt_tree, hf_libvirt_program, tvb, offset, 4, ENC_NA); offset += 4;
        proto_tree_add_item(libvirt_tree, hf_libvirt_version, tvb, offset, 4, ENC_NA); offset += 4;

        hf_proc = *(int *)get_program_data(prog, VIR_PROGRAM_PROCHFVAR);
        if (hf_proc == -1) {
            proto_tree_add_none_format(libvirt_tree, -1, tvb, offset, 4, "Unknown proc: %u", proc);
        } else {
            proto_tree_add_item(libvirt_tree, hf_proc, tvb, offset, 4, ENC_NA);
        }
        offset += 4;

        proto_tree_add_item(libvirt_tree, hf_libvirt_type,    tvb, offset, 4, ENC_NA); offset += 4;
        proto_tree_add_item(libvirt_tree, hf_libvirt_serial,  tvb, offset, 4, ENC_NA); offset += 4;
        proto_tree_add_item(libvirt_tree, hf_libvirt_status,  tvb, offset, 4, ENC_NA); offset += 4;

        /* Dissect payload remaining */
        dissect_libvirt_payload(tvb, libvirt_tree, prog, proc, type, status);
    }
}

static guint32
get_message_len(packet_info *pinfo __attribute__((unused)), tvbuff_t *tvb, int offset)
{
    return tvb_get_ntohl(tvb, offset);
}

static void
dissect_libvirt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Another magic const - 4; simply, how much bytes
     * is needed to tell the length of libvirt packet. */
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, get_message_len, dissect_libvirt_message);
}

void
proto_register_libvirt(void)
{
    static hf_register_info hf[] = {
        { &hf_libvirt_length,
          { "length", "libvirt.length",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_program,
          { "program", "libvirt.program",
            FT_UINT32, BASE_HEX,
            VALS(program_strings), 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_version,
          { "version", "libvirt.version",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_type,
          { "type", "libvirt.type",
            FT_INT32, BASE_DEC,
            VALS(type_strings), 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_serial,
          { "serial", "libvirt.serial",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_status,
          { "status", "libvirt.status",
            FT_INT32, BASE_DEC,
            VALS(status_strings), 0x0,
            NULL, HFILL}
        },

        VIR_DYNAMIC_HFSET

        { &hf_libvirt_payload,
          { "payload", "libvirt.payload",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_stream,
          { "stream", "libvirt.stream",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_num_of_fds,
          { "num_of_fds", "libvirt.num_of_fds",
            FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
        },
    };

    static gint *ett[] = {
        VIR_DYNAMIC_ETTSET
        &ett_libvirt
    };

    proto_libvirt = proto_register_protocol(
        "Libvirt", /* name */
        "libvirt", /* short name */
        "libvirt"  /* abbrev */
    );

    proto_register_field_array(proto_libvirt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_libvirt(void)
{
    static dissector_handle_t libvirt_handle;

    libvirt_handle = create_dissector_handle(dissect_libvirt, proto_libvirt);
    dissector_add_uint("tcp.port", LIBVIRT_PORT, libvirt_handle);
}

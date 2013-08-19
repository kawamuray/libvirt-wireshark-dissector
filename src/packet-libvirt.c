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
static gint ett_libvirt = -1;

#define XDR_PRIMITIVE_DISSECTOR(xtype, ctype, ftype)                    \
    static gboolean                                                     \
    dissect_xdr_##xtype(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf)    \
    {                                                                   \
        goffset start;                                                  \
        ctype val;                                                      \
        start = VIR_HEADER_LEN + xdr_getpos(xdrs);                      \
        if (xdr_##xtype(xdrs, &val)) {                                  \
            proto_tree_add_##ftype(tree, hf, tvb, start, xdr_getpos(xdrs) - start + VIR_HEADER_LEN, val); \
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

    start = VIR_HEADER_LEN + xdr_getpos(xdrs);
    if (xdr_string(xdrs, &val, maxlen)) {
        proto_tree_add_string(tree, hf, tvb, start,
                              xdr_getpos(xdrs) - start + VIR_HEADER_LEN, val);
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
    if (val == NULL) {
        g_print("ERROR: memory allocation failed\n");
        return FALSE;
    }

    start = VIR_HEADER_LEN + xdr_getpos(xdrs);
    if ((rc = xdr_opaque(xdrs, (caddr_t)val, size))) {
        proto_tree_add_bytes(tree, hf, tvb, start,
                             xdr_getpos(xdrs) - start + VIR_HEADER_LEN, val);
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
    guint length;

    start = VIR_HEADER_LEN + xdr_getpos(xdrs) + sizeof(length); /* XXX */
    if (xdr_bytes(xdrs, (char **)&val, &length, maxlen)) {
        proto_tree_add_bytes(tree, hf, tvb,
                             start, xdr_getpos(xdrs) - start + VIR_HEADER_LEN, val);
        /* XXX: maybe this is wrong way */
        xdrs->x_op = XDR_FREE;
        xdr_bytes(xdrs, (char **)&val, &length, maxlen);
        /* xdr_free((xdrproc_t)xdr_bytes, (char *)&val); */
        xdrs->x_op = XDR_DECODE;
        return TRUE;
    } else {
        proto_tree_add_text(tree, tvb, start, -1, "(unknown)");
        return FALSE;
    }
}

static gboolean
dissect_xdr_pointer(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf,
                    vir_xdr_dissector_t dp)
{
    goffset start;
    bool_t isnull;

    start = VIR_HEADER_LEN + xdr_getpos(xdrs);
    if (!xdr_bool(xdrs, &isnull)) {
        proto_tree_add_text(tree, tvb, start, -1, "(unknown)");
        return FALSE;
    }
    if (isnull) {
        proto_item_append_text(proto_tree_add_item(tree, hf, tvb, start, xdr_getpos(xdrs) - start + VIR_HEADER_LEN, ENC_NA), "(NULL)");
        return TRUE;
    } else {
        return dp(tvb, tree, xdrs, hf);
    }
}

static gboolean
dissect_xdr_vector(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf,
                   gint ett, int rhf, gint32 size, vir_xdr_dissector_t dp)
{
    goffset start;
    proto_item *ti;
    gint i;

    start = VIR_HEADER_LEN + xdr_getpos(xdrs);
    ti = proto_tree_add_item(tree, hf, tvb, start, -1, ENC_NA);
    tree = proto_item_add_subtree(ti, ett);
    for (i = 0; i < size; i++) {
        if (!dp(tvb, tree, xdrs, rhf))
            return FALSE;
    }
    proto_item_set_len(ti, xdr_getpos(xdrs) - start + VIR_HEADER_LEN);
    return TRUE;
}

static gboolean
dissect_xdr_array(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf,
                  gint ett, int rhf, gint32 maxlen, vir_xdr_dissector_t dp)
{
    gint32 length;

    if (!xdr_int(xdrs, &length))
        return FALSE;
    if (length > maxlen)
        return FALSE;
    return dissect_xdr_vector(tvb, tree, xdrs, hf, ett, rhf, length, dp);
}

static void
dissect_payload(tvbuff_t *tvb, proto_tree *tree,
                size_t length, vir_xdr_dissector_t xd)
{
    guint8 *payload;
    XDR xdrs;

    g_print("Payload length = %u\n", length);

    payload = (guint8 *)tvb_memdup(tvb, 28, length);
    if (payload == NULL) {
        return;
    }

    xdrmem_create(&xdrs, (caddr_t)payload, length, XDR_DECODE);

    xd(tvb, tree, &xdrs, hf_libvirt_payload);

    xdr_destroy(&xdrs);
    g_free(payload);
}

static const vir_proc_payload_t *
find_xdr_dissector(guint32 proc, const vir_proc_payload_t *defs, gsize length)
{
    const vir_proc_payload_t *def;
    guint32 first, last, direction;

    if (length < 1) {
        return NULL;
    }

    first = defs[0].proc;
    last = defs[length-1].proc;
    if (proc < first || proc > last) {
        return NULL;
    }

    def = &defs[proc-first];
    /* There is no guarantee to proc numbers has no gap */
    if (def->proc == proc)
        return def;

    direction = (def->proc < proc) ? 1 : -1;
    while (def->proc != proc) {
        if (def->proc == first || def->proc == last)
            return NULL;
        def += direction;
    }

    return def;
}

static vir_xdr_dissector_t
payload_dispatch_type(guint32 prog, guint32 proc, guint32 type)
{
    if (type == VIR_NET_STREAM) {
        /* NOP */
    } else {
        const vir_proc_payload_t *pd = NULL;
#define VIR_PROG_CASE(ps) pd = find_xdr_dissector(proc, ps##_dissectors, array_length(ps##_dissectors))
        VIR_PROG_SWITCH(prog);
#undef VIR_PROG_CASE

        if (pd == NULL) {
            g_print("ERROR: cannot find payload definition: Prog=%u, Proc=%u\n", prog, proc);
            return NULL;
        }
        switch (type) {
        case VIR_NET_CALL_WITH_FDS:
            /* TODO: dissect number of fds */
            break; /* fall through in the feature */
        case VIR_NET_CALL:
            return pd->args;
        case VIR_NET_REPLY_WITH_FDS:
            /* TODO: dissect number of fds */
            break; /* fall through in the feature */
        case VIR_NET_REPLY:
            return pd->ret;
        }
    }

    g_print("ERROR: type = %u is not implemented\n", type);
    return NULL;
}

static void
dissect_libvirt_payload(tvbuff_t *tvb, proto_tree *tree, gint length,
                        guint32 prog, guint32 proc,
                        guint32 type, guint32 status)
{
    switch (status) {
    case VIR_NET_OK: {
        vir_xdr_dissector_t xd;
        xd = payload_dispatch_type(prog, proc, type);
        if (xd == NULL) {
            proto_tree_add_text(tree, tvb, VIR_HEADER_LEN, length, "(unknown payload)");
        } else {
            dissect_payload(tvb, tree, length, xd);
        }
        break;
    }
    case VIR_NET_ERROR:
        dissect_payload(tvb, tree, length, VIR_ERROR_MESSAGE_DISSECTOR);
        break;
    case VIR_NET_CONTINUE:
    default:
        g_print("ERROR: status = %u is not implemented", status);
    }
}

static void
dissect_libvirt_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint offset = 0;
    /* Okay, these are magic constants, but
     * they are just offsets where requested
     * info is to be found */
    guint32 prog = tvb_get_ntohl(tvb, 4);
    guint32 proc = tvb_get_ntohl(tvb, 12);
    guint32 type = tvb_get_ntohl(tvb, 16);
    guint32 serial = tvb_get_ntohl(tvb, 20);
    guint32 status = tvb_get_ntohl(tvb, 24);
    const value_string *vs = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Libvirt");
    col_clear(pinfo->cinfo, COL_INFO);

#define VIR_PROG_CASE(ps) vs = ps##_procedure_strings
    VIR_PROG_SWITCH(prog);
#undef VIR_PROG_CASE

    if (vs == NULL) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Proc=%u ", proc);
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Proc=%s ", val_to_str(proc, vs, "%d"));
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "Type=%s Status=%s Prog=%s Serial=%u",
        val_to_str(type, type_strings, "%d"),
        val_to_str(status, status_strings, "%d"),
        val_to_str(prog, program_strings, "%x"),
        serial);

    if (tree) {
        int hf_proc = -1;
        proto_item *ti = NULL;
        proto_tree *libvirt_tree = NULL;
        gint pld_length;

        ti = proto_tree_add_item(tree, proto_libvirt, tvb, 0, -1, FALSE);
        libvirt_tree = proto_item_add_subtree(ti, ett_libvirt);
        proto_tree_add_item(libvirt_tree, hf_libvirt_length, tvb, offset, 4, FALSE); offset += 4;
        proto_tree_add_item(libvirt_tree, hf_libvirt_program, tvb, offset, 4, FALSE); offset += 4;
        proto_tree_add_item(libvirt_tree, hf_libvirt_version, tvb, offset, 4, FALSE); offset += 4;

#define VIR_PROG_CASE(ps) hf_proc = hf_##ps##_procedure
        VIR_PROG_SWITCH(prog);
#undef VIR_PROG_CASE

        if (hf_proc == -1) {
            proto_tree_add_none_format(libvirt_tree, -1, tvb, offset, 4, "Unknown proc: %u", proc);
        } else {
            proto_tree_add_item(libvirt_tree, hf_proc, tvb, offset, 4, FALSE);
        }

        offset += 4;
        proto_tree_add_item(libvirt_tree, hf_libvirt_type, tvb, offset, 4, FALSE); offset += 4;
        proto_tree_add_item(libvirt_tree, hf_libvirt_serial, tvb, offset, 4, FALSE); offset += 4;
        proto_tree_add_item(libvirt_tree, hf_libvirt_status, tvb, offset, 4, FALSE); offset += 4;

        /* Dissect packet payload */
        pld_length = tvb_get_ntohl(tvb, 0) - offset;
        if (pld_length > 0) {
            dissect_libvirt_payload(tvb, libvirt_tree, pld_length, prog, proc, type, status);
            g_print("Dissecting libvirt payload END\n");
        } else {
            g_print("No payload\n");
        }
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

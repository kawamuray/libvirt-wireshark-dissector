/* packet-libvirt.c --- Libvirt packet dissector routines.
 *
 * Copyright (C) 2013 Yuto Kawamura(kawamuray) <kawamuray.dadada@gmail.com>
 *
 * Author: Michal Privoznik <mprivozn redhat com>, enhanced by Yuto Kawamura(kawamuray)
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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <wireshark/config.h>
#include <epan/packet.h>
#include <glib.h>
#include <rpc/xdr.h>
#include "packet-tcp.h"
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

static gboolean describe_dispatch(const vir_xdrdef_t *def, XDR *xdrs, proto_item *ti);

#define XDR_PRIMITIVE_DESCRIBER(name, ctype, fmt)                       \
    static gboolean                                                     \
    describe_xdr_##name(const vir_xdrdef_t *def __attribute__((unused)), \
                        XDR *xdrs, proto_item *ti)                      \
    {                                                                   \
        ctype val;                                                      \
        if (xdr_##name(xdrs, &val)) {                                   \
            proto_item_append_text(ti, fmt, val);                       \
            return TRUE;                                                \
        } else {                                                        \
            proto_item_append_text(ti, "(unkown)");                     \
            return FALSE;                                               \
        }                                                               \
    }

XDR_PRIMITIVE_DESCRIBER(int,     gint32,  "%d")
XDR_PRIMITIVE_DESCRIBER(u_int,   guint32, "%u")
XDR_PRIMITIVE_DESCRIBER(short,   gshort,  "%d")
XDR_PRIMITIVE_DESCRIBER(u_short, gushort, "%u")
XDR_PRIMITIVE_DESCRIBER(char,    gchar,   "%02x")
XDR_PRIMITIVE_DESCRIBER(u_char,  guchar,  "%02x")
XDR_PRIMITIVE_DESCRIBER(hyper,   gint64,  "%lld")
XDR_PRIMITIVE_DESCRIBER(u_hyper, guint64, "%llu")
XDR_PRIMITIVE_DESCRIBER(float,   gfloat,  "%f")
XDR_PRIMITIVE_DESCRIBER(double,  gdouble, "%lf")

static gboolean
describe_xdr_string(const vir_xdrdef_t *def, XDR *xdrs, proto_item *ti)
{
    gchar *val = NULL;

    if (xdr_string(xdrs, &val, def->metainfo)) {
        proto_item_append_text(ti, "\"%s\"", (val) ? val : "(null)");
        xdr_free((xdrproc_t)xdr_string, (char *)&val);
        return TRUE;
    } else {
        proto_item_append_text(ti, "(unkown)");
        return FALSE;
    }
}

static gboolean
describe_xdr_opaque(const vir_xdrdef_t *def, XDR *xdrs, proto_item *ti)
{
    gboolean rc;
    guint8 *val;

    val = g_malloc(def->metainfo);
    if (val == NULL) {
        g_print("ERROR: memory allocation failed\n");
        return FALSE;
    }

    if ((rc = xdr_opaque(xdrs, (caddr_t)val, def->metainfo))) {
        gint i;
        /* TODO: buffering */
        for (i = 0; i < def->metainfo; i++) {
            if (!i) proto_item_append_text(ti, " ");
            proto_item_append_text(ti, "%02x ", val[i]);
        }
    } else {
        proto_item_append_text(ti, "(unkown)");
    }

    g_free(val);
    return rc;
}

static gboolean
describe_xdr_bytes(const vir_xdrdef_t *def, XDR *xdrs, proto_item *ti)
{
    guint8 *val = NULL;
    guint length;

    if (xdr_bytes(xdrs, (char **)&val, &length, def->metainfo)) {
        gint i;
        /* g_print("DEBUG: xdr_bytes length = %u, val = %p\n", length, val); */
        /* TODO: buffering */
        for (i = 0; i < length; i++) {
            if (!i) proto_item_append_text(ti, " ");
            proto_item_append_text(ti, "%02x", val[i]);
        }
        /* XXX: maybe this is wrong way */
        xdrs->x_op = XDR_FREE;
        xdr_bytes(xdrs, (char **)&val, &length, def->metainfo);
        /* xdr_free((xdrproc_t)xdr_bytes, (char *)&val); */
        xdrs->x_op = XDR_DECODE;
        return TRUE;
    } else {
        proto_item_append_text(ti, "(unkown)");
        return FALSE;
    }
}

static gboolean
describe_xdr_pointer(const vir_xdrdef_t *def, XDR *xdrs, proto_item *ti)
{
    bool_t isnull;

    if (!xdr_bool(xdrs, &isnull)) {
        return FALSE;
    }
    if (isnull) {
        proto_item_append_text(ti, "(null)");
    } else {
        if (!describe_dispatch(def->typeref, xdrs, ti)) {
            return FALSE;
        }
    }
    return TRUE;
}

static gboolean
describe_xdr_enum(const vir_xdrdef_t *def, XDR *xdrs, proto_item *ti)
{
    const vir_named_xdrdef_t *field;
    enum { DUMMY } es;

    if (xdr_enum(xdrs, (enum_t *)&es)) {
        for (field = def->typeref; field->name != NULL; field++) {
            if (field->metainfo == (gintptr)es) {
                proto_item_append_text(ti, "%s(%u)", field->name, es);
                return TRUE;
            }
        }
    } else {
        proto_item_append_text(ti, "(unkown)");
    }
    return FALSE;
}

static gboolean
describe_xdr_bool(const vir_xdrdef_t *def, XDR *xdrs, proto_item *ti)
{
    bool_t bool;

    if (xdr_bool(xdrs, &bool)) {
        proto_item_append_text(ti, "%s", bool ? "TRUE" : "FALSE");
        return TRUE;
    } else {
        proto_item_append_text(ti, "(unkown)");
        return FALSE;
    }
}

static gboolean
describe_xdr_struct(const vir_xdrdef_t *def, XDR *xdrs, proto_item *ti)
{
    gboolean rc = TRUE;
    const vir_named_xdrdef_t *field;

    proto_item_append_text(ti, "{ ");
    for (field = def->typeref; field->name != NULL; field++) {
        proto_item_append_text(ti, " .%s = ", field->name);
        if (!(rc = describe_dispatch(VIR_XDRDEF_STRIP(field), xdrs, ti))) {
            proto_item_append_text(ti, "<<UNABLE TO CONTINUE>>");
            break;
        }
    }
    proto_item_append_text(ti, " }");
    return rc;
}

static gboolean
describe_xdr_array(const vir_xdrdef_t *def, XDR *xdrs, proto_item *ti)
{
    gint length;

    if (xdr_int(xdrs, &length)) {
        const vir_xdrdef_t *subdef;
        gint i;
        if (length > def->metainfo)
            return FALSE;

        subdef = def->typeref;
        proto_item_append_text(ti, "[ ");
        for (i = 0; i < length; i++) {
            if (!describe_dispatch(subdef, xdrs, ti)) {
                g_print("ERROR: failed decoding on iteration %d\n", i);
                return FALSE;
            }
        }
        proto_item_append_text(ti, " ]");
        return TRUE;
    } else {
        proto_item_append_text(ti, "(unkown)");
        return FALSE;
    }
}

static gboolean
describe_xdr_vector(const vir_xdrdef_t *def, XDR *xdrs, proto_item *ti)
{
    const vir_xdrdef_t *subdef;
    gint i;

    subdef = def->typeref;
    proto_item_append_text(ti, "[ ");
    for (i = 0; i < def->metainfo; i++) {
        if (!describe_dispatch(subdef, xdrs, ti)) {
            g_print("ERROR: failed decoding on iteration %d\n", i);
            return FALSE;
        }
    }
    proto_item_append_text(ti, " ]");
    return TRUE;
}

static gboolean
describe_xdr_union(const vir_xdrdef_t *def, XDR *xdrs, proto_item *ti)
{
    const vir_named_xdrdef_t *mp;
    void *index;
    bool_t (*xdr_func)(XDR *, caddr_t);
    guint size;
    gboolean rc = FALSE;

    mp = def->typeref;
    xdr_func = mp->typeref;
    size = mp->metainfo;

    index = g_malloc(size);
    if (index == NULL) {
        g_print("ERROR: memory allocation fail\n");
        return FALSE;
    }

    if (!xdr_func(xdrs, index)) {
        g_print("ERROR: cannot extract union index\n");
        goto done;
    }
    while ((++mp)->type) {
        if (!memcmp(index, (void *)mp->metainfo, size)) {
            rc = describe_dispatch(VIR_XDRDEF_STRIP(mp), xdrs, ti);
            break;
        }
    }

done:
    g_free(index);
    return rc;
}

static gboolean
describe_dispatch(const vir_xdrdef_t *def, XDR *xdrs, proto_item *ti)
{
    switch (def->type) {
    case XDR_INT:
        return describe_xdr_int(def, xdrs, ti);
    case XDR_UINT:
        return describe_xdr_u_int(def, xdrs, ti);
    case XDR_ENUM:
        return describe_xdr_enum(def, xdrs, ti);
    case XDR_BOOL:
        return describe_xdr_bool(def, xdrs, ti);
    case XDR_SHORT:
        return describe_xdr_short(def, xdrs, ti);
    case XDR_USHORT:
        return describe_xdr_u_short(def, xdrs, ti);
    case XDR_HYPER:
        return describe_xdr_hyper(def, xdrs, ti);
    case XDR_UHYPER:
        return describe_xdr_u_hyper(def, xdrs, ti);
    case XDR_CHAR:
        return describe_xdr_char(def, xdrs, ti);
    case XDR_UCHAR:
        return describe_xdr_u_char(def, xdrs, ti);
    case XDR_FLOAT:
        return describe_xdr_float(def, xdrs, ti);
    case XDR_DOUBLE:
        return describe_xdr_double(def, xdrs, ti);
    case XDR_OPAQUE:
        return describe_xdr_opaque(def, xdrs, ti);
    case XDR_BYTES:
        return describe_xdr_bytes(def, xdrs, ti);
    case XDR_STRING:
        return describe_xdr_string(def, xdrs, ti);
    case XDR_VECTOR:
        return describe_xdr_vector(def, xdrs, ti);
    case XDR_ARRAY:
        return describe_xdr_array(def, xdrs, ti);
    case XDR_STRUCT:
        return describe_xdr_struct(def, xdrs, ti);
    case XDR_UNION:
        return describe_xdr_union(def, xdrs, ti);
    case XDR_POINTER:
        return describe_xdr_pointer(def, xdrs, ti);
    default:
        proto_item_append_text(ti, "UNIMPLEMENTED TYPE APPEARED!!!");
        /* return FALSE; */
        /* XXX: temporaily */
        return TRUE;
    }
}

static void
describe_payload(tvbuff_t *tvb, proto_item *ti,
                 size_t length, vir_named_xdrdef_t *def)
{
    guint8 *payload;
    XDR xdrs;
    const vir_xdrdef_t dmdef = { XDR_STRUCT, def, 0 };

    g_print("Payload length = %u\n", length);

    payload = (guint8 *)tvb_memdup(tvb, 28, length);
    if (payload == NULL) {
        return;
    }

    xdrmem_create(&xdrs, (caddr_t)payload, length, XDR_DECODE);

    describe_xdr_struct(&dmdef, &xdrs, ti);

    xdr_destroy(&xdrs);
    g_free(payload);
}

static const vir_proc_payload_t *
find_payload_def(guint32 proc, const vir_proc_payload_t *defs, gsize length)
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

static vir_named_xdrdef_t *
payload_dispatch_type(guint32 prog, guint32 proc, guint32 type)
{
    if (type == VIR_NET_STREAM) {
        /* NOP */
    } else {
        const vir_proc_payload_t *pd = NULL;
#define VIR_PROG_CASE(ps) pd = find_payload_def(proc, ps##_payload_def, array_length(ps##_payload_def))
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
dissect_libvirt_payload(tvbuff_t *tvb, proto_item *ti, gint length,
                        guint32 prog, guint32 proc,
                        guint32 type, guint32 status)
{
    switch (status) {
    case VIR_NET_OK: {
        vir_named_xdrdef_t *def;
        def = payload_dispatch_type(prog, proc, type);
        if (def == NULL) {
            proto_item_set_text(ti, "(unkown payload)");
        } else {
            describe_payload(tvb, ti, length, def);
        }
        break;
    }
    case VIR_NET_ERROR:
        describe_payload(tvb, ti, length, VIR_ERROR_MESSAGE_PAYLOAD_DEF);
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
            ti = proto_tree_add_item(libvirt_tree, hf_libvirt_payload, tvb, offset, pld_length, FALSE);
            dissect_libvirt_payload(tvb, ti, pld_length, prog, proc, type, status);
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

        VIR_PROCEDURES_HEADERSET

        { &hf_libvirt_payload,
          { "payload", "libvirt.payload",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        }
    };

    static gint *ett[] = {
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

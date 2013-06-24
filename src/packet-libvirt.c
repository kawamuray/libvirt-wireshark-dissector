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
static int hf_libvirt_procedure = -1;
static int hf_libvirt_type = -1;
static int hf_libvirt_serial = -1;
static int hf_libvirt_status = -1;
static int hf_qemu_procedure = -1;
static int hf_libvirt_payload = -1;
static gint ett_libvirt = -1;

/* #define DESCRIBE_XDR_IFNULL(bool, fmt, val)     \ */
/*     if ((bool)) {                               \ */
/*         proto_item_append_text(ti, "%d", val);  \ */
/*     } else {                                    \ */
/*         proto_item_append_text(ti, "(unkown)"); \ */
/*     } */

static void
describe_xdr_int(vir_pld_anon_field_def_t *def __attribute__((unused)), XDR *xdrs, proto_item *ti)
{
    int val;

    if (xdr_int(xdrs, &val)) {
        proto_item_append_text(ti, "%d", val);
    } else {
        proto_item_append_text(ti, "(unkown)");
    }
}

static void
describe_xdr_uint(vir_pld_anon_field_def_t *def __attribute__((unused)), XDR *xdrs, proto_item *ti)
{
    unsigned int val;

    if (xdr_int(xdrs, (int *)&val)) {
        proto_item_append_text(ti, "%u", val);
    } else {
        proto_item_append_text(ti, "(unkown)");
    }
}

static void
describe_xdr_string(vir_pld_anon_field_def_t *def __attribute__((unused)), XDR *xdrs, proto_item *ti)
{
    char *val = NULL;

    if (xdr_string(xdrs, &val, 4194304)) {
        proto_item_append_text(ti, "%s", (val) ? val : "(null)");
        xdr_free((xdrproc_t)xdr_string, (char *)&val);
    } else {
        proto_item_append_text(ti, "(unkown)");
    }
}

static void
describe_xdr_pointer(vir_pld_anon_field_def_t *def __attribute__((unused)),
                     XDR *xdrs, proto_item *ti,
                     void (*func)(vir_pld_anon_field_def_t*, XDR*, proto_item*))
{
    bool_t isnull;

    if (!xdr_bool(xdrs, &isnull)) {
        return;
    }
    if (isnull) {
        proto_item_append_text(ti, "(null)");
    } else {
        func(def, xdrs, ti);
    }
}

static void
describe_field(vir_pld_field_def_t *def, XDR *xdrs, proto_item *ti)
{
    switch (def->type) {
    case XDR_INT:
        describe_xdr_int(VIR_PLD_DEF_TOANON(def), xdrs, ti);
        break;
    case XDR_UINT:
        describe_xdr_uint(VIR_PLD_DEF_TOANON(def), xdrs, ti);
        break;
    case XDR_STRING:
        describe_xdr_string(VIR_PLD_DEF_TOANON(def), xdrs, ti);
        break;
    case XDR_POINTER:
        describe_xdr_pointer(VIR_PLD_DEF_TOANON(def), xdrs, ti, describe_xdr_string);
        break;
    default:
        proto_item_append_text(ti, "UNIMPLEMENTED TYPE APPEARED!!!");
    }
}

static void
describe_payload(tvbuff_t *tvb, proto_item *ti,
                 size_t length, vir_pld_field_def_t *def)
{
    guint8 *payload;
    XDR xdrs;

    g_print("Payload length = %u", length);

    payload = (guint8 *)tvb_memdup(tvb, 28, length);
    if (payload == NULL) {
        return;
    }

    xdrmem_create(&xdrs, (caddr_t)payload, length, XDR_DECODE);

    while (def != NULL && def->name != NULL) {
        proto_item_append_text(ti, " [%s] = ", def->name);
        describe_field(def, &xdrs, ti);
        def++;
    }

    xdr_destroy(&xdrs);
    g_free(payload);
}

static vir_pld_field_def_t *
find_field_def(guint32 proc, vir_pld_def_t *defs, gint length)
{
    gint i;

    for (i = 0; i < length; i++) {
        if (defs[i].proc == proc) {
            return defs[i].def;
        }
    }
    return NULL;
}

#define SWITCH_PROG(ts, prog, proc)                                     \
    switch (prog) {                                                     \
    case VIR_PROG_REMOTE:                                               \
        return find_field_def(proc, VIR_ARR_W_SIZE(vir_remote_##ts##_payload_defs)); \
    case VIR_PROG_QEMU:                                                 \
        return find_field_def(proc, VIR_ARR_W_SIZE(vir_qemu_##ts##_payload_defs)); \
    case VIR_PROG_LXC:                                                  \
        return find_field_def(proc, VIR_ARR_W_SIZE(vir_lxc_##ts##_payload_defs)); \
    default:                                                            \
        g_print("ERROR: prog = %u is not implemented", prog);           \
        return NULL;                                                    \
    }

static vir_pld_field_def_t *
payload_dispatch_type(guint32 prog, guint32 proc, guint32 type)
{
    switch (type) {
    case VIR_NET_CALL:
        SWITCH_PROG(args, prog, proc);
    case VIR_NET_REPLY:
        SWITCH_PROG(ret, prog, proc);
    case VIR_NET_MESSAGE:
    case VIR_NET_STREAM:
    case VIR_NET_CALL_WITH_FDS:
    case VIR_NET_REPLY_WITH_FDS:
    default:
        g_print("ERROR: type = %u is not implemented", type);
        return NULL;
    }
}
#undef SWITCH_PROG

static void
dissect_libvirt_payload(tvbuff_t *tvb, proto_item *ti, gint length,
                        guint32 prog, guint32 proc,
                        guint32 type, guint32 status)
{
    vir_pld_field_def_t *def;

    switch (status) {
    case VIR_NET_OK:
        def = payload_dispatch_type(prog, proc, type);
        if (def == NULL) {
            proto_item_set_text(ti, "(unkown payload)");
        } else {
            describe_payload(tvb, ti, length, def);
        }
        break;
    case VIR_NET_ERROR:
        /* TODO: error handler */
        g_print("ERROR: received error");
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

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Libvirt");
    col_clear(pinfo->cinfo,COL_INFO);
    if (prog == VIR_PROG_REMOTE)
        col_add_fstr(pinfo->cinfo, COL_INFO, "Proc=%s ", val_to_str(proc, remote_procedure_strings, "%d"));
    else if (prog == VIR_PROG_QEMU)
        col_add_fstr(pinfo->cinfo, COL_INFO, "Proc=%s ", val_to_str(proc, qemu_procedure_strings, "%d"));
    else
        /* unhandeld program */
        col_add_fstr(pinfo->cinfo, COL_INFO, "Proc=%u ", proc);

    col_append_fstr(pinfo->cinfo, COL_INFO, "Type=%s Status=%s Prog=%s Serial=%u",
        val_to_str(type, type_strings, "%d"),
        val_to_str(status, status_strings, "%d"),
        val_to_str(prog, program_strings, "%x"),
        serial);

    if (tree) {
        proto_item *ti = NULL;
        proto_tree *libvirt_tree = NULL;
        gint pld_length;

        ti = proto_tree_add_item(tree, proto_libvirt, tvb, 0, -1, FALSE);
        libvirt_tree = proto_item_add_subtree(ti, ett_libvirt);
        proto_tree_add_item(libvirt_tree, hf_libvirt_length, tvb, offset, 4, FALSE); offset += 4;
        proto_tree_add_item(libvirt_tree, hf_libvirt_program, tvb, offset, 4, FALSE); offset += 4;
        proto_tree_add_item(libvirt_tree, hf_libvirt_version, tvb, offset, 4, FALSE); offset += 4;
        if (prog == VIR_PROG_REMOTE)
            proto_tree_add_item(libvirt_tree, hf_libvirt_procedure, tvb, offset, 4, FALSE);
        else if (prog == VIR_PROG_QEMU)
            proto_tree_add_item(libvirt_tree, hf_qemu_procedure, tvb, offset, 4, FALSE);
        else
            /* unhandeld program */
            proto_tree_add_none_format(libvirt_tree, -1, tvb, offset, 4, "Unknown proc: %u", proc);
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

static guint32 get_message_len(packet_info *pinfo __attribute__((unused)), tvbuff_t *tvb, int offset)
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
        { &hf_libvirt_procedure,
          { "procedure", "libvirt.procedure",
            FT_INT32, BASE_DEC,
            VALS(remote_procedure_strings), 0x0,
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
        { &hf_qemu_procedure,
          { "procedure", "libvirt.procedure",
          FT_INT32, BASE_DEC,
          VALS(qemu_procedure_strings), 0x0,
          NULL, HFILL}
        },
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

    proto_libvirt = proto_register_protocol (
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

/* static bool_t */
/* describe_xdr_array(vir_pld_anon_field_def_t *def, XDR *xdrs) */
/* { */
/*     vir_pld_anon_field_def_t *indef; */
/*     char *array; */
/*     size_t length; */

/*     indef = (vir_pld_anon_field_def_t *)def->data; */
/*     XDRDEF_EXTENDED_DEF(xdrs) = indef; */

/*     if (!xdr_array(xdrs, &array, &length, 999999999, */
/*                    compute_xdrdef_size(indef), (xdrproc_t)xdr_general_array_each)) { */
/*         return FALSE; */
/*     } */
/*     return TRUE; */
/* } */


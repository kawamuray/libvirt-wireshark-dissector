#ifndef _LIBVIRT_REMOTE_DEF_H_
#define _LIBVIRT_REMOTE_DEF_H_

/* This file will be automatically generated in the feature */

/* Definition of arguments */
static vir_pld_field_def_t connect_open_args_def[] = {
    { "name",  XDR_POINTER, 0 },
    { "flags", XDR_UINT,    0 },
    VIR_PLD_DEF_NULL
};

static vir_pld_def_t vir_remote_args_payload_defs[] = {
    { 1, connect_open_args_def },
};

/* Definition of return values */
static vir_pld_field_def_t connect_get_hostname_ret_def[] = {
    /* CONNECT_OPEN */
    { "hostname", XDR_STRING, 0 },
    VIR_PLD_DEF_NULL
};

static vir_pld_def_t vir_remote_ret_payload_defs[] = {
    /* CONNECT_GET_HOSTNAME */
    { 59, connect_get_hostname_ret_def },
};

#endif /* _LIBVIRT_REMOTE_DEF_H_ */

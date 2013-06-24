#ifndef _LIBVIRT_REMOTE_DEF_H_
#define _LIBVIRT_REMOTE_DEF_H_

/* This file will be automatically generated in the feature */

/* Definition of arguments */
static vir_pld_field_def_t connect_open_args_def[] = {
    { "name",  XDR_POINTER, 0 },
    { "flags", XDR_UINT,    0 },
    VIR_PLD_DEF_NULL
};

static vir_pld_field_def_t connect_list_domains_args_def[] = {
    { "maxids",  XDR_INT, 0 },
    VIR_PLD_DEF_NULL
};

static vir_pld_def_t vir_remote_args_payload_defs[] = {
    { 1, connect_open_args_def },
    { 37, connect_list_domains_args_def },
};

/* Definition of return values */
static vir_pld_anon_field_def_t xdr_anon_int_def = { XDR_INT, 0 };

static vir_pld_field_def_t remote_nonnull_storage_vol_def[] = {
    { "pool", XDR_STRING, 0 },
    { "name", XDR_STRING, 0 },
    { "key", XDR_STRING, 0 },
    VIR_PLD_DEF_NULL
};

static vir_pld_field_def_t connect_list_domains_ret_def[] = {
    { "ids", XDR_ARRAY, (uintptr_t)&xdr_anon_int_def },
    VIR_PLD_DEF_NULL
};

static vir_pld_field_def_t connect_get_hostname_ret_def[] = {
    { "hostname", XDR_STRING, 0 },
    VIR_PLD_DEF_NULL
};

static vir_pld_field_def_t storage_vol_lookup_by_name_ret_def[] = {
    { "vol", XDR_STRUCT, (uintptr_t)remote_nonnull_storage_vol_def },
    VIR_PLD_DEF_NULL
};

static vir_pld_def_t vir_remote_ret_payload_defs[] = {
    /* CONNECT_GET_HOSTNAME */
    { 37, connect_list_domains_ret_def },
    { 59, connect_get_hostname_ret_def },
    { 95, storage_vol_lookup_by_name_ret_def },
};

#endif /* _LIBVIRT_REMOTE_DEF_H_ */

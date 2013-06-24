#ifndef _PACKET_LIBVIRT_H_
#define _PACKET_LIBVIRT_H_

#include "libvirt-const.h"

#ifndef LIBVIRT_PORT
#define LIBVIRT_PORT 16509
#endif

typedef struct vir_pld_field_def vir_pld_field_def_t;
struct vir_pld_field_def {
    const char      *name;
    const guint      type;
    const uintptr_t  data;
};
typedef struct vir_pld_anon_field_def vir_pld_anon_field_def_t;
struct vir_pld_anon_field_def {
    const guint     type;
    const uintptr_t data;
};

typedef struct vir_pld_def vir_pld_def_t;
struct vir_pld_def {
    guint32              proc;
    vir_pld_field_def_t *def;
};

#define VIR_PLD_DEF_NULL { NULL, 0, 0 }
#define VIR_PLD_ANON_DEF_NULL { 0, 0 }

#define VIR_PLD_DEF_TOANON(def) ((vir_pld_anon_field_def_t *)&(def)->type)
#define VIR_ARR_W_SIZE(ary) (ary), array_length(ary)

/* Load each programs definition list */
#include "libvirt-remote-def.h"
#include "libvirt-qemu-def.h"
#include "libvirt-lxc-def.h"

#endif /* _PACKET_LIBVIRT_H_ */

#ifndef _LIBVIRT_CONST_H_
#define _LIBVIRT_CONST_H_

enum xdr_type {
    XDR_INT = 1,
    XDR_UINT,
    XDR_ENUM,
    XDR_BOOL,
    XDR_HINT,
    XDR_HUINT,
    XDR_FLOAT,
    XDR_DOUBLE,
    XDR_OPAQUE,
    XDR_VOPAQUE,
    XDR_POINTER,
    XDR_STRING,
    XDR_ARRAY,
    XDR_VARRAY,
    XDR_STRUCT,
    XDR_UNION,
    XDR_VOID,
    XDR_CONSTANT,
    XDR_TYPEDEF,
};

enum vir_net_message_type {
    VIR_NET_CALL = 0,
    VIR_NET_REPLY = 1,
    VIR_NET_MESSAGE = 2,
    VIR_NET_STREAM = 3,
    VIR_NET_CALL_WITH_FDS = 4,
    VIR_NET_REPLY_WITH_FDS = 5,
};

enum vir_net_message_status {
    VIR_NET_OK = 0,
    VIR_NET_ERROR = 1,
    VIR_NET_CONTINUE = 2,
};

enum vir_rpc_program {
    VIR_PROG_REMOTE = 0x20008086,
    VIR_PROG_QEMU = 0x20008087,
    VIR_PROG_LXC = 0x00068000,
};

static const value_string program_strings[] = {
    { VIR_PROG_REMOTE, "REMOTE" },
    { VIR_PROG_QEMU, "QEMU" },
    { VIR_PROG_LXC,  "LXC" },
    { 0, NULL }
};

static const value_string type_strings[] = {
    { VIR_NET_CALL, "CALL" },
    { VIR_NET_REPLY, "REPLY" },
    { VIR_NET_MESSAGE, "MESSAGE" },
    { VIR_NET_STREAM, "STREAM" },
    { VIR_NET_CALL_WITH_FDS, "STREAM" },
    { VIR_NET_REPLY_WITH_FDS, "STREAM" },
    {-1, NULL}
};

static const value_string status_strings[] = {
    { VIR_NET_OK, "OK" },
    { VIR_NET_ERROR, "ERROR" },
    { VIR_NET_CONTINUE, "CONTINUE" },
    { -1, NULL },
};

/* TODO: outdated */
static const value_string remote_procedure_strings [] = {
    { 1, "OPEN" },
    { 2, "CLOSE" },
    { 3, "GET_TYPE" },
    { 4, "GET_VERSION" },
    { 5, "GET_MAX_VCPUS" },
    { 6, "NODE_GET_INFO" },
    { 7, "GET_CAPABILITIES" },
    { 8, "DOMAIN_ATTACH_DEVICE" },
    { 9, "DOMAIN_CREATE" },
    { 10, "DOMAIN_CREATE_XML" },
    { 11, "DOMAIN_DEFINE_XML" },
    { 12, "DOMAIN_DESTROY" },
    { 13, "DOMAIN_DETACH_DEVICE" },
    { 14, "DOMAIN_GET_XML_DESC" },
    { 15, "DOMAIN_GET_AUTOSTART" },
    { 16, "DOMAIN_GET_INFO" },
    { 17, "DOMAIN_GET_MAX_MEMORY" },
    { 18, "DOMAIN_GET_MAX_VCPUS" },
    { 19, "DOMAIN_GET_OS_TYPE" },
    { 20, "DOMAIN_GET_VCPUS" },
    { 21, "LIST_DEFINED_DOMAINS" },
    { 22, "DOMAIN_LOOKUP_BY_ID" },
    { 23, "DOMAIN_LOOKUP_BY_NAME" },
    { 24, "DOMAIN_LOOKUP_BY_UUID" },
    { 25, "NUM_OF_DEFINED_DOMAINS" },
    { 26, "DOMAIN_PIN_VCPU" },
    { 27, "DOMAIN_REBOOT" },
    { 28, "DOMAIN_RESUME" },
    { 29, "DOMAIN_SET_AUTOSTART" },
    { 30, "DOMAIN_SET_MAX_MEMORY" },
    { 31, "DOMAIN_SET_MEMORY" },
    { 32, "DOMAIN_SET_VCPUS" },
    { 33, "DOMAIN_SHUTDOWN" },
    { 34, "DOMAIN_SUSPEND" },
    { 35, "DOMAIN_UNDEFINE" },
    { 36, "LIST_DEFINED_NETWORKS" },
    { 37, "LIST_DOMAINS" },
    { 38, "LIST_NETWORKS" },
    { 39, "NETWORK_CREATE" },
    { 40, "NETWORK_CREATE_XML" },
    { 41, "NETWORK_DEFINE_XML" },
    { 42, "NETWORK_DESTROY" },
    { 43, "NETWORK_GET_XML_DESC" },
    { 44, "NETWORK_GET_AUTOSTART" },
    { 45, "NETWORK_GET_BRIDGE_NAME" },
    { 46, "NETWORK_LOOKUP_BY_NAME" },
    { 47, "NETWORK_LOOKUP_BY_UUID" },
    { 48, "NETWORK_SET_AUTOSTART" },
    { 49, "NETWORK_UNDEFINE" },
    { 50, "NUM_OF_DEFINED_NETWORKS" },
    { 51, "NUM_OF_DOMAINS" },
    { 52, "NUM_OF_NETWORKS" },
    { 53, "DOMAIN_CORE_DUMP" },
    { 54, "DOMAIN_RESTORE" },
    { 55, "DOMAIN_SAVE" },
    { 56, "DOMAIN_GET_SCHEDULER_TYPE" },
    { 57, "DOMAIN_GET_SCHEDULER_PARAMETERS" },
    { 58, "DOMAIN_SET_SCHEDULER_PARAMETERS" },
    { 59, "GET_HOSTNAME" },
    { 60, "SUPPORTS_FEATURE" },
    { 61, "DOMAIN_MIGRATE_PREPARE" },
    { 62, "DOMAIN_MIGRATE_PERFORM" },
    { 63, "DOMAIN_MIGRATE_FINISH" },
    { 64, "DOMAIN_BLOCK_STATS" },
    { 65, "DOMAIN_INTERFACE_STATS" },
    { 66, "AUTH_LIST" },
    { 67, "AUTH_SASL_INIT" },
    { 68, "AUTH_SASL_START" },
    { 69, "AUTH_SASL_STEP" },
    { 70, "AUTH_POLKIT" },
    { 71, "NUM_OF_STORAGE_POOLS" },
    { 72, "LIST_STORAGE_POOLS" },
    { 73, "NUM_OF_DEFINED_STORAGE_POOLS" },
    { 74, "LIST_DEFINED_STORAGE_POOLS" },
    { 75, "FIND_STORAGE_POOL_SOURCES" },
    { 76, "STORAGE_POOL_CREATE_XML" },
    { 77, "STORAGE_POOL_DEFINE_XML" },
    { 78, "STORAGE_POOL_CREATE" },
    { 79, "STORAGE_POOL_BUILD" },
    { 80, "STORAGE_POOL_DESTROY" },
    { 81, "STORAGE_POOL_DELETE" },
    { 82, "STORAGE_POOL_UNDEFINE" },
    { 83, "STORAGE_POOL_REFRESH" },
    { 84, "STORAGE_POOL_LOOKUP_BY_NAME" },
    { 85, "STORAGE_POOL_LOOKUP_BY_UUID" },
    { 86, "STORAGE_POOL_LOOKUP_BY_VOLUME" },
    { 87, "STORAGE_POOL_GET_INFO" },
    { 88, "STORAGE_POOL_GET_XML_DESC" },
    { 89, "STORAGE_POOL_GET_AUTOSTART" },
    { 90, "STORAGE_POOL_SET_AUTOSTART" },
    { 91, "STORAGE_POOL_NUM_OF_VOLUMES" },
    { 92, "STORAGE_POOL_LIST_VOLUMES" },
    { 93, "STORAGE_VOL_CREATE_XML" },
    { 94, "STORAGE_VOL_DELETE" },
    { 95, "STORAGE_VOL_LOOKUP_BY_NAME" },
    { 96, "STORAGE_VOL_LOOKUP_BY_KEY" },
    { 97, "STORAGE_VOL_LOOKUP_BY_PATH" },
    { 98, "STORAGE_VOL_GET_INFO" },
    { 99, "STORAGE_VOL_GET_XML_DESC" },
    { 100, "STORAGE_VOL_GET_PATH" },
    { 101, "NODE_GET_CELLS_FREE_MEMORY" },
    { 102, "NODE_GET_FREE_MEMORY" },
    { 103, "DOMAIN_BLOCK_PEEK" },
    { 104, "DOMAIN_MEMORY_PEEK" },
    { 105, "DOMAIN_EVENTS_REGISTER" },
    { 106, "DOMAIN_EVENTS_DEREGISTER" },
    { 107, "DOMAIN_EVENT_LIFECYCLE" },
    { 108, "DOMAIN_MIGRATE_PREPARE2" },
    { 109, "DOMAIN_MIGRATE_FINISH2" },
    { 110, "GET_URI" },
    { 111, "NODE_NUM_OF_DEVICES" },
    { 112, "NODE_LIST_DEVICES" },
    { 113, "NODE_DEVICE_LOOKUP_BY_NAME" },
    { 114, "NODE_DEVICE_GET_XML_DESC" },
    { 115, "NODE_DEVICE_GET_PARENT" },
    { 116, "NODE_DEVICE_NUM_OF_CAPS" },
    { 117, "NODE_DEVICE_LIST_CAPS" },
    { 118, "NODE_DEVICE_DETTACH" },
    { 119, "NODE_DEVICE_RE_ATTACH" },
    { 120, "NODE_DEVICE_RESET" },
    { 121, "DOMAIN_GET_SECURITY_LABEL" },
    { 122, "NODE_GET_SECURITY_MODEL" },
    { 123, "NODE_DEVICE_CREATE_XML" },
    { 124, "NODE_DEVICE_DESTROY" },
    { 125, "STORAGE_VOL_CREATE_XML_FROM" },
    { 126, "NUM_OF_INTERFACES" },
    { 127, "LIST_INTERFACES" },
    { 128, "INTERFACE_LOOKUP_BY_NAME" },
    { 129, "INTERFACE_LOOKUP_BY_MAC_STRING" },
    { 130, "INTERFACE_GET_XML_DESC" },
    { 131, "INTERFACE_DEFINE_XML" },
    { 132, "INTERFACE_UNDEFINE" },
    { 133, "INTERFACE_CREATE" },
    { 134, "INTERFACE_DESTROY" },
    { 135, "DOMAIN_XML_FROM_NATIVE" },
    { 136, "DOMAIN_XML_TO_NATIVE" },
    { 137, "NUM_OF_DEFINED_INTERFACES" },
    { 138, "LIST_DEFINED_INTERFACES" },
    { 139, "NUM_OF_SECRETS" },
    { 140, "LIST_SECRETS" },
    { 141, "SECRET_LOOKUP_BY_UUID" },
    { 142, "SECRET_DEFINE_XML" },
    { 143, "SECRET_GET_XML_DESC" },
    { 144, "SECRET_SET_VALUE" },
    { 145, "SECRET_GET_VALUE" },
    { 146, "SECRET_UNDEFINE" },
    { 147, "SECRET_LOOKUP_BY_USAGE" },
    { 148, "DOMAIN_MIGRATE_PREPARE_TUNNEL" },
    { 149, "IS_SECURE" },
    { 150, "DOMAIN_IS_ACTIVE" },
    { 151, "DOMAIN_IS_PERSISTENT" },
    { 152, "NETWORK_IS_ACTIVE" },
    { 153, "NETWORK_IS_PERSISTENT" },
    { 154, "STORAGE_POOL_IS_ACTIVE" },
    { 155, "STORAGE_POOL_IS_PERSISTENT" },
    { 156, "INTERFACE_IS_ACTIVE" },
    { 157, "GET_LIB_VERSION" },
    { 158, "CPU_COMPARE" },
    { 159, "DOMAIN_MEMORY_STATS" },
    { 160, "DOMAIN_ATTACH_DEVICE_FLAGS" },
    { 161, "DOMAIN_DETACH_DEVICE_FLAGS" },
    { 162, "CPU_BASELINE" },
    { 163, "DOMAIN_GET_JOB_INFO" },
    { 164, "DOMAIN_ABORT_JOB" },
    { 165, "STORAGE_VOL_WIPE" },
    { 166, "DOMAIN_MIGRATE_SET_MAX_DOWNTIME" },
    { 167, "DOMAIN_EVENTS_REGISTER_ANY" },
    { 168, "DOMAIN_EVENTS_DEREGISTER_ANY" },
    { 169, "DOMAIN_EVENT_REBOOT" },
    { 170, "DOMAIN_EVENT_RTC_CHANGE" },
    { 171, "DOMAIN_EVENT_WATCHDOG" },
    { 172, "DOMAIN_EVENT_IO_ERROR" },
    { 173, "DOMAIN_EVENT_GRAPHICS" },
    { 174, "DOMAIN_UPDATE_DEVICE_FLAGS" },
    { 175, "NWFILTER_LOOKUP_BY_NAME" },
    { 176, "NWFILTER_LOOKUP_BY_UUID" },
    { 177, "NWFILTER_GET_XML_DESC" },
    { 178, "NUM_OF_NWFILTERS" },
    { 179, "LIST_NWFILTERS" },
    { 180, "NWFILTER_DEFINE_XML" },
    { 181, "NWFILTER_UNDEFINE" },
    { 182, "DOMAIN_MANAGED_SAVE" },
    { 183, "DOMAIN_HAS_MANAGED_SAVE_IMAGE" },
    { 184, "DOMAIN_MANAGED_SAVE_REMOVE" },
    { 185, "DOMAIN_SNAPSHOT_CREATE_XML" },
    { 186, "DOMAIN_SNAPSHOT_GET_XML_DESC" },
    { 187, "DOMAIN_SNAPSHOT_NUM" },
    { 188, "DOMAIN_SNAPSHOT_LIST_NAMES" },
    { 189, "DOMAIN_SNAPSHOT_LOOKUP_BY_NAME" },
    { 190, "DOMAIN_HAS_CURRENT_SNAPSHOT" },
    { 191, "DOMAIN_SNAPSHOT_CURRENT" },
    { 192, "DOMAIN_REVERT_TO_SNAPSHOT" },
    { 193, "DOMAIN_SNAPSHOT_DELETE" },
    { 194, "DOMAIN_GET_BLOCK_INFO" },
    { 195, "DOMAIN_EVENT_IO_ERROR_REASON" },
    { 196, "DOMAIN_CREATE_WITH_FLAGS" },
    { 197, "DOMAIN_SET_MEMORY_PARAMETERS" },
    { 198, "DOMAIN_GET_MEMORY_PARAMETERS" },
    { 199, "DOMAIN_SET_VCPUS_FLAGS" },
    { 200, "DOMAIN_GET_VCPUS_FLAGS" },
    { 201, "DOMAIN_OPEN_CONSOLE" },
    { 202, "DOMAIN_IS_UPDATED" },
    { 203, "GET_SYSINFO" },
    { 204, "DOMAIN_SET_MEMORY_FLAGS" },
    { 205, "DOMAIN_SET_BLKIO_PARAMETERS" },
    { 206, "DOMAIN_GET_BLKIO_PARAMETERS" },
    { 207, "DOMAIN_MIGRATE_SET_MAX_SPEED" },
    { 208, "STORAGE_VOL_UPLOAD" },
    { 209, "STORAGE_VOL_DOWNLOAD" },
    { 210, "DOMAIN_INJECT_NMI" },
    { 211, "DOMAIN_SCREENSHOT" },
    { 212, "DOMAIN_GET_STATE" },
    { 213, "DOMAIN_MIGRATE_BEGIN3" },
    { 214, "DOMAIN_MIGRATE_PREPARE3" },
    { 215, "DOMAIN_MIGRATE_PREPARE_TUNNEL3" },
    { 216, "DOMAIN_MIGRATE_PERFORM3" },
    { 217, "DOMAIN_MIGRATE_FINISH3" },
    { 218, "DOMAIN_MIGRATE_CONFIRM3" },
    { 219, "DOMAIN_SET_SCHEDULER_PARAMETERS_FLAGS" },
    { 220, "INTERFACE_CHANGE_BEGIN" },
    { 221, "INTERFACE_CHANGE_COMMIT" },
    { 222, "INTERFACE_CHANGE_ROLLBACK" },
    { 223, "DOMAIN_GET_SCHEDULER_PARAMETERS_FLAGS" },
    { 224, "DOMAIN_EVENT_CONTROL_ERROR" },
    { 225, "DOMAIN_PIN_VCPU_FLAGS" },
    { 226, "DOMAIN_SEND_KEY" },
    { 227, "NODE_GET_CPU_STATS" },
    { 228, "NODE_GET_MEMORY_STATS" },
    { 229, "DOMAIN_GET_CONTROL_INFO" },
    { 230, "DOMAIN_GET_VCPU_PIN_INFO" },
    { 231, "DOMAIN_UNDEFINE_FLAGS" },
    { 232, "DOMAIN_SAVE_FLAGS" },
    { 233, "DOMAIN_RESTORE_FLAGS" },
    { 234, "DOMAIN_DESTROY_FLAGS" },
    { 235, "DOMAIN_SAVE_IMAGE_GET_XML_DESC" },
    { 236, "DOMAIN_SAVE_IMAGE_DEFINE_XML" },
    { 237, "DOMAIN_BLOCK_JOB_ABORT" },
    { 238, "DOMAIN_GET_BLOCK_JOB_INFO" },
    { 239, "DOMAIN_BLOCK_JOB_SET_SPEED" },
    { 240, "DOMAIN_BLOCK_PULL" },
    { 241, "DOMAIN_EVENT_BLOCK_JOB" },
    { 242, "DOMAIN_MIGRATE_GET_MAX_SPEED" },
    { 243, "DOMAIN_BLOCK_STATS_FLAGS" },
    { 244, "DOMAIN_SNAPSHOT_GET_PARENT" },
    { 245, "DOMAIN_RESET" },
    {   0, NULL}
};

/* TODO: outdated */
static const value_string qemu_procedure_strings[] = {
    { 1, "MONITOR_COMMAND" },
    { 2, "DOMAIN_ATTACH" },
    { 0, NULL}
};

#endif /* _LIBVIRT_CONST_H_ */
/* Generated by IDL compiler version FreeDCE 1.1.0.7 with GNU Flex/Bison */
#ifndef sec_id_base_v0_0_included
#define sec_id_base_v0_0_included
#ifndef IDLBASE_H
#include <dce/idlbase.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#ifndef nbase_v0_0_included
#include <dce/nbase.h>
#endif
typedef struct sec_id_t {
idl_uuid_t uuid;
idl_char *name;
} sec_id_t;
typedef struct sec_id_foreign_t {
sec_id_t id;
sec_id_t realm;
} sec_id_foreign_t;
typedef struct sec_id_foreign_groupset_t {
sec_id_t realm;
unsigned16 num_groups;
sec_id_t *groups;
} sec_id_foreign_groupset_t;
typedef enum {sec_id_pac_format_v1 = 0,
sec_id_pac_format_raw = 1} sec_id_pac_format_t;
#define sec_id_authz_data_dce (64)
#define sec_id_authz_data_sesame (65)
#define sec_id_authz_data_mspac (128)
typedef struct sec_id_pac_format_v1_t {
sec_id_t realm;
sec_id_t principal;
sec_id_t group;
unsigned16 num_groups;
unsigned16 num_foreign_groups;
sec_id_t *groups;
sec_id_t *foreign_groups;
} sec_id_pac_format_v1_t;
typedef struct sec_id_pac_format_raw_t {
unsigned32 type;
unsigned32 length;
idl_byte *value;
} sec_id_pac_format_raw_t;
typedef union sec_id_pac_rep_t {
/* case(s): 0 */
sec_id_pac_format_v1_t v1_pac;
/* case(s): 1 */
sec_id_pac_format_raw_t raw_pac;
} sec_id_pac_rep_t;
typedef struct sec_id_pac_t {
sec_id_pac_format_t pac_type;
boolean32 authenticated;
sec_id_pac_rep_t pac;
} sec_id_pac_t;
typedef struct sec_id_pickled_pac_t {
ndr_format_t format_label;
unsigned32 num_bytes;
idl_byte pickled_data[1];
} sec_id_pickled_pac_t;
typedef struct rpc_np_sec_context_t {
unsigned32 Length;
unsigned32 Version;
unsigned32 UserNameLength;
idl_char *UserName;
unsigned32 DomainNameLength;
idl_char *DomainName;
unsigned32 WorkstationLength;
idl_char *Workstation;
unsigned32 SessionKeyLength;
idl_char *SessionKey;
} rpc_np_sec_context_t;
typedef rpc_np_sec_context_t *rpc_np_sec_context_p_t;

#ifdef __cplusplus
    }
#endif

#endif

/* Generated by IDL compiler version FreeDCE 1.1.0.7 with GNU Flex/Bison */
#ifndef lrpc_v0_0_included
#define lrpc_v0_0_included
#ifndef IDLBASE_H
#include <dce/idlbase.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#ifndef nbase_v0_0_included
#include <dce/nbase.h>
#endif
#ifndef lbase_v0_0_included
#include <dce/lbase.h>
#endif
#ifndef rpcbase_v0_0_included
#include <dce/rpcbase.h>
#endif
extern void rpc_lrpc_transport_info_free(
    /* [in] */ rpc_transport_info_handle_t info
);
extern void rpc_lrpc_transport_info_inq_peer_eid(
    /* [in] */ rpc_transport_info_handle_t info,
    /* [out] */ unsigned32 *uid,
    /* [out] */ unsigned32 *gid
);

#ifdef __cplusplus
    }
#endif

#endif

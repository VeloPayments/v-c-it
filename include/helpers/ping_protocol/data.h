/**
 * \file vcblockchain/protocol/data.h
 *
 * \brief Data for ping protocol.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#pragma once

#include <vccrypt/buffer.h>
#include <vpr/disposable.h>
#include <vpr/uuid.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

typedef struct ping_protocol_req_ping
ping_protocol_req_ping;

struct ping_protocol_req_ping
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    uint32_t offset;
};

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif /*__cplusplus*/

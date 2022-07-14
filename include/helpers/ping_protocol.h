/**
 * \file helpers/ping_protocol.h
 *
 * \brief Simple ping protocol to test the extended API.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#pragma once

#include <rcpr/status.h>
#include <vcblockchain/ssock.h>

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

/**
 * \brief Send a ping request to the extended ping API.
 *
 * \param sock          The socket to which this request is written.
 * \param suite         The crypto suite to use for this request.
 * \param client_iv     Pointer to the client IV, updated by this call.
 * \param shared_secret The shared secret to use ofr this request.
 * \param offset        The offset for this request.
 */
status ping_protocol_sendreq_ping(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    vccrypt_buffer_t* shared_secret, uint32_t offset);

#if defined(__cplusplus)
}
#endif /*defined(__cplusplus)*/

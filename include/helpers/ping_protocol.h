/**
 * \file helpers/ping_protocol.h
 *
 * \brief Simple ping protocol to test the extended API.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#pragma once

#include <rcpr/psock.h>
#include <rcpr/status.h>
#include <vcblockchain/protocol.h>

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
 * \param payload       Payload to copy to the ping request.
 */
status ping_protocol_sendreq_ping(
    RCPR_SYM(psock)* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    vccrypt_buffer_t* shared_secret,
    const vpr_uuid* ping_sentinel_id, uint32_t offset,
    const vccrypt_buffer_t* payload);

/**
 * \brief Send a ping response request to the extended ping API.
 *
 * \param sock          The socket to which this request is written.
 * \param suite         The crypto suite to use for this request.
 * \param client_iv     Pointer to the client IV, updated by this call.
 * \param shared_secret The shared secret to use ofr this request.
 * \param offset        The offset for this request.
 * \param status        The status code for this request.
 * \param payload       Payload to copy to the ping response.
 */
status ping_protocol_sendreq_ping_response(
    RCPR_SYM(psock)* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    vccrypt_buffer_t* shared_secret, uint64_t offset, uint32_t status_code,
    const vccrypt_buffer_t* payload);

#if defined(__cplusplus)
}
#endif /*defined(__cplusplus)*/

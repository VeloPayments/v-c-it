/**
 * \file helpers/ping_protocol/ping_protocol_sendreq_ping_response.c
 *
 * \brief Send a ping response request to the ping sentinel using the extended
 * API.
 *
 * \copyright 2022-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <helpers/ping_protocol.h>
#include <vcblockchain/protocol.h>

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
    const vccrypt_buffer_t* payload)
{
    /* send response request. */
    return
        vcblockchain_protocol_sendreq_extended_api_response(
            sock, suite, client_iv, shared_secret, offset, status_code,
            payload);
}

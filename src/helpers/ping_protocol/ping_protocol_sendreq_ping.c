/**
 * \file helpers/ping_protocol/ping_protocol_sendreq_ping.c
 *
 * \brief Send a ping request to the ping sentinel using the extended API.
 *
 * \copyright 2022-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <helpers/ping_protocol.h>
#include <helpers/ping_protocol/verbs.h>
#include <vcblockchain/protocol.h>

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
    const vccrypt_buffer_t* payload)
{
    /* send request. */
    return
        vcblockchain_protocol_sendreq_extended_api(
            sock, suite, client_iv, shared_secret, offset, ping_sentinel_id,
            &HELPERS_PING_PROTOCOL_VERB_PING, payload);
}

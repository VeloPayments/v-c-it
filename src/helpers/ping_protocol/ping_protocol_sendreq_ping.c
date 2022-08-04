/**
 * \file helpers/ping_protocol/ping_protocol_sendreq_ping.c
 *
 * \brief Send a ping request to the ping sentinel using the extended API.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
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
 */
status ping_protocol_sendreq_ping(
    RCPR_SYM(psock)* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    vccrypt_buffer_t* shared_secret,
    const vpr_uuid* ping_sentinel_id, uint32_t offset)
{
    status retval;
    vccrypt_buffer_t payload;

    /* create dummy request body. */
    retval = vccrypt_buffer_init(&payload, suite->alloc_opts, 1);
    if (STATUS_SUCCESS != retval)
    {
        goto done;
    }

    /* send request. */
    retval =
        vcblockchain_protocol_sendreq_extended_api(
            sock, suite, client_iv, shared_secret, offset, ping_sentinel_id,
            &HELPERS_PING_PROTOCOL_VERB_PING, &payload);
    goto cleanup_payload;

cleanup_payload:
    dispose((disposable_t*)&payload);

done:
    return retval;
}

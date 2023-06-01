/**
 * \file helpers/send_and_verify_ping_request.c
 *
 * \brief Send and verify the extended api ping request and response.
 *
 * \copyright 2022-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <helpers/conn_helpers.h>
#include <helpers/ping_protocol.h>
#include <helpers/status_codes.h>
#include <stdio.h>
#include <string.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Send an extended api ping protocol request and response.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param offset            The offset to use for this request.
 * \param ping_sentinel_id  The UUID of the ping sentinel.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status send_and_verify_ping_request(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, uint32_t offset,
    const vpr_uuid* ping_sentinel_id)
{
    status retval;
    vccrypt_buffer_t ping_request_response;
    uint32_t request_id, resp_offset, status_code;
    protocol_resp_extended_api ping_resp;
    vccrypt_buffer_t payload;

    /* create the ping payload */
    retval = vccrypt_buffer_init(&payload, suite->alloc_opts, 1);
    if (STATUS_SUCCESS != retval)
    {
        goto done;
    }

    /* send the ping protocol request. */
    retval =
        ping_protocol_sendreq_ping(
            sock, suite, client_iv, shared_secret, ping_sentinel_id, offset,
            &payload);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(
            stderr, "Failed to send extended api ping request. (%x).\n",
            retval);
        retval = ERROR_PING_REQUEST_SEND;
        goto cleanup_payload;
    }

    /* get the response. */
    retval =
        vcblockchain_protocol_recvresp(
            sock, alloc, suite, server_iv, shared_secret,
            &ping_request_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Failed to receive extended api ping response.\n");
        retval = ERROR_PING_RESPONSE_RECEIVE;
        goto cleanup_payload;
    }

    /* decode the response header. */
    retval =
        vcblockchain_protocol_response_decode_header(
            &request_id, &resp_offset, &status_code, &ping_request_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error decoding extended api ping response.\n");
        retval = ERROR_PING_RESPONSE_DECODE_HEADER;
        goto cleanup_buffer;
    }

    /* verify that the request id matches. */
    if (PROTOCOL_REQ_ID_EXTENDED_API_SENDRECV != request_id)
    {
        fprintf(
            stderr, "Unexpected extended api ping response id (%x).\n",
            request_id);
        retval = ERROR_PING_RESPONSE_ID;
    }

    /* verify that the status was successful. */
    if (STATUS_SUCCESS != status_code)
    {
        fprintf(
            stderr, "Unexpected extended api ping response status (%x).\n",
            status_code);
        retval = ERROR_PING_RESPONSE_STATUS_CODE;
    }

    /* verify that the offset is correct. */
    if (offset != resp_offset)
    {
        fprintf(
            stderr, "Unexpected extended api ping response offset (%x).\n",
            resp_offset);
        retval = ERROR_PING_RESPONSE_OFFSET;
    }

    /* if we failed one of the checks above, error out. */
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_buffer;
    }

    /* decode the response. */
    retval =
        vcblockchain_protocol_decode_resp_extended_api(
            &ping_resp, suite->alloc_opts, ping_request_response.data,
            ping_request_response.size);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(
            stderr, "Could not decode extended api ping response (%x).\n",
            retval);
        retval = ERROR_PING_RESPONSE_DECODE;
        goto cleanup_buffer;
    }

    /* success. */
    retval = STATUS_SUCCESS;
    goto cleanup_response;

cleanup_response:
    dispose((disposable_t*)&ping_resp);

cleanup_buffer:
    dispose((disposable_t*)&ping_request_response);

cleanup_payload:
    dispose(&payload.hdr);

done:
    return retval;
}

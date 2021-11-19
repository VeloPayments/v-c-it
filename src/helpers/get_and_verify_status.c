/**
 * \file helpers/get_and_verify_status.c
 *
 * \brief Get and verify the connection status.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <helpers/conn_helpers.h>
#include <helpers/status_codes.h>
#include <stdio.h>
#include <string.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Get and verify the connection status.
 *
 * \param sock              The socket connection with agentd.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_status(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    uint64_t* server_iv, vccrypt_buffer_t* shared_secret)
{
    status retval;
    uint32_t expected_get_status_offset = 0x3133;
    vccrypt_buffer_t get_status_response;
    protocol_resp_status_get get_status_resp;
    uint32_t request_id, status, offset;

    /* parameter sanity checks. */
    MODEL_ASSERT(prop_ssock_valid(sock));
    MODEL_ASSERT(prop_crypto_suite_valid(suite));
    MODEL_ASSERT(NULL != client_iv);
    MODEL_ASSERT(NULL != server_iv);
    MODEL_ASSERT(prop_buffer_valid(shared_secret));

    /* get status. */
    retval =
        vcblockchain_protocol_sendreq_status_get(
            sock, suite, client_iv, shared_secret,
            expected_get_status_offset);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Failed to send status req. (%x).\n", retval);
        retval = ERROR_SEND_STATUS_REQ;
        goto done;
    }

    /* get response. */
    retval =
        vcblockchain_protocol_recvresp(
            sock, suite, server_iv, shared_secret,
            &get_status_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Failed to receive get status response.\n");
        retval = ERROR_RECV_STATUS_RESP;
        goto done;
    }

    /* decode the response header. */
    retval =
        vcblockchain_protocol_response_decode_header(
            &request_id, &offset, &status, &get_status_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error decoding response from get_status.\n");
        retval = ERROR_DECODE_STATUS;
        goto cleanup_get_status_response;
    }

    /* verify that the request id matches. */
    if (PROTOCOL_REQ_ID_STATUS_GET != request_id)
    {
        fprintf(stderr, "Unexpected request id (%x).\n", request_id);
        retval = ERROR_STATUS_REQUEST_ID;
        goto cleanup_get_status_response;
    }

    /* verify that the status was successful. */
    if (STATUS_SUCCESS != status)
    {
        fprintf(stderr, "Unexpected get status status (%x).\n", status);
        retval = ERROR_STATUS_STATUS;
        goto cleanup_get_status_response;
    }

    /* verify that the offset is correct. */
    if (expected_get_status_offset != offset)
    {
        fprintf(stderr, "Unexpected get status offset (%x).\n", offset);
        retval = ERROR_STATUS_OFFSET;
        goto cleanup_get_status_response;
    }

    /* decode the response. */
    retval =
        vcblockchain_protocol_decode_resp_status_get(
            &get_status_resp, get_status_response.data,
            get_status_response.size);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(
            stderr, "Could not decode get status response (%x).\n", retval);
        retval = ERROR_DECODE_STATUS_DATA;
        goto cleanup_get_status_response;
    }

    /* success. */
    retval = STATUS_SUCCESS;
    goto cleanup_get_status_resp;

cleanup_get_status_resp:
    dispose((disposable_t*)&get_status_resp);

cleanup_get_status_response:
    dispose((disposable_t*)&get_status_response);

done:
    return retval;
}

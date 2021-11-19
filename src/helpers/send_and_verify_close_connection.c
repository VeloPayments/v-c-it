/**
 * \file helpers/send_and_verify_close_connection.c
 *
 * \brief Send and verify the close connection request.
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
 * \brief Send and verify the close connection request.
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
status send_and_verify_close_connection(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    uint64_t* server_iv, vccrypt_buffer_t* shared_secret)
{
    status retval;
    uint32_t expected_close_connection_offset = 0x3133;
    vccrypt_buffer_t close_connection_response;
    protocol_resp_connection_close close_connection_resp;
    uint32_t request_id, status, offset;

    /* parameter sanity checks. */
    MODEL_ASSERT(prop_ssock_valid(sock));
    MODEL_ASSERT(prop_crypto_suite_valid(suite));
    MODEL_ASSERT(NULL != client_iv);
    MODEL_ASSERT(NULL != server_iv);
    MODEL_ASSERT(prop_buffer_valid(shared_secret));

    /* close connection. */
    retval =
        vcblockchain_protocol_sendreq_connection_close(
            sock, suite, client_iv, shared_secret,
            expected_close_connection_offset);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Failed to send close connection. (%x).\n", retval);
        retval = ERROR_SEND_CLOSE_REQ;
        goto done;
    }

    /* get response. */
    retval =
        vcblockchain_protocol_recvresp(
            sock, suite, server_iv, shared_secret,
            &close_connection_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Failed to receive close connection response.\n");
        retval = ERROR_RECV_CLOSE_RESP;
        goto done;
    }

    /* decode the response header. */
    retval =
        vcblockchain_protocol_response_decode_header(
            &request_id, &offset, &status, &close_connection_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error decoding response from close_connection.\n");
        retval = ERROR_DECODE_CLOSE;
        goto cleanup_close_connection_response;
    }

    /* verify that the request id matches. */
    if (PROTOCOL_REQ_ID_CLOSE != request_id)
    {
        fprintf(stderr, "Unexpected request id (%x).\n", request_id);
        retval = ERROR_CLOSE_REQUEST_ID;
        goto cleanup_close_connection_response;
    }

    /* verify that the status was successful. */
    if (STATUS_SUCCESS != status)
    {
        fprintf(stderr, "Unexpected get status status (%x).\n", status);
        retval = ERROR_CLOSE_STATUS;
        goto cleanup_close_connection_response;
    }

    /* verify that the offset is correct. */
    if (expected_close_connection_offset != offset)
    {
        fprintf(stderr, "Unexpected close connection offset (%x).\n", offset);
        retval = ERROR_CLOSE_OFFSET;
        goto cleanup_close_connection_response;
    }

    /* decode the response. */
    retval =
        vcblockchain_protocol_decode_resp_connection_close(
            &close_connection_resp, close_connection_response.data,
            close_connection_response.size);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(
            stderr, "Could not decode close response (%x).\n", retval);
        retval = ERROR_DECODE_CLOSE_DATA;
        goto cleanup_close_connection_response;
    }

    /* success. */
    retval = STATUS_SUCCESS;
    goto cleanup_close_connection_resp;

cleanup_close_connection_resp:
    dispose((disposable_t*)&close_connection_resp);

cleanup_close_connection_response:
    dispose((disposable_t*)&close_connection_response);

done:
    return retval;
}

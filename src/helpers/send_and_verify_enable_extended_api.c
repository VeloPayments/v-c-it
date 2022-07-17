/**
 * \file helpers/send_and_verify_enable_extended_api.c
 *
 * \brief Send and verify the enable extended API request.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <helpers/conn_helpers.h>
#include <helpers/status_codes.h>
#include <stdio.h>
#include <string.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Request that the extended API be enabled for this entity on this
 * connection.
 *
 * \param sock              The socket connection with agentd.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param offset            The offset to use for this request.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status send_and_verify_enable_extended_api(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    uint64_t* server_iv, vccrypt_buffer_t* shared_secret, uint32_t offset)
{
    status retval;
    vccrypt_buffer_t enable_extended_api_response;
    uint32_t request_id, status, resp_offset;
    protocol_resp_extended_api_enable extended_api_enable_resp;

    /* parameter sanity checks. */
    MODEL_ASSERT(prop_ssock_valid(sock));
    MODEL_ASSERT(prop_crypto_suite_valid(suite));
    MODEL_ASSERT(NULL != client_iv);
    MODEL_ASSERT(NULL != server_iv);
    MODEL_ASSERT(prop_buffer_valid(shared_secret));

    /* send the extended API enable request. */
    retval =
        vcblockchain_protocol_sendreq_extended_api_enable(
            sock, suite, client_iv, shared_secret, offset);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(
            stderr, "Failed to send extended api enable request. (%x).\n",
            retval);
        retval = ERROR_EXTENDED_API_ENABLE_REQ;
        goto done;
    }

    /* get response. */
    retval =
        vcblockchain_protocol_recvresp(
            sock, suite, server_iv, shared_secret,
            &enable_extended_api_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Failed to receive extended api enable response.\n");
        retval = ERROR_RECV_EXTENDED_API_ENABLE_RESP;
        goto done;
    }

    /* decode the response header. */
    retval =
        vcblockchain_protocol_response_decode_header(
            &request_id, &resp_offset, &status, &enable_extended_api_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error decoding response from extended api enable.\n");
        retval = ERROR_DECODE_EXTENDED_API_ENABLE_HEADER;
        goto cleanup_buffer;
    }

    /* verify that the request id matches. */
    if (PROTOCOL_REQ_ID_EXTENDED_API_ENABLE != request_id)
    {
        fprintf(
            stderr, "Unexpected extended api enable request id (%x).\n",
            request_id);
        retval = ERROR_EXTENDED_API_ENABLE_REQUEST_ID;
        goto cleanup_buffer;
    }

    /* verify that the status was successful. */
    if (STATUS_SUCCESS != status)
    {
        fprintf(
            stderr, "Unexpected extended api enable status (%x).\n", status);
        retval = ERROR_EXTENDED_API_ENABLE_STATUS;
        goto cleanup_buffer;
    }

    /* verify that the offset is correct. */
    if (offset != resp_offset)
    {
        fprintf(
            stderr, "Unexpected extended api enable offset (%x).\n",
            resp_offset);
        retval = ERROR_EXTENDED_API_ENABLE_OFFSET;
        goto cleanup_buffer;
    }

    /* decode the response. */
    retval =
        vcblockchain_protocol_decode_resp_extended_api_enable(
            &extended_api_enable_resp, enable_extended_api_response.data,
            enable_extended_api_response.size);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(
            stderr, "Could not decode extended api enable response (%x).\n",
            retval);
        retval = ERROR_DECODE_EXTENDED_API_ENABLE;
        goto cleanup_buffer;
    }

    /* success. */
    retval = STATUS_SUCCESS;
    goto cleanup_response;

cleanup_response:
    dispose((disposable_t*)&extended_api_enable_resp);

cleanup_buffer:
    dispose((disposable_t*)&enable_extended_api_response);

done:
    return retval;
}

/**
 * \file helpers/get_and_verify_last_block_id.c
 *
 * \brief Request the latest block id from agentd.
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
 * \brief Request the current last ID from the agentd instance.
 *
 * \param sock              The socket connection with agentd.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param last_block_id     Variable to hold the last block id on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_last_block_id(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    uint64_t* server_iv, vccrypt_buffer_t* shared_secret,
    vpr_uuid* last_block_id)
{
    status retval;
    vccrypt_buffer_t resp;
    const uint32_t EXPECTED_OFFSET = 0x1337;
    protocol_resp_latest_block_id_get decoded_resp;
    uint32_t request_id, status, offset;

    /* parameter sanity checks. */
    MODEL_ASSERT(prop_ssock_valid(sock));
    MODEL_ASSERT(prop_crypto_suite_valid(suite));
    MODEL_ASSERT(NULL != client_iv);
    MODEL_ASSERT(NULL != server_iv);
    MODEL_ASSERT(prop_buffer_valid(shared_secret));
    MODEL_ASSERT(NULL != last_block_id);

    /* send the get latest block query request. */
    retval =
        vcblockchain_protocol_sendreq_latest_block_id_get(
            sock, suite, client_iv, shared_secret, EXPECTED_OFFSET);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error sending get latest block id request.\n");
        retval = ERROR_SEND_LATEST_BLOCK_ID_REQ;
        goto done;
    }

    /* get a response. */
    retval =
        vcblockchain_protocol_recvresp(
            sock, suite, server_iv, shared_secret, &resp);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(
            stderr, "Error receiving response from agentd. (%x)\n", retval);
        retval = ERROR_RECV_LATEST_BLOCK_ID_RESP;
        goto done;
    }

    /* decode the response. */
    retval =
        vcblockchain_protocol_response_decode_header(
            &request_id, &offset, &status, &resp);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(
            stderr, "Error decoding response from agentd. (%x)\n", retval);
        retval = ERROR_DECODE_LATEST_BLOCK_ID;
        goto cleanup_resp;
    }

    /* verify the request ID. */
    if (PROTOCOL_REQ_ID_LATEST_BLOCK_ID_GET != request_id)
    {
        fprintf(stderr, "Wrong response code. (%x)\n", request_id);
        retval = ERROR_LATEST_BLOCK_ID_REQUEST_ID;
        goto cleanup_resp;
    }

    /* verify status. */
    if (STATUS_SUCCESS != status)
    {
        fprintf(stderr, "fail status from agentd. (%x)\n", status);
        retval = ERROR_LATEST_BLOCK_ID_STATUS;
        goto cleanup_resp;
    }

    /* verify offset. */
    if (EXPECTED_OFFSET != offset)
    {
        fprintf(
            stderr, "mismatched offsets. (%x) vs (%x)", offset,
            EXPECTED_OFFSET);
        retval = ERROR_LATEST_BLOCK_ID_OFFSET;
        goto cleanup_resp;
    }

    /* decode the response. */
    retval =
        vcblockchain_protocol_decode_resp_latest_block_id_get(
            &decoded_resp, resp.data, resp.size);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "could not decode response. (%x)\n", status);
        retval = ERROR_DECODE_LATEST_BLOCK_ID_DATA;
        goto cleanup_resp;
    }

    /* copy latest block id. */
    memcpy(last_block_id, &decoded_resp.block_id, 16);

    /* success. */
    retval = STATUS_SUCCESS;
    goto cleanup_decoded_resp;

cleanup_decoded_resp:
    dispose((disposable_t*)&decoded_resp);

cleanup_resp:
    dispose((disposable_t*)&resp);

done:
    return retval;
}

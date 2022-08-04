/**
 * \file helpers/get_and_verify_block_id_by_height.c
 *
 * \brief Query the block id by height.
 *
 * \copyright 2021-2022 Velo Payments, Inc.  All rights reserved.
 */

#include <helpers/conn_helpers.h>
#include <helpers/status_codes.h>
#include <stdio.h>
#include <string.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Request a block id by height.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param height            The height to query.
 * \param block_id          Variable to hold the block id on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_block_id_by_height(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, uint64_t height, vpr_uuid* block_id)
{
    status retval;
    vccrypt_buffer_t resp;
    const uint32_t EXPECTED_OFFSET = 0x1337;
    protocol_resp_block_id_by_height_get decoded_resp;
    uint32_t request_id, status, offset;

    /* parameter sanity checks. */
    MODEL_ASSERT(prop_ssock_valid(sock));
    MODEL_ASSERT(prop_crypto_suite_valid(suite));
    MODEL_ASSERT(NULL != client_iv);
    MODEL_ASSERT(NULL != server_iv);
    MODEL_ASSERT(prop_buffer_valid(shared_secret));
    MODEL_ASSERT(NULL != block_id);

    /* send the get block id by height query request. */
    retval =
        vcblockchain_protocol_sendreq_block_id_by_height_get(
            sock, suite, client_iv, shared_secret, EXPECTED_OFFSET, height);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error sending get latest block id request.\n");
        retval = ERROR_SEND_BLOCK_ID_BY_HEIGHT_REQ;
        goto done;
    }

    /* get a response. */
    retval =
        vcblockchain_protocol_recvresp(
            sock, alloc, suite, server_iv, shared_secret, &resp);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(
            stderr, "Error receiving response from agentd. (%x)\n", retval);
        retval = ERROR_RECV_BLOCK_ID_BY_HEIGHT_RESP;
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
        retval = ERROR_DECODE_BLOCK_ID_BY_HEIGHT;
        goto cleanup_resp;
    }

    /* verify the request ID. */
    if (PROTOCOL_REQ_ID_BLOCK_ID_BY_HEIGHT_GET != request_id)
    {
        fprintf(stderr, "Wrong response code. (%x)\n", request_id);
        retval = ERROR_BLOCK_ID_BY_HEIGHT_REQUEST_ID;
        goto cleanup_resp;
    }

    /* verify status. */
    if (STATUS_SUCCESS != status)
    {
        fprintf(stderr, "fail status from agentd. (%x)\n", status);
        retval = ERROR_BLOCK_ID_BY_HEIGHT_STATUS;
        goto cleanup_resp;
    }

    /* verify offset. */
    if (EXPECTED_OFFSET != offset)
    {
        fprintf(
            stderr, "mismatched offsets. (%x) vs (%x)", offset,
            EXPECTED_OFFSET);
        retval = ERROR_BLOCK_ID_BY_HEIGHT_OFFSET;
        goto cleanup_resp;
    }

    /* decode the response. */
    retval =
        vcblockchain_protocol_decode_resp_block_id_by_height_get(
            &decoded_resp, resp.data, resp.size);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "could not decode response. (%x)\n", status);
        retval = ERROR_DECODE_BLOCK_ID_BY_HEIGHT_DATA;
        goto cleanup_resp;
    }

    /* copy latest block id. */
    memcpy(block_id, &decoded_resp.block_id, 16);

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

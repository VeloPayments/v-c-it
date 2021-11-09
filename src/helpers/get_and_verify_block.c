/**
 * \file helpers/get_and_verify_block.c
 *
 * \brief Request a block by id from agentd.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <helpers/conn_helpers.h>
#include <stdio.h>
#include <string.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Request a block by ID from the agentd instance.
 *
 * \param sock              The socket connection with agentd.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param block_id          The block id to query.
 * \param block_cert        Pointer to an uninitialized vccrypt buffer that is
 *                          initialized by the block certificate on success.
 * \param prev_block_id     UUID initialized with the previous block id on
 *                          success.
 * \param next_block_id     UUID initialized with the next block id on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_block(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    uint64_t* server_iv, vccrypt_buffer_t* shared_secret,
    const vpr_uuid* block_id, vccrypt_buffer_t* block_cert,
    vpr_uuid* prev_block_id, vpr_uuid* next_block_id)
{
    status retval;
    uint32_t expected_block_get_offset = 0x1234;
    uint32_t request_id, status, offset;
    vccrypt_buffer_t get_block_response;
    protocol_resp_block_get block_get_resp;

    /* parameter sanity checks. */
    MODEL_ASSERT(prop_ssock_valid(sock));
    MODEL_ASSERT(prop_crypto_suite_valid(suite));
    MODEL_ASSERT(NULL != client_iv);
    MODEL_ASSERT(NULL != server_iv);
    MODEL_ASSERT(prop_buffer_valid(shared_secret));
    MODEL_ASSERT(NULL != block_id);
    MODEL_ASSERT(NULL != block_cert);
    MODEL_ASSERT(NULL != prev_block_id);
    MODEL_ASSERT(NULL != next_block_id);

    /* query block by id. */
    retval =
        vcblockchain_protocol_sendreq_block_get(
            sock, suite, client_iv, shared_secret,
            expected_block_get_offset, block_id);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Could not send get block id req (%x).\n", retval);
        retval = 215;
        goto done;
    }

    /* get response. */
    retval =
        vcblockchain_protocol_recvresp(
            sock, suite, server_iv, shared_secret, &get_block_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Failed to receive get next block response.\n");
        retval = 216;
        goto done;
    }

    /* decode the response header. */
    retval =
        vcblockchain_protocol_response_decode_header(
            &request_id, &offset, &status, &get_block_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error decoding response from get_block.\n");
        retval = 217;
        goto cleanup_get_block_response;
    }

    /* verify that the request id matches. */
    if (PROTOCOL_REQ_ID_BLOCK_BY_ID_GET != request_id)
    {
        fprintf(stderr, "Unexpected request id (%x).\n", request_id);
        retval = 218;
        goto cleanup_get_block_response;
    }

    /* verify that the status was successful. */
    if (STATUS_SUCCESS != status)
    {
        fprintf(stderr, "Unexpected status (%x).\n", status);
        retval = 219;
        goto cleanup_get_block_response;
    }

    /* verify that the offset is correct. */
    if (expected_block_get_offset != offset)
    {
        fprintf(stderr, "Unexpected offset (%x).\n", offset);
        retval = 220;
        goto cleanup_get_block_response;
    }

    /* decode block. */
    retval =
        vcblockchain_protocol_decode_resp_block_get(
            &block_get_resp, suite->alloc_opts, get_block_response.data,
            get_block_response.size);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Could not decode block get response. (%x)\n", retval);
        retval = 221;
        goto cleanup_get_block_response;
    }

    /* success. Move / Copy data. */
    retval = STATUS_SUCCESS;
    vccrypt_buffer_move(block_cert, &block_get_resp.block_cert);
    memcpy(prev_block_id, &block_get_resp.prev_block_id, 16);
    memcpy(next_block_id, &block_get_resp.next_block_id, 16);
    goto cleanup_block_get_resp;

cleanup_block_get_resp:
    dispose((disposable_t*)&block_get_resp);

cleanup_get_block_response:
    dispose((disposable_t*)&get_block_response);

done:
    return retval;
}

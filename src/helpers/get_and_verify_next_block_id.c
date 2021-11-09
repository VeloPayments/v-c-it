/**
 * \file helpers/get_and_verify_next_block_id.c
 *
 * \brief Request the next block id from agentd.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <helpers/conn_helpers.h>
#include <stdio.h>
#include <string.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Request the next block ID for a given block ID from the agentd
 * instance.
 *
 * \param sock              The socket connection with agentd.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param block_id          The block id to query.
 * \param next_block_id     Variable to hold the next block id on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_next_block_id(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    uint64_t* server_iv, vccrypt_buffer_t* shared_secret,
    const vpr_uuid* block_id, vpr_uuid* next_block_id)
{
    status retval;
    uint32_t expected_get_next_block_id_offset = 0x3133;
    vccrypt_buffer_t get_next_block_id_response;
    protocol_resp_block_next_id_get get_next_block_id_resp;
    uint32_t request_id, status, offset;

    /* parameter sanity checks. */
    MODEL_ASSERT(prop_ssock_valid(sock));
    MODEL_ASSERT(prop_crypto_suite_valid(suite));
    MODEL_ASSERT(NULL != client_iv);
    MODEL_ASSERT(NULL != server_iv);
    MODEL_ASSERT(prop_buffer_valid(shared_secret));
    MODEL_ASSERT(NULL != block_id);
    MODEL_ASSERT(NULL != next_block_id);

    /* get next block id from root block. */
    retval =
        vcblockchain_protocol_sendreq_block_next_id_get(
            sock, suite, client_iv, shared_secret,
            expected_get_next_block_id_offset, block_id);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Failed to send get next id req. (%x).\n", retval);
        retval = 208;
        goto done;
    }

    /* get response. */
    retval =
        vcblockchain_protocol_recvresp(
            sock, suite, server_iv, shared_secret,
            &get_next_block_id_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Failed to receive get next block response.\n");
        retval = 209;
        goto done;
    }

    /* decode the response header. */
    retval =
        vcblockchain_protocol_response_decode_header(
            &request_id, &offset, &status, &get_next_block_id_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error decoding response from get_next_block_id.\n");
        retval = 210;
        goto cleanup_get_next_block_id_response;
    }

    /* verify that the request id matches. */
    if (PROTOCOL_REQ_ID_BLOCK_ID_GET_NEXT != request_id)
    {
        fprintf(stderr, "Unexpected request id (%x).\n", request_id);
        retval = 211;
        goto cleanup_get_next_block_id_response;
    }

    /* verify that the status was successful. */
    if (STATUS_SUCCESS != status)
    {
        fprintf(stderr, "Unexpected get next block id status (%x).\n", status);
        retval = 212;
        goto cleanup_get_next_block_id_response;
    }

    /* verify that the offset is correct. */
    if (expected_get_next_block_id_offset != offset)
    {
        fprintf(stderr, "Unexpected get next block id offset (%x).\n", offset);
        retval = 213;
        goto cleanup_get_next_block_id_response;
    }

    /* decode the response. */
    retval =
        vcblockchain_protocol_decode_resp_block_next_id_get(
            &get_next_block_id_resp, get_next_block_id_response.data,
            get_next_block_id_response.size);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(
            stderr, "Could not decode get next block response (%x).\n", retval);
        retval = 214;
        goto cleanup_get_next_block_id_response;
    }

    /* copy the next block id on success. */
    retval = STATUS_SUCCESS;
    memcpy(next_block_id, &get_next_block_id_resp.next_block_id, 16);
    goto cleanup_get_next_block_id_resp;

cleanup_get_next_block_id_resp:
    dispose((disposable_t*)&get_next_block_id_resp);

cleanup_get_next_block_id_response:
    dispose((disposable_t*)&get_next_block_id_response);

done:
    return retval;
}
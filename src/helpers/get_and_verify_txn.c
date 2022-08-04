/**
 * \file helpers/get_and_verify_txn.c
 *
 * \brief Request a txn by id from agentd.
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
 * \brief Request a transaction by ID from the agentd instance.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param txn_id            The transaction id to query.
 * \param txn_cert          Pointer to an uninitialized vccrypt buffer that is
 *                          initialized by the txn certificate on success.
 * \param prev_txn_id       UUID initialized with the previous transaction id on
 *                          success.
 * \param next_txn_id       UUID initialized with the next transaction id on
 *                          success.
 * \param artifact_id       UUID initialized with the artifact id of this
 *                          transaction on success.
 * \param block_id          UUID initialized with the block id of this
 *                          transaction on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_txn(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, const vpr_uuid* txn_id,
    vccrypt_buffer_t* txn_cert, vpr_uuid* prev_txn_id, vpr_uuid* next_txn_id,
    vpr_uuid* artifact_id, vpr_uuid* block_id)
{
    status retval;
    uint32_t expected_txn_get_offset = 0x1234;
    uint32_t request_id, status, offset;
    vccrypt_buffer_t get_txn_response;
    protocol_resp_txn_get txn_get_resp;

    /* parameter sanity checks. */
    MODEL_ASSERT(prop_ssock_valid(sock));
    MODEL_ASSERT(prop_crypto_suite_valid(suite));
    MODEL_ASSERT(NULL != client_iv);
    MODEL_ASSERT(NULL != server_iv);
    MODEL_ASSERT(prop_buffer_valid(shared_secret));
    MODEL_ASSERT(NULL != txn_id);
    MODEL_ASSERT(NULL != txn_cert);
    MODEL_ASSERT(NULL != prev_txn_id);
    MODEL_ASSERT(NULL != next_txn_id);
    MODEL_ASSERT(NULL != artifact_id);
    MODEL_ASSERT(NULL != block_id);

    /* query txn by id. */
    retval =
        vcblockchain_protocol_sendreq_txn_get(
            sock, suite, client_iv, shared_secret,
            expected_txn_get_offset, txn_id);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Could not send get txn req (%x).\n", retval);
        retval = ERROR_SEND_TXN_REQ;
        goto done;
    }

    /* get response. */
    retval =
        vcblockchain_protocol_recvresp(
            sock, alloc, suite, server_iv, shared_secret, &get_txn_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Failed to receive get txn response.\n");
        retval = ERROR_RECV_TXN_RESP;
        goto done;
    }

    /* decode the response header. */
    retval =
        vcblockchain_protocol_response_decode_header(
            &request_id, &offset, &status, &get_txn_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error decoding response from get_txn.\n");
        retval = ERROR_DECODE_TXN_RESP;
        goto cleanup_get_txn_response;
    }

    /* verify that the request id matches. */
    if (PROTOCOL_REQ_ID_TRANSACTION_BY_ID_GET != request_id)
    {
        fprintf(stderr, "Unexpected request id (%x).\n", request_id);
        retval = ERROR_GET_TXN_REQUEST_ID;
        goto cleanup_get_txn_response;
    }

    /* verify that the status was successful. */
    if (STATUS_SUCCESS != status)
    {
        fprintf(stderr, "Unexpected status (%x).\n", status);
        retval = ERROR_GET_TXN_STATUS;
        goto cleanup_get_txn_response;
    }

    /* verify that the offset is correct. */
    if (expected_txn_get_offset != offset)
    {
        fprintf(stderr, "Unexpected offset (%x).\n", offset);
        retval = ERROR_GET_TXN_OFFSET;
        goto cleanup_get_txn_response;
    }

    /* decode txn. */
    retval =
        vcblockchain_protocol_decode_resp_txn_get(
            &txn_get_resp, suite->alloc_opts, get_txn_response.data,
            get_txn_response.size);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Could not decode txn get response. (%x)\n", retval);
        retval = ERROR_DECODE_TXN_RESP_DATA;
        goto cleanup_get_txn_response;
    }

    /* success. Move / Copy data. */
    retval = STATUS_SUCCESS;
    vccrypt_buffer_move(txn_cert, &txn_get_resp.txn_cert);
    memcpy(prev_txn_id, &txn_get_resp.prev_txn_id, 16);
    memcpy(next_txn_id, &txn_get_resp.next_txn_id, 16);
    memcpy(artifact_id, &txn_get_resp.artifact_id, 16);
    memcpy(block_id, &txn_get_resp.block_id, 16);
    goto cleanup_txn_get_resp;

cleanup_txn_get_resp:
    dispose((disposable_t*)&txn_get_resp);

cleanup_get_txn_response:
    dispose((disposable_t*)&get_txn_response);

done:
    return retval;
}

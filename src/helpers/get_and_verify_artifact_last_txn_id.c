/**
 * \file helpers/get_and_verify_artifact_last_txn_id.c
 *
 * \brief Request the last txn id of a given artifact from agentd.
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
 * \brief Request the last txn ID for a given artifact ID from the agentd
 * instance.
 *
 * \param sock              The socket connection with agentd.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param artifact_id       The artifact id to query.
 * \param last_txn_id       Variable to hold the last txn id on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_artifact_last_txn_id(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    uint64_t* server_iv, vccrypt_buffer_t* shared_secret,
    const vpr_uuid* artifact_id, vpr_uuid* last_txn_id)
{
    status retval;
    uint32_t expected_get_last_txn_id_offset = 0x4321;
    vccrypt_buffer_t get_last_txn_id_response;
    protocol_resp_artifact_last_txn_id_get get_last_txn_id_resp;
    uint32_t request_id, status, offset;

    /* parameter sanity checks. */
    MODEL_ASSERT(prop_ssock_valid(sock));
    MODEL_ASSERT(prop_crypto_suite_valid(suite));
    MODEL_ASSERT(NULL != client_iv);
    MODEL_ASSERT(NULL != server_iv);
    MODEL_ASSERT(prop_buffer_valid(shared_secret));
    MODEL_ASSERT(NULL != artifact_id);
    MODEL_ASSERT(NULL != last_txn_id);

    /* get artifact last txn id. */
    retval =
        vcblockchain_protocol_sendreq_artifact_last_txn_id_get(
            sock, suite, client_iv, shared_secret,
            expected_get_last_txn_id_offset, artifact_id);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Failed to send get last txn id req. (%x).\n", retval);
        retval = ERROR_SEND_LAST_TXN_ID_REQ;
        goto done;
    }

    /* get response. */
    retval =
        vcblockchain_protocol_recvresp(
            sock, suite, server_iv, shared_secret,
            &get_last_txn_id_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Failed to receive get last txn id response.\n");
        retval = ERROR_RECV_LAST_TXN_ID_RESP;
        goto done;
    }

    /* decode the response header. */
    retval =
        vcblockchain_protocol_response_decode_header(
            &request_id, &offset, &status, &get_last_txn_id_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error decoding response from get_last_txn_id.\n");
        retval = ERROR_DECODE_LAST_TXN_ID;
        goto cleanup_get_last_txn_id_response;
    }

    /* verify that the request id matches. */
    if (PROTOCOL_REQ_ID_ARTIFACT_LAST_TXN_BY_ID_GET != request_id)
    {
        fprintf(stderr, "Unexpected request id (%x).\n", request_id);
        retval = ERROR_LAST_TXN_ID_REQUEST_ID;
        goto cleanup_get_last_txn_id_response;
    }

    /* verify that the status was successful. */
    if (STATUS_SUCCESS != status)
    {
        fprintf(stderr, "Unexpected get last txn id status (%x).\n", status);
        retval = ERROR_LAST_TXN_ID_STATUS;
        goto cleanup_get_last_txn_id_response;
    }

    /* verify that the offset is correct. */
    if (expected_get_last_txn_id_offset != offset)
    {
        fprintf(stderr, "Unexpected get last txn id offset (%x).\n", offset);
        retval = ERROR_LAST_TXN_ID_OFFSET;
        goto cleanup_get_last_txn_id_response;
    }

    /* decode the response. */
    retval =
        vcblockchain_protocol_decode_resp_artifact_last_txn_id_get(
            &get_last_txn_id_resp, get_last_txn_id_response.data,
            get_last_txn_id_response.size);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(
            stderr, "Could not decode get last txn response (%x).\n", retval);
        retval = ERROR_DECODE_LAST_TXN_ID_DATA;
        goto cleanup_get_last_txn_id_response;
    }

    /* copy the next block id on success. */
    retval = STATUS_SUCCESS;
    memcpy(last_txn_id, &get_last_txn_id_resp.last_txn_id, 16);
    goto cleanup_get_last_txn_id_resp;

cleanup_get_last_txn_id_resp:
    dispose((disposable_t*)&get_last_txn_id_resp);

cleanup_get_last_txn_id_response:
    dispose((disposable_t*)&get_last_txn_id_response);

done:
    return retval;
}
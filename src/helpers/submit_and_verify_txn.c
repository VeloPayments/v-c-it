/**
 * \file helpers/submit_and_verify_txn.c
 *
 * \brief Submit a transaction and verify the results.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <rcpr/status.h>
#include <stdio.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/ssock.h>

/**
 * \brief Submit and verify the response from submitting a transaction.
 *
 * \param sock              The socket connection with agentd.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param txn_uuid          The uuid of this transaction.
 * \param artifact_uuid     The uuid of the artifact modified by this
 *                          transaction.
 * \param cert              The certificate contents of this transaction.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status submit_and_verify_txn(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    uint64_t* server_iv, vccrypt_buffer_t* shared_secret,
    const vpr_uuid* txn_uuid, const vpr_uuid* artifact_uuid,
    const vccrypt_buffer_t* cert)
{
    status retval;
    uint32_t request_id, status, offset;
    const uint32_t expected_submit_offset = 0x1337;
    vccrypt_buffer_t submit_response;

    /* parameter sanity checks. */
    MODEL_ASSERT(prop_ssock_valid(sock));
    MODEL_ASSERT(NULL != client_iv);
    MODEL_ASSERT(NULL != server_iv);
    MODEL_ASSERT(prop_buffer_valid(shared_secret));
    MODEL_ASSERT(NULL != txn_uuid);
    MODEL_ASSERT(NULL != artifact_uuid);
    MODEL_ASSERT(prop_buffer_valid(cert));

    /* submit this certificate. */
    retval =
        vcblockchain_protocol_sendreq_transaction_submit(
            sock, suite, client_iv, shared_secret, expected_submit_offset,
            txn_uuid, artifact_uuid, cert->data, cert->size);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error submitting transaction.\n");
        retval = 201;
        goto done;
    }

    /* get response from submit. */
    retval =
        vcblockchain_protocol_recvresp(
            sock, suite, server_iv, shared_secret, &submit_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error receiving response from submit.\n");
        retval = 202;
        goto done;
    }

    /* decode the response header. */
    retval =
        vcblockchain_protocol_response_decode_header(
            &request_id, &offset, &status, &submit_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error decoding response from submit.\n");
        retval = 203;
        goto cleanup_submit_response;
    }

    /* verify that the request id matches. */
    if (PROTOCOL_REQ_ID_TRANSACTION_SUBMIT != request_id)
    {
        fprintf(stderr, "Unexpected request id (%x).\n", request_id);
        retval = 204;
        goto cleanup_submit_response;
    }

    /* verify that the status was successful. */
    if (STATUS_SUCCESS != status)
    {
        fprintf(stderr, "Unexpected submit status (%x).\n", status);
        retval = 205;
        goto cleanup_submit_response;
    }

    /* verify that the offset is correct. */
    if (expected_submit_offset != offset)
    {
        fprintf(stderr, "Unexpected submit offset (%x).\n", offset);
        retval = 207;
        goto cleanup_submit_response;
    }

    /* success. */
    retval = STATUS_SUCCESS;
    goto cleanup_submit_response;

cleanup_submit_response:
    dispose((disposable_t*)&submit_response);

done:
    return retval;
}

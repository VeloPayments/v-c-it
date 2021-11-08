/**
 * \file submit_txn_and_read_block/main.c
 *
 * \brief Main entry point for submit transaction and read block test utility.
 *
 * \copyright 2021 Velo Payments.  See License.txt for license terms.
 */

#include <fcntl.h>
#include <stdio.h>
#include <helpers/cert_helpers.h>
#include <helpers/conn_helpers.h>
#include <rcpr/resource.h>
#include <rcpr/uuid.h>
#include <string.h>
#include <vcblockchain/entity_cert.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/protocol/serialization.h>
#include <vcblockchain/ssock.h>
#include <vccert/builder.h>
#include <vccert/certificate_types.h>
#include <vccert/fields.h>
#include <vccrypt/compare.h>
#include <vccrypt/suite.h>
#include <vctool/file.h>
#include <vctool/status_codes.h>
#include <vpr/allocator/malloc_allocator.h>
#include <unistd.h>

RCPR_IMPORT_resource;
RCPR_IMPORT_uuid;

/* forward decls. */
static status create_transaction_cert(
    vccrypt_buffer_t* cert_buffer, rcpr_uuid* txn_uuid,
    rcpr_uuid* artifact_uuid, vccert_builder_options_t* builder_opts,
    const rcpr_uuid* signer_id, const vccrypt_buffer_t* client_privkey);

/**
 * \brief Main entry point for the submit transaction and read block test
 * utility.
 *
 * \param argc      The number of arguments.
 * \param argv      Arguments to main.
 *
 * \returns 0 on success and non-zero on failure.
 */
int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    int retval, release_retval;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    vccert_builder_options_t builder_opts;
    vccrypt_buffer_t shared_secret;
    vccrypt_buffer_t cert_buffer;
    vccrypt_buffer_t get_next_block_id_response;
    vccrypt_buffer_t get_block_response;
    /*
    vccrypt_buffer_t get_artifact_response;
    vccrypt_buffer_t get_transaction_response;*/
    vcblockchain_entity_private_cert* client_priv;
    const vccrypt_buffer_t* client_sign_priv;
    const rcpr_uuid* client_id;
    file file;
    ssock sock;
    uint64_t client_iv, server_iv;
    uint32_t expected_get_next_block_id_offset = 0x3133;
    uint32_t expected_block_get_offset = 0x1234;
    vpr_uuid txn_uuid, artifact_uuid;
    uint32_t request_id, status, offset;
    protocol_resp_block_next_id_get get_next_block_id_resp;
    protocol_resp_block_get block_get_resp;

    /* register the velo v1 suite. */
    vccrypt_suite_register_velo_v1();

    /* initialize the allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* initialize the vccrypt suite. */
    retval =
        vccrypt_suite_options_init(&suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error initializing crypto suite.\n");
        retval = 1;
        goto cleanup_allocator;
    }

    /* initialize certificate builder options. */
    retval = vccert_builder_options_init(&builder_opts, &alloc_opts, &suite);
    if (VCCERT_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error initializing certificate builder.\n");
        retval = 230;
        goto cleanup_crypto_suite;
    }

    /* create OS level file abstraction. */
    retval = file_init(&file);
    if (VCTOOL_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error creating file abstraction layer.\n");
        retval = 2;
        goto cleanup_builder_opts;
    }

    /* connect to agentd. */
    retval =
        agentd_connection_init(
            &sock, &client_priv, &shared_secret, &client_iv, &server_iv, &file,
            &suite, "127.0.0.1", 4931, "test.priv", "agentd.pub");
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_file;
    }

    /* get the client artifact id. */
    retval =
        vcblockchain_entity_get_artifact_id(
            &client_id, client_priv);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_connection;
    }

    /* get the client private signing key. */
    retval =
        vcblockchain_entity_private_cert_get_private_signing_key(
            &client_sign_priv, client_priv);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_connection;
    }

    /* create a test transaction certificate. */
    retval =
        create_transaction_cert(
            &cert_buffer, (rcpr_uuid*)&txn_uuid, (rcpr_uuid*)&artifact_uuid,
            &builder_opts, client_id, client_sign_priv);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error creating transaction certificate.\n");
        retval = 200;
        goto cleanup_connection;
    }

    /* submit and verify the certificate. */
    retval =
        submit_and_verify_txn(
            &sock, &suite, &client_iv, &server_iv, &shared_secret, &txn_uuid,
            &artifact_uuid, &cert_buffer);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_transaction_cert;
    }

    /* sleep 5 seconds. */
    printf("Sleeping for 5 seconds while txn is canonized.\n");
    sleep(5);

    /* get next block id from root block. */
    retval =
        vcblockchain_protocol_sendreq_block_next_id_get(
            &sock, &suite, &client_iv, &shared_secret,
            expected_get_next_block_id_offset,
            (const vpr_uuid*)vccert_certificate_type_uuid_root_block);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Failed to send get next id req. (%x).\n", retval);
        retval = 208;
        goto cleanup_transaction_cert;
    }

    /* get response. */
    retval =
        vcblockchain_protocol_recvresp(
            &sock, &suite, &server_iv, &shared_secret,
            &get_next_block_id_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Failed to receive get next block response.\n");
        retval = 209;
        goto cleanup_transaction_cert;
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

    /* query block by id. */
    retval =
        vcblockchain_protocol_sendreq_block_get(
            &sock, &suite, &client_iv, &shared_secret,
            expected_block_get_offset, &get_next_block_id_resp.next_block_id);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Could not send get block id req (%x).\n", retval);
        retval = 215;
        goto cleanup_get_next_block_id_resp;
    }

    /* get response. */
    retval =
        vcblockchain_protocol_recvresp(
            &sock, &suite, &server_iv, &shared_secret,
            &get_block_response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Failed to receive get next block response.\n");
        retval = 216;
        goto cleanup_get_next_block_id_resp;
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
            &block_get_resp, &alloc_opts, get_block_response.data,
            get_block_response.size);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Could not decode block get response. (%x)\n", retval);
        retval = 221;
        goto cleanup_get_block_response;
    }

    /* TODO - iterate through block. */
    /* TODO - verify our submitted transaction matches. */
    /* TODO - get artifact by id. */
    /* TODO - get response and verify / etc. */
    /* TODO - decode artifact stuff and verify it matches. */
    /* TODO - get transaction by id. */
    /* TODO - get response and verify / etc. */
    /* TODO - decode transaction stuff and verify it matches. */

    /* TODO - here. */
    retval = STATUS_SUCCESS;
    goto cleanup_block_get_resp;

cleanup_block_get_resp:
    dispose((disposable_t*)&block_get_resp);

cleanup_get_block_response:
    dispose((disposable_t*)&get_block_response);

cleanup_get_next_block_id_resp:
    dispose((disposable_t*)&get_next_block_id_resp);

cleanup_get_next_block_id_response:
    dispose((disposable_t*)&get_next_block_id_response);

cleanup_transaction_cert:
    dispose((disposable_t*)&cert_buffer);

cleanup_connection:
    release_retval =
        resource_release(
            vcblockchain_entity_private_cert_resource_handle(client_priv));
    if (STATUS_SUCCESS != release_retval)
    {
        retval = release_retval;
    }

    dispose((disposable_t*)&shared_secret);
    dispose((disposable_t*)&sock);

cleanup_file:
    dispose((disposable_t*)&file);

cleanup_builder_opts:
    dispose((disposable_t*)&builder_opts);

cleanup_crypto_suite:
    dispose((disposable_t*)&suite);

cleanup_allocator:
    dispose((disposable_t*)&alloc_opts);

    return retval;
}

static const rcpr_uuid TEST_CERT_TYPE = { .data = {
    0x76, 0x13, 0x1b, 0x90, 0xc1, 0x0f, 0x47, 0xfb,
    0xab, 0x83, 0x86, 0x0d, 0x87, 0xf1, 0x3c, 0x08 } };

static const rcpr_uuid TEST_ARTIFACT_TYPE = { .data = {
    0x67, 0x7f, 0x58, 0xf7, 0xb0, 0xa8, 0x45, 0x07,
    0x9e, 0xff, 0x6b, 0x18, 0x1d, 0xb7, 0x06, 0xb7 } };

static const rcpr_uuid TEST_CERT_ID = { .data = {
    0x7a, 0x9d, 0x22, 0xe3, 0x99, 0x70, 0x4e, 0x35,
    0xa4, 0x62, 0x85, 0x2e, 0xa1, 0x40, 0xcd, 0x47 } };

static const rcpr_uuid TEST_ARTIFACT_ID = { .data = {
    0x7e, 0x5b, 0x76, 0xc4, 0x18, 0x33, 0x4d, 0x74,
    0xa5, 0xb8, 0x0d, 0x6f, 0x8f, 0x82, 0xa8, 0x5d } };

static const rcpr_uuid ZERO_UUID = { .data = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

/**
 * \brief Create a transaction certificate suitable for testing.
 *
 * \param cert_buffer       Pointer to an uninitialized certificate buffer that
 *                          is initialized with the contents of this certificate
 *                          on success.
 * \param txn_uuid          Pointer to a uuid field that is populated with the
 *                          transaction uuid on success.
 * \param artifact_uuid     Pointer to a uuid field that is populated with the
 *                          artifact uuid on success.
 * \param builder_opts      Certificate builder options for this operation.
 * \param client_id         ID of the client signing this certificate.
 * \param client_privkey    Private signing key of the client.
 *
 * \note On success, the caller owns the cert_buffer and must dispose it when it
 * is no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
static status create_transaction_cert(
    vccrypt_buffer_t* cert_buffer, rcpr_uuid* txn_uuid,
    rcpr_uuid* artifact_uuid, vccert_builder_options_t* builder_opts,
    const rcpr_uuid* signer_id, const vccrypt_buffer_t* client_privkey)
{
    status retval;
    vccert_builder_context_t builder;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != cert_buffer);
    MODEL_ASSERT(NULL != txn_uuid);
    MODEL_ASSERT(NULL != artifact_uuid);
    MODEL_ASSERT(prop_valid_builder_options(builder_opts));

    /* create a certificate builder instance. */
    retval = vccert_builder_init(
        builder_opts, &builder, 16384);
    if (STATUS_SUCCESS != retval)
    {
        goto done;
    }

    /* add certificate version. */
    retval =
        vccert_builder_add_short_uint32(
            &builder, VCCERT_FIELD_TYPE_CERTIFICATE_VERSION, 0x00010000);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add crypto suite. */
    retval =
        vccert_builder_add_short_uint16(
            &builder, VCCERT_FIELD_TYPE_CERTIFICATE_CRYPTO_SUITE,
            VCCRYPT_SUITE_VELO_V1);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add certificate type. */
    retval =
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_CERTIFICATE_TYPE, TEST_CERT_TYPE.data);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add artifact type. */
    retval =
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_ARTIFACT_TYPE, TEST_ARTIFACT_TYPE.data);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add transaction id (certificate id). */
    retval =
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_CERTIFICATE_ID, TEST_CERT_ID.data);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add artifact id. */
    retval =
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_ARTIFACT_ID, TEST_ARTIFACT_ID.data);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add previous certificate id. */
    retval =
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_PREVIOUS_CERTIFICATE_ID,
            ZERO_UUID.data);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add previous artifact state. */
    retval =
        vccert_builder_add_short_uint32(
            &builder, VCCERT_FIELD_TYPE_PREVIOUS_ARTIFACT_STATE, 0xFFFFFFFF);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add new artifact state. */
    retval =
        vccert_builder_add_short_uint32(
            &builder, VCCERT_FIELD_TYPE_NEW_ARTIFACT_STATE, 0x00000000);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add our custom field. */
    const char* test_message = "this is a test.";
    const size_t test_message_size = strlen(test_message);
    retval =
        vccert_builder_add_short_buffer(
            &builder, 0x0400, (const uint8_t*)test_message, test_message_size);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* sign the certificate. */
    retval =
        vccert_builder_sign(
            &builder, signer_id->data, client_privkey);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* get the signed certificate pointer and size. */
    size_t cert_size = 0;
    const uint8_t* cert = vccert_builder_emit(&builder, &cert_size);

    /* create a buffer large enough for this certficate. */
    retval =
        vccrypt_buffer_init(cert_buffer, builder_opts->alloc_opts, cert_size);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* copy data to the caller's cert buffer. */
    retval =
        vccrypt_buffer_read_data(cert_buffer, cert, cert_size);
    if (STATUS_SUCCESS != retval)
    {
        dispose((disposable_t*)cert_buffer);
        goto cleanup_builder;
    }

    /* success. */
    memcpy(txn_uuid, &TEST_CERT_ID, sizeof(TEST_CERT_ID));
    memcpy(artifact_uuid, &TEST_ARTIFACT_ID, sizeof(TEST_ARTIFACT_ID));
    retval = STATUS_SUCCESS;
    goto cleanup_builder;

cleanup_builder:
    dispose((disposable_t*)&builder);

done:
    return retval;
}

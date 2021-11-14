/**
 * \file submit_txn_and_read_block/main.c
 *
 * \brief Main entry point for submit transaction and read block test utility.
 *
 * \copyright 2021 Velo Payments.  See License.txt for license terms.
 */

#include <stdio.h>
#include <helpers/cert_helpers.h>
#include <helpers/conn_helpers.h>
#include <helpers/status_codes.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/protocol/serialization.h>
#include <vccert/certificate_types.h>
#include <vccrypt/compare.h>
#include <vpr/allocator/malloc_allocator.h>
#include <vpr/parameters.h>

RCPR_IMPORT_resource;
RCPR_IMPORT_uuid;

/* forward decls */
static bool dummy_txn_resolver(
    void* options, void* parser, const uint8_t* artifact_id,
    const uint8_t* txn_id, vccrypt_buffer_t* output_buffer, bool* trusted);
static int32_t dummy_artifact_state_resolver(
    void* options, void* parser, const uint8_t* artifact_id,
    vccrypt_buffer_t* txn_id);
static int dummy_contract_resolver(
    void* options, void* parser, const uint8_t* type_id,
    const uint8_t* artifact_id, vccert_contract_closure_t* closure);
static bool dummy_key_resolver(
    void* options, void* parser, uint64_t height, const uint8_t* entity_id,
    vccrypt_buffer_t* pubenckey_buffer, vccrypt_buffer_t* pubsignkey_buffer);

static vpr_uuid ff_uuid = { .data = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };

static vpr_uuid zero_uuid = { .data = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

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
    vccert_parser_options_t parser_options;
    vccrypt_buffer_t shared_secret;
    vccrypt_buffer_t cert_buffer;
    vccrypt_buffer_t block_cert;
    vccrypt_buffer_t txn_cert;
    vcblockchain_entity_private_cert* client_priv;
    const vccrypt_buffer_t* client_sign_priv;
    const rcpr_uuid* client_id;
    file file;
    ssock sock;
    uint64_t client_iv, server_iv;
    vpr_uuid txn_uuid, artifact_uuid, first_txn_uuid, last_txn_uuid;
    vpr_uuid next_block_id, prev_block_id, prev_block_id2, latest_block_id;
    vpr_uuid next_next_block_id, prev_txn_uuid, next_txn_uuid;
    vpr_uuid txn_artifact_uuid, txn_block_uuid;

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
        retval = ERROR_CRYPTO_SUITE_INIT;
        goto cleanup_allocator;
    }

    /* initialize certificate builder options. */
    retval = vccert_builder_options_init(&builder_opts, &alloc_opts, &suite);
    if (VCCERT_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error initializing certificate builder.\n");
        retval = ERROR_CERTIFICATE_BUILDER_INIT;
        goto cleanup_crypto_suite;
    }

    /* initialize parser options. */
    retval =
        vccert_parser_options_init(
            &parser_options, &alloc_opts, &suite, &dummy_txn_resolver,
            &dummy_artifact_state_resolver, &dummy_contract_resolver,
            &dummy_key_resolver, NULL);
    if (VCCERT_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error creating file abstraction layer.\n");
        retval = ERROR_CERTIFICATE_PARSER_INIT;
        goto cleanup_builder_opts;
    }

    /* create OS level file abstraction. */
    retval = file_init(&file);
    if (VCTOOL_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error creating file abstraction layer.\n");
        retval = ERROR_FILE_ABSTRACTION_INIT;
        goto cleanup_parser_opts;
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
        retval = ERROR_TRANSACTION_CERT_CREATE;
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

    /* get the root block's next block id. */
    retval =
        get_and_verify_next_block_id(
            &sock, &suite, &client_iv, &server_iv, &shared_secret,
            (const vpr_uuid*)vccert_certificate_type_uuid_root_block,
            &next_block_id);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_transaction_cert;
    }

    /* get the new block. */
    retval =
        get_and_verify_block(
            &sock, &suite, &client_iv, &server_iv, &shared_secret,
            &next_block_id, &block_cert, &prev_block_id, &next_next_block_id);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_transaction_cert;
    }

    /* the previous block id should be the root block id. */
    if (crypto_memcmp(
            &prev_block_id, &vccert_certificate_type_uuid_root_block, 16))
    {
        fprintf(stderr, "prev block id does not match root block id.\n");
        retval = ERROR_PREV_ID_ROOT_ID_MISMATCH;
        goto cleanup_block_cert;
    }

    /* the next next block id should be all 0xff. */
    if (crypto_memcmp(
            &next_next_block_id, &ff_uuid, 16))
    {
        fprintf(stderr, "next next block id should be invalid.\n");
        retval = ERROR_NEXT_NEXT_BLOCK_ID_MISMATCH;
        goto cleanup_block_cert;
    }

    /* find the transaction in the block. */
    retval =
        find_transaction_in_block(
            &block_cert, &cert_buffer, &parser_options);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_block_cert;
    }

    /* get the latest block id. */
    retval =
        get_and_verify_last_block_id(
            &sock, &suite, &client_iv, &server_iv, &shared_secret,
            &latest_block_id);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_block_cert;
    }

    /* verify that this matches our next block id. */
    if (crypto_memcmp(&next_block_id, &latest_block_id, 16))
    {
        fprintf(stderr, "next block id does not match latest block id.\n");
        retval = ERROR_NEXT_ID_LATEST_ID_MISMATCH;
        goto cleanup_block_cert;
    }

    /* get the next block's previous block id. */
    retval =
        get_and_verify_prev_block_id(
            &sock, &suite, &client_iv, &server_iv, &shared_secret,
            &next_block_id, &prev_block_id2);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_block_cert;
    }

    /* verify that the next block's previous block id matches the root block. */
    if (
        crypto_memcmp(
            &prev_block_id2, vccert_certificate_type_uuid_root_block, 16))
    {
        fprintf(stderr, "next block id does not match latest block id.\n");
        retval = ERROR_PREV_ID_ROOT_ID_MISMATCH2;
        goto cleanup_block_cert;

    }

    /* get and verify artifact get first txn id by artifact id. */
    retval =
        get_and_verify_artifact_first_txn_id(
            &sock, &suite, &client_iv, &server_iv, &shared_secret,
            &artifact_uuid, &first_txn_uuid);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_block_cert;
    }

    /* verify that the first transaction id matches our transaction id. */
    if (
        crypto_memcmp(
            &txn_uuid, &first_txn_uuid, 16))
    {
        fprintf(stderr, "first txn id does not match txn id.\n");
        retval = ERROR_TXN_ID_FIRST_ID_MISMATCH;
        goto cleanup_block_cert;
    }

    /* get and verify artifact get last txn id by artifact id. */
    retval =
        get_and_verify_artifact_last_txn_id(
            &sock, &suite, &client_iv, &server_iv, &shared_secret,
            &artifact_uuid, &last_txn_uuid);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_block_cert;
    }

    /* verify that the last transaction id matches our transaction id. */
    if (
        crypto_memcmp(
            &txn_uuid, &last_txn_uuid, 16))
    {
        fprintf(stderr, "last txn id does not match txn id.\n");
        retval = ERROR_TXN_ID_LAST_ID_MISMATCH;
        goto cleanup_block_cert;
    }

    /* get and verify transaction by id. */
    retval =
        get_and_verify_txn(
            &sock, &suite, &client_iv, &server_iv, &shared_secret, &txn_uuid,
            &txn_cert, &prev_txn_uuid, &next_txn_uuid, &txn_artifact_uuid,
            &txn_block_uuid);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_block_cert;
    }

    /* verify that the previous txn uuid is our zero id. */
    if (
        crypto_memcmp(
            &prev_txn_uuid, &zero_uuid, 16))
    {
        fprintf(stderr, "prev txn id is not zero.\n");
        retval = ERROR_TXN_PREV_ID_ZERO_ID_MISMATCH;
        goto cleanup_txn_cert;
    }

    /* verify that the next txn uuid is our ff id. */
    if (
        crypto_memcmp(
            &next_txn_uuid, &ff_uuid, 16))
    {
        fprintf(stderr, "next txn id is not 0xff.\n");
        retval = ERROR_TXN_NEXT_ID_FF_ID_MISMATCH;
        goto cleanup_txn_cert;
    }

    /* verify that the artifact id matches. */
    if (
        crypto_memcmp(
            &txn_artifact_uuid, &artifact_uuid, 16))
    {
        fprintf(stderr, "transaction artifact id does not match.\n");
        retval = ERROR_TXN_ARTIFACT_ID_MISMATCH;
        goto cleanup_txn_cert;
    }

    /* verify that the block id matches. */
    if (
        crypto_memcmp(
            &txn_block_uuid, &latest_block_id, 16))
    {
        fprintf(stderr, "transaction block id does not match.\n");
        retval = ERROR_TXN_BLOCK_ID_MISMATCH;
        goto cleanup_txn_cert;
    }

    /* success. */
    retval = STATUS_SUCCESS;
    goto cleanup_txn_cert;

cleanup_txn_cert:
    dispose((disposable_t*)&txn_cert);

cleanup_block_cert:
    dispose((disposable_t*)&block_cert);

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

cleanup_parser_opts:
    dispose((disposable_t*)&parser_options);

cleanup_builder_opts:
    dispose((disposable_t*)&builder_opts);

cleanup_crypto_suite:
    dispose((disposable_t*)&suite);

cleanup_allocator:
    dispose((disposable_t*)&alloc_opts);

    return retval;
}

/**
 * \brief Dummy transaction resolver.
 */
static bool dummy_txn_resolver(
    void* UNUSED(options), void* UNUSED(parser),
    const uint8_t* UNUSED(artifact_id),
    const uint8_t* UNUSED(txn_id), vccrypt_buffer_t* UNUSED(output_buffer),
    bool* UNUSED(trusted))
{
    return false;
}

/**
 * \brief Dummy artifact state resolver.
 */
static int32_t dummy_artifact_state_resolver(
    void* UNUSED(options), void* UNUSED(parser),
    const uint8_t* UNUSED(artifact_id), vccrypt_buffer_t* UNUSED(txn_id))
{
    return 0;
}

/**
 * \brief Dummy contract resolver.
 */
static int dummy_contract_resolver(
    void* UNUSED(options), void* UNUSED(parser), const uint8_t* UNUSED(type_id),
    const uint8_t* UNUSED(artifact_id),
    vccert_contract_closure_t* UNUSED(closure))
{
    return VCCERT_ERROR_PARSER_ATTEST_MISSING_CONTRACT;
}

/**
 * \brief Dummy key resolver.
 */
static bool dummy_key_resolver(
    void* UNUSED(options), void* UNUSED(parser), uint64_t UNUSED(height),
    const uint8_t* UNUSED(entity_id),
    vccrypt_buffer_t* UNUSED(pubenckey_buffer),
    vccrypt_buffer_t* UNUSED(pubsignkey_buffer))
{
    return false;
}

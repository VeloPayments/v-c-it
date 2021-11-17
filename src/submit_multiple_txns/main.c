/**
 * \file submit_multiple_txns/main.c
 *
 * \brief Main entry point for the submit multiple transactions test utility.
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
 * \brief Main entry point for the submit multiple transactions test.
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
    status retval, release_retval;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    vccert_builder_options_t builder_opts;
    vccert_parser_options_t parser_options;
    file file;
    ssock sock;
    vcblockchain_entity_private_cert* client_priv;
    vccrypt_buffer_t shared_secret;
    uint64_t client_iv, server_iv;
    const vccrypt_buffer_t* client_sign_priv;
    const rcpr_uuid* client_id;
    vccrypt_buffer_t cert1_buffer, cert2_buffer, cert3_buffer;
    vpr_uuid txn1_id, txn2_id, txn3_id, artifact_id;
    vccrypt_buffer_t txn1_cert, txn2_cert, txn3_cert;
    vpr_uuid prev_txn1_id, next_txn1_id, txn1_artifact_id, txn1_block_id;
    vpr_uuid prev_txn2_id, next_txn2_id, txn2_artifact_id, txn2_block_id;
    vpr_uuid prev_txn3_id, next_txn3_id, txn3_artifact_id, txn3_block_id;

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

    /* create the first test transaction certificate. */
    retval =
        create_transaction_cert(
            &cert1_buffer, (rcpr_uuid*)&txn1_id, (rcpr_uuid*)&artifact_id,
            &builder_opts, client_id, client_sign_priv);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error creating transaction certificate.\n");
        retval = ERROR_TRANSACTION_CERT_CREATE;
        goto cleanup_connection;
    }

    /* create the second test transaction certificate. */
    retval =
        create_next_transaction_cert(
            &cert2_buffer, (rcpr_uuid*)&txn2_id,
            (const rcpr_uuid*)&txn1_id, (const rcpr_uuid*)&artifact_id,
            0, 1, &builder_opts, client_id, client_sign_priv);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error creating transaction certificate.\n");
        retval = ERROR_TRANSACTION_CERT_CREATE;
        goto cleanup_txn1_cert;
    }

    /* create the third test transaction certificate. */
    retval =
        create_next_transaction_cert(
            &cert3_buffer, (rcpr_uuid*)&txn3_id,
            (const rcpr_uuid*)&txn2_id, (const rcpr_uuid*)&artifact_id,
            1, 2, &builder_opts, client_id, client_sign_priv);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error creating transaction certificate.\n");
        retval = ERROR_TRANSACTION_CERT_CREATE;
        goto cleanup_txn2_cert;
    }

    /* submit and verify cert 1. */
    retval =
        submit_and_verify_txn(
            &sock, &suite, &client_iv, &server_iv, &shared_secret, &txn1_id,
            &artifact_id, &cert1_buffer);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_txn3_cert;
    }

    /* submit and verify cert 2. */
    retval =
        submit_and_verify_txn(
            &sock, &suite, &client_iv, &server_iv, &shared_secret, &txn2_id,
            &artifact_id, &cert2_buffer);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_txn3_cert;
    }

    /* submit and verify cert 3. */
    retval =
        submit_and_verify_txn(
            &sock, &suite, &client_iv, &server_iv, &shared_secret, &txn3_id,
            &artifact_id, &cert3_buffer);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_txn3_cert;
    }

    /* sleep 5 seconds. */
    printf("Sleeping for 5 seconds while txns are canonized.\n");
    sleep(5);

    /* get and verify the first transaction by id. */
    retval =
        get_and_verify_txn(
            &sock, &suite, &client_iv, &server_iv, &shared_secret, &txn1_id,
            &txn1_cert, &prev_txn1_id, &next_txn1_id, &txn1_artifact_id,
            &txn1_block_id);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_txn3_cert;
    }

    /* get and verify the second transaction by id. */
    retval =
        get_and_verify_txn(
            &sock, &suite, &client_iv, &server_iv, &shared_secret, &txn2_id,
            &txn2_cert, &prev_txn2_id, &next_txn2_id, &txn2_artifact_id,
            &txn2_block_id);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_txn1_agentd_cert;
    }

    /* get and verify the third transaction by id. */
    retval =
        get_and_verify_txn(
            &sock, &suite, &client_iv, &server_iv, &shared_secret, &txn3_id,
            &txn3_cert, &prev_txn3_id, &next_txn3_id, &txn3_artifact_id,
            &txn3_block_id);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_txn2_agentd_cert;
    }

    /* verify that prev_txn1_id is zero uuid. */
    if (crypto_memcmp(&prev_txn1_id, &zero_uuid, 16))
    {
        fprintf(stderr, "Prev TXN1 mismatch.\n");
        retval = ERROR_TXN1_PREV_ID_MISMATCH;
        goto cleanup_txn3_agentd_cert;
    }

    /* verify that next is txn2. */
    if (crypto_memcmp(&next_txn1_id, &txn2_id, 16))
    {
        fprintf(stderr, "Next TXN1 mismatch.\n");
        retval = ERROR_TXN1_NEXT_ID_MISMATCH;
        goto cleanup_txn3_agentd_cert;
    }

    /* verify that txn1 artifact id is correct. */
    if (crypto_memcmp(&txn1_artifact_id, &artifact_id, 16))
    {
        fprintf(stderr, "TXN1 artifact id mismatch.\n");
        retval = ERROR_TXN1_ARTIFACT_ID_MISMATCH;
        goto cleanup_txn3_agentd_cert;
    }

    /* verify that prev_txn2_id is txn1 uuid. */
    if (crypto_memcmp(&prev_txn2_id, &txn1_id, 16))
    {
        fprintf(stderr, "Prev TXN2 mismatch.\n");
        retval = ERROR_TXN2_PREV_ID_MISMATCH;
        goto cleanup_txn3_agentd_cert;
    }

    /* verify that next is txn3. */
    if (crypto_memcmp(&next_txn2_id, &txn3_id, 16))
    {
        fprintf(stderr, "Next TXN2 mismatch.\n");
        retval = ERROR_TXN2_NEXT_ID_MISMATCH;
        goto cleanup_txn3_agentd_cert;
    }

    /* verify that txn2 artifact id is correct. */
    if (crypto_memcmp(&txn2_artifact_id, &artifact_id, 16))
    {
        fprintf(stderr, "TXN2 artifact id mismatch.\n");
        retval = ERROR_TXN1_ARTIFACT_ID_MISMATCH;
        goto cleanup_txn3_agentd_cert;
    }

    /* verify that prev_txn3_id is txn2 uuid. */
    if (crypto_memcmp(&prev_txn3_id, &txn2_id, 16))
    {
        fprintf(stderr, "Prev TXN3 mismatch.\n");
        retval = ERROR_TXN3_PREV_ID_MISMATCH;
        goto cleanup_txn3_agentd_cert;
    }

    /* verify that next is ff uuid. */
    if (crypto_memcmp(&next_txn3_id, &ff_uuid, 16))
    {
        fprintf(stderr, "Next TXN3 mismatch.\n");
        retval = ERROR_TXN3_NEXT_ID_MISMATCH;
        goto cleanup_txn3_agentd_cert;
    }

    /* verify that txn3 artifact id is correct. */
    if (crypto_memcmp(&txn3_artifact_id, &artifact_id, 16))
    {
        fprintf(stderr, "TXN3 artifact id mismatch.\n");
        retval = ERROR_TXN3_ARTIFACT_ID_MISMATCH;
        goto cleanup_txn3_agentd_cert;
    }

    /* get and verify txn1 next id. */
    retval =
        get_and_verify_next_txn_id(
            &sock, &suite, &client_iv, &server_iv, &shared_secret, &txn1_id,
            &next_txn1_id);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_txn3_agentd_cert;
    }

    /* verify that next is txn2 uuid. */
    if (crypto_memcmp(&next_txn1_id, &txn2_id, 16))
    {
        fprintf(stderr, "Next TXN1 mismatch.\n");
        retval = ERROR_TXN1_NEXT_ID_MISMATCH2;
        goto cleanup_txn3_agentd_cert;
    }

    /* get and verify txn2 next id. */
    retval =
        get_and_verify_next_txn_id(
            &sock, &suite, &client_iv, &server_iv, &shared_secret, &txn2_id,
            &next_txn2_id);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_txn3_agentd_cert;
    }

    /* verify that next is txn3 uuid. */
    if (crypto_memcmp(&next_txn2_id, &txn3_id, 16))
    {
        fprintf(stderr, "Next TXN2 mismatch.\n");
        retval = ERROR_TXN2_NEXT_ID_MISMATCH2;
        goto cleanup_txn3_agentd_cert;
    }

    /* success. */
    retval = STATUS_SUCCESS;
    goto cleanup_txn3_agentd_cert;

cleanup_txn3_agentd_cert:
    dispose((disposable_t*)&txn3_cert);

cleanup_txn2_agentd_cert:
    dispose((disposable_t*)&txn2_cert);

cleanup_txn1_agentd_cert:
    dispose((disposable_t*)&txn1_cert);

cleanup_txn3_cert:
    dispose((disposable_t*)&cert3_buffer);

cleanup_txn2_cert:
    dispose((disposable_t*)&cert2_buffer);

cleanup_txn1_cert:
    dispose((disposable_t*)&cert1_buffer);

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

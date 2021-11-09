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
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/protocol/serialization.h>
#include <vccert/certificate_types.h>
#include <vpr/allocator/malloc_allocator.h>

RCPR_IMPORT_resource;
RCPR_IMPORT_uuid;

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
    vccrypt_buffer_t block_cert;
    vcblockchain_entity_private_cert* client_priv;
    const vccrypt_buffer_t* client_sign_priv;
    const rcpr_uuid* client_id;
    file file;
    ssock sock;
    uint64_t client_iv, server_iv;
    vpr_uuid txn_uuid, artifact_uuid;
    vpr_uuid next_block_id, prev_block_id;

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
            &next_block_id, &block_cert, &prev_block_id, &next_block_id);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_transaction_cert;
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
    goto cleanup_block_cert;

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

cleanup_builder_opts:
    dispose((disposable_t*)&builder_opts);

cleanup_crypto_suite:
    dispose((disposable_t*)&suite);

cleanup_allocator:
    dispose((disposable_t*)&alloc_opts);

    return retval;
}

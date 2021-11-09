/**
 * \file test_handshake/main.c
 *
 * \brief Main entry point for the handshake test utility.
 *
 * \copyright 2021 Velo Payments.  See License.txt for license terms.
 */

#include <fcntl.h>
#include <stdio.h>
#include <helpers/cert_helpers.h>
#include <helpers/conn_helpers.h>
#include <helpers/status_codes.h>
#include <rcpr/resource.h>
#include <rcpr/uuid.h>
#include <vcblockchain/entity_cert.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/ssock.h>
#include <vccrypt/suite.h>
#include <vctool/file.h>
#include <vctool/status_codes.h>
#include <vpr/allocator/malloc_allocator.h>
#include <unistd.h>

RCPR_IMPORT_resource;
RCPR_IMPORT_uuid;

/**
 * \brief Main entry point for the test handshake utility.
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
    vccrypt_buffer_t shared_secret;
    vcblockchain_entity_private_cert* client_priv;
    file file;
    ssock sock;
    uint64_t client_iv, server_iv;

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

    /* create OS level file abstraction. */
    retval = file_init(&file);
    if (VCTOOL_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error creating file abstraction layer.\n");
        retval = ERROR_FILE_ABSTRACTION_INIT;
        goto cleanup_crypto_suite;
    }

    /* connect to agentd. */
    retval =
        agentd_connection_init(
            &sock, &client_priv, &shared_secret, &client_iv, &server_iv, &file,
            &suite, "127.0.0.1", 4931, "handshake.priv", "agentd.pub");
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_file;
    }

    /* success. */
    retval = STATUS_SUCCESS;
    goto cleanup_connection;

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

cleanup_crypto_suite:
    dispose((disposable_t*)&suite);

cleanup_allocator:
    dispose((disposable_t*)&alloc_opts);

    return retval;
}

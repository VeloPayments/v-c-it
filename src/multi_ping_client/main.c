/**
 * \file multi_ping_client/main.c
 *
 * \brief Main entry point for the ping client test utility.
 *
 * \copyright 2023 Velo Payments.  See License.txt for license terms.
 */

#include <errno.h>
#include <helpers/cert_helpers.h>
#include <helpers/conn_helpers.h>
#include <helpers/ping_protocol.h>
#include <helpers/status_codes.h>
#include <inttypes.h>
#include <stdio.h>
#include <vpr/allocator/malloc_allocator.h>
#include <vpr/parameters.h>

RCPR_IMPORT_allocator_as(rcpr);
RCPR_IMPORT_psock;
RCPR_IMPORT_resource;
RCPR_IMPORT_uuid;

/* forward decls. */
static size_t get_payload_size();

/**
 * \brief Main entry point for the ping client test utility.
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
    rcpr_allocator* alloc;
    vccrypt_suite_options_t suite;
    vccert_builder_options_t builder_opts;
    vccert_parser_options_t parser_options;
    file file;
    psock* sock;
    vcblockchain_entity_private_cert* client_priv;
    vccrypt_buffer_t shared_secret;
    uint64_t client_iv, server_iv;
    const vccrypt_buffer_t* client_sign_priv;
    const rcpr_uuid* ping_sentinel_id;
    const rcpr_uuid* client_id;
    vcblockchain_entity_public_cert* ping_sentinel_cert;
    uint32_t offset_ctr = 5U;
    size_t payload_size = get_payload_size();

    /* register the velo v1 suite. */
    vccrypt_suite_register_velo_v1();

    /* initialize the allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* create the RCPR allocator. */
    retval = rcpr_malloc_allocator_create(&alloc);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_allocator;
    }

    /* initialize the vccrypt suite. */
    retval =
        vccrypt_suite_options_init(&suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error initializing crypto suite.\n");
        retval = ERROR_CRYPTO_SUITE_INIT;
        goto cleanup_rcpr_allocator;
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
        vccert_parser_options_simple_init(
            &parser_options, &alloc_opts, &suite);
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

    /* open the public key for the ping sentinel. */
    retval =
        entity_public_certificate_create_from_file(
            &ping_sentinel_cert, &file, &suite, "ping_sentinel.pub");
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_file;
    }

    /* get the ping sentinel artifact id. */
    retval =
        vcblockchain_entity_get_artifact_id(
            &ping_sentinel_id, ping_sentinel_cert);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_ping_sentinel_cert;
    }

    /* connect to agentd. */
    retval =
        agentd_connection_init(
            &sock, alloc, &client_priv, &shared_secret, &client_iv, &server_iv,
            &file, &suite, "127.0.0.1", 4931, "ping_client.priv", "agentd.pub");
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_ping_sentinel_cert;
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

    /* iterate 10000 times. */
    for (int i = 0; i < 10000; ++i)
    {
        if (i % 100 == 0)
        {
            printf("\n%2d%%", i/100);
            fflush(stdout);
        }

        /* Send a ping request and verify the response. */
        retval =
            send_and_verify_ping_request(
                sock, alloc, &suite, &client_iv, &server_iv, &shared_secret,
                offset_ctr++, (const vpr_uuid*)ping_sentinel_id, payload_size);
        if (STATUS_SUCCESS != retval)
        {
            goto cleanup_connection;
        }

        printf(".");
        fflush(stdout);
    }

    printf("\n");

    /* send the close request. */
    retval =
        send_and_verify_close_connection(
            sock, alloc, &suite, &client_iv, &server_iv, &shared_secret);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_connection;
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

    release_retval = resource_release(psock_resource_handle(sock));
    if (STATUS_SUCCESS != release_retval)
    {
        retval = release_retval;
    }

cleanup_ping_sentinel_cert:
    release_retval =
        resource_release(
            vcblockchain_entity_public_cert_resource_handle(
                ping_sentinel_cert));
    if (STATUS_SUCCESS != release_retval)
    {
        retval = release_retval;
    }

cleanup_file:
    dispose((disposable_t*)&file);

cleanup_parser_opts:
    dispose((disposable_t*)&parser_options);

cleanup_builder_opts:
    dispose((disposable_t*)&builder_opts);

cleanup_crypto_suite:
    dispose((disposable_t*)&suite);

cleanup_rcpr_allocator:
    release_retval = resource_release(rcpr_allocator_resource_handle(alloc));
    if (STATUS_SUCCESS != release_retval)
    {
        retval = release_retval;
    }

cleanup_allocator:
    dispose((disposable_t*)&alloc_opts);

    return retval;
}

/**
 * \brief Get the payload size from the environment, defaulting it to 1.
 *
 * \returns the payload size.
 */
static size_t get_payload_size()
{
    const char* payload_size_str;
    size_t payload_size;

    /* attempt to read the payload size from the environment. */
    payload_size_str = getenv("PING_CLIENT_PAYLOAD_SIZE");
    if (NULL == payload_size_str)
    {
        goto return_default;
    }

    /* attempt to convert this size to a size_t value. */
    errno = 0;
    payload_size = (size_t)strtoumax(payload_size_str, NULL, 10);
    if (0 == payload_size || 0 != errno)
    {
        fprintf(stderr, "Bad PING_CLIENT_PAYLOAD_SIZE value.\n");
        goto return_default;
    }

    /* return the updated size. */
    printf("Using %lu as the max size.\n", payload_size);
    return payload_size;

return_default:
    return 1;
}

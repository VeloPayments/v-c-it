/**
 * \file ping_sentinel/main.c
 *
 * \brief Main entry point for the ping sentinel test utility.
 *
 * \copyright 2022-2023 Velo Payments.  See License.txt for license terms.
 */

#include <errno.h>
#include <helpers/cert_helpers.h>
#include <helpers/conn_helpers.h>
#include <helpers/ping_protocol.h>
#include <helpers/ping_protocol/verbs.h>
#include <helpers/status_codes.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/protocol/serialization.h>
#include <vccert/certificate_types.h>
#include <vccrypt/compare.h>
#include <vpr/allocator/malloc_allocator.h>
#include <vpr/parameters.h>

RCPR_IMPORT_allocator_as(rcpr);
RCPR_IMPORT_psock;
RCPR_IMPORT_resource;
RCPR_IMPORT_uuid;

/* forward decls */
static status read_decode_and_dispatch_request(
    psock* sock, rcpr_allocator* alloc, vccrypt_suite_options_t* suite,
    uint64_t* client_iv, uint64_t* server_iv, vccrypt_buffer_t* shared_secret,
    size_t payload_size);
static size_t get_payload_size();

/**
 * \brief Main entry point for the ping sentinel test utility.
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
    const rcpr_uuid* client_id;
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

    /* connect to agentd. */
    retval =
        agentd_connection_init(
            &sock, alloc, &client_priv, &shared_secret, &client_iv, &server_iv,
            &file, &suite, "127.0.0.1", 4931, "ping_sentinel.priv",
            "agentd.pub");
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

    /* enable the extended API. */
    retval =
        send_and_verify_enable_extended_api(
            sock, alloc, &suite, &client_iv, &server_iv, &shared_secret,
            offset_ctr++);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_connection;
    }

    /* Read and respond to requests. */
    for (;;)
    {
        retval =
            read_decode_and_dispatch_request(
                sock, alloc, &suite, &client_iv, &server_iv, &shared_secret,
                payload_size);
        if (STATUS_SUCCESS != retval)
        {
            goto cleanup_connection;
        }
    }

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
 * \brief Read, decode, and dispatch a request.
 */
static status read_decode_and_dispatch_request(
    psock* sock, rcpr_allocator* alloc, vccrypt_suite_options_t* suite,
    uint64_t* client_iv, uint64_t* server_iv, vccrypt_buffer_t* shared_secret,
    size_t payload_size)
{
    status retval;
    vccrypt_buffer_t response, send_response;
    vccrypt_buffer_t response_body;
    uint32_t request_id, offset, status_code;
    bool fail_response = false;
    uint32_t fail_code;
    protocol_resp_extended_api_client_request client_resp;

    /* read a response from the API. */
    retval =
        vcblockchain_protocol_recvresp(
            sock, alloc, suite, server_iv, shared_secret, &response);
    if (STATUS_SUCCESS != retval)
    {
        retval = ERROR_READ_EXTENDED_API_RESPONSE;
        goto done;
    }

    /* decode the header. */
    retval =
        vcblockchain_protocol_response_decode_header(
            &request_id, &offset, &status_code, &response);
    if (STATUS_SUCCESS != retval)
    {
        retval = ERROR_READ_EXTENDED_API_RESPONSE_DECODE_HEADER;
        goto cleanup_response;
    }

    /* verify that this is a client request. */
    if (PROTOCOL_REQ_ID_EXTENDED_API_CLIENTREQ != request_id)
    {
        retval = ERROR_READ_EXTENDED_API_BAD_REQUEST_ID;
        goto cleanup_response;
    }

    /* decode the client request. */
    retval =
        vcblockchain_protocol_decode_resp_extended_api_client_request(
            &client_resp, suite->alloc_opts, response.data, response.size);
    if (STATUS_SUCCESS != retval)
    {
        retval = ERROR_READ_EXTENDED_API_DECODE_RESPONSE;
        goto cleanup_response;
    }

    /* verify the verb id. */
    if (memcmp(&HELPERS_PING_PROTOCOL_VERB_PING, &client_resp.verb_id, 16))
    {
        fail_response = true;
        fail_code = ERROR_READ_EXTENDED_API_INVALID_VERB;
    }

    /* create a dummy response body. */
    retval =
        vccrypt_buffer_init(&response_body, suite->alloc_opts, payload_size);
    if (STATUS_SUCCESS != retval)
    {
        retval = ERROR_READ_EXTENDED_API_OUT_OF_MEMORY;
        goto cleanup_client_resp;
    }

    /* send the response. */
    if (fail_response)
    {
        retval =
            vcblockchain_protocol_sendreq_extended_api_response(
                sock, suite, client_iv, shared_secret, client_resp.offset,
                fail_code, &response_body);
    }
    else
    {
        retval =
            vcblockchain_protocol_sendreq_extended_api_response(
                sock, suite, client_iv, shared_secret, client_resp.offset,
                STATUS_SUCCESS, &response_body);
    }

    if (STATUS_SUCCESS != retval)
    {
        retval = ERROR_WRITE_EXTENDED_API_RESPONSE;
        goto cleanup_response_body;
    }

    /* read a response from the API. */
    retval =
        vcblockchain_protocol_recvresp(
            sock, alloc, suite, server_iv, shared_secret, &send_response);
    if (STATUS_SUCCESS != retval)
    {
        retval = ERROR_READ_EXTENDED_API_RESPONSE;
        goto cleanup_response_body;
    }

    /* decode the header. */
    retval =
        vcblockchain_protocol_response_decode_header(
            &request_id, &offset, &status_code, &send_response);
    if (STATUS_SUCCESS != retval)
    {
        retval = ERROR_READ_EXTENDED_API_RESPONSE_DECODE_HEADER;
        goto cleanup_send_response;
    }

    /* verify that this is a send response. */
    if (PROTOCOL_REQ_ID_EXTENDED_API_SENDRESP != request_id)
    {
        retval = ERROR_READ_EXTENDED_API_BAD_REQUEST_ID;
        goto cleanup_send_response;
    }

    /* either way, we are done. */
    goto cleanup_send_response;

cleanup_send_response:
    dispose((disposable_t*)&send_response);

cleanup_response_body:
    dispose((disposable_t*)&response_body);

cleanup_client_resp:
    dispose((disposable_t*)&client_resp);

cleanup_response:
    dispose((disposable_t*)&response);

done:
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
    payload_size_str = getenv("PING_SENTINEL_PAYLOAD_SIZE");
    if (NULL == payload_size_str)
    {
        goto return_default;
    }

    /* attempt to convert this size to a size_t value. */
    errno = 0;
    payload_size = (size_t)strtoumax(payload_size_str, NULL, 10);
    if (0 == payload_size || 0 != errno)
    {
        fprintf(stderr, "Bad PING_SENTINEL_PAYLOAD_SIZE value.\n");
        goto return_default;
    }

    /* return the updated size. */
    printf("Using %lu as the max size.\n", payload_size);
    return payload_size;

return_default:
    return 1;
}

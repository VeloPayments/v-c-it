/**
 * \file test_get_latest_block_empty/main.c
 *
 * \brief Main entry point for the empty latest block get test utility.
 *
 * \copyright 2021 Velo Payments.  See License.txt for license terms.
 */

#include <fcntl.h>
#include <stdio.h>
#include <helpers/cert_helpers.h>
#include <helpers/conn_helpers.h>
#include <rcpr/resource.h>
#include <rcpr/uuid.h>
#include <vcblockchain/entity_cert.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/protocol/serialization.h>
#include <vcblockchain/ssock.h>
#include <vccert/certificate_types.h>
#include <vccrypt/compare.h>
#include <vccrypt/suite.h>
#include <vctool/file.h>
#include <vctool/status_codes.h>
#include <vpr/allocator/malloc_allocator.h>
#include <unistd.h>

RCPR_IMPORT_resource;
RCPR_IMPORT_uuid;

/**
 * \brief Main entry point for the empty latest block get utility.
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
    const uint32_t EXPECTED_OFFSET = 0x1337;
    vccrypt_buffer_t resp;
    uint32_t request_id, offset, status;
    protocol_resp_latest_block_id_get decoded_resp;

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

    /* create OS level file abstraction. */
    retval = file_init(&file);
    if (VCTOOL_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error creating file abstraction layer.\n");
        retval = 2;
        goto cleanup_crypto_suite;
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

    /* send the get latest block query request. */
    retval =
        vcblockchain_protocol_sendreq_latest_block_id_get(
            &sock, &suite, &client_iv, &shared_secret, EXPECTED_OFFSET);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error sending get latest block id request.\n");
        retval = 200;
        goto cleanup_connection;
    }

    /* get a response. */
    retval =
        vcblockchain_protocol_recvresp(
            &sock, &suite, &server_iv, &shared_secret, &resp);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(
            stderr, "Error receiving response from agentd. (%x)\n", retval);
        retval = 201;
        goto cleanup_connection;
    }

    /* decode the response. */
    retval =
        vcblockchain_protocol_response_decode_header(
            &request_id, &offset, &status, &resp);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(
            stderr, "Error decoding response from agentd. (%x)\n", retval);
        retval = 202;
        goto cleanup_resp;
    }

    /* verify the request ID. */
    if (PROTOCOL_REQ_ID_LATEST_BLOCK_ID_GET != request_id)
    {
        fprintf(stderr, "Wrong response code. (%x)\n", request_id);
        retval = 203;
        goto cleanup_resp;
    }

    /* verify status. */
    if (STATUS_SUCCESS != status)
    {
        fprintf(stderr, "fail status from agentd. (%x)\n", status);
        retval = 204;
        goto cleanup_resp;
    }

    /* decode the response. */
    retval =
        vcblockchain_protocol_decode_resp_latest_block_id_get(
            &decoded_resp, resp.data, resp.size);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "could not decode response. (%x)\n", status);
        retval = 205;
        goto cleanup_resp;
    }

    /* verify that the block id is the root block. */
    if (crypto_memcmp(
            &decoded_resp.block_id, vccert_certificate_type_uuid_root_block,
            16))
    {
        fprintf(stderr, "latest block id does not match root block.\n");
        retval = 206;
        goto cleanup_decoded_resp;
    }

    /* success. */
    retval = 0;
    goto cleanup_decoded_resp;

cleanup_decoded_resp:
    dispose((disposable_t*)&decoded_resp);

cleanup_resp:
    dispose((disposable_t*)&resp);

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

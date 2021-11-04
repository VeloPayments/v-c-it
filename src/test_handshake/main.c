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
    vccrypt_buffer_t key_nonce, challenge_nonce, server_pubkey,
                     server_challenge_nonce, shared_secret, response;
    vcblockchain_entity_private_cert* client_priv;
    vcblockchain_entity_public_cert* server_pub;
    file file;
    ssock sock;
    const rcpr_uuid* client_id;
    vpr_uuid server_id;
    uint32_t offset, status, request_id;
    uint64_t client_iv, server_iv;
    const vccrypt_buffer_t* client_pubkey;
    const vccrypt_buffer_t* client_privkey;

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

    /* read the private key. */
    retval =
        entity_private_certificate_create_from_file(
            &client_priv, &file, &suite, "handshake.priv");
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_file;
    }

    /* read the public key. */
    retval =
        entity_public_certificate_create_from_file(
            &server_pub, &file, &suite, "agentd.pub");
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_client_priv;
    }

    /* open socket connection to agentd. */
    retval =
        ssock_init_from_host_address(&sock, "127.0.0.1", 4931);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error connecting to agentd.\n");
        retval = 13;
        goto cleanup_server_pub;
    }

    /* get client artifact id. */
    retval =
        vcblockchain_entity_get_artifact_id(&client_id, client_priv);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_sock;
    }

    /* get client public encryption key. */
    retval =
        vcblockchain_entity_get_public_encryption_key(
            &client_pubkey, client_priv);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_sock;
    }

    /* get client private encryption key. */
    retval =
        vcblockchain_entity_private_cert_get_private_encryption_key(
            &client_privkey, client_priv);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_sock;
    }

    /* send handshake request. */
    retval =
        vcblockchain_protocol_sendreq_handshake_request(
            &sock, &suite, (const vpr_uuid*)client_id, &key_nonce,
            &challenge_nonce);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error sending handshake request to agentd.\n");
        retval = 101;
        goto cleanup_sock;
    }

    /* receive handshake response. */
    retval =
        vcblockchain_protocol_recvresp_handshake_request(
            &sock, &suite, &server_id, &server_pubkey,
            client_privkey,
            &key_nonce, &challenge_nonce, &server_challenge_nonce,
            &shared_secret, &offset, &status);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval
     || VCBLOCKCHAIN_STATUS_SUCCESS != status)
    {
        fprintf(
            stderr,
            "Error receiving handshake response from agentd (%x) (%x).\n",
            retval, status);
        retval = 102;
        goto cleanup_handshake_req;
    }

    /* send handshake acknowledge request. */
    retval =
        vcblockchain_protocol_sendreq_handshake_ack(
            &sock, &suite, &client_iv, &server_iv, &shared_secret,
            &server_challenge_nonce);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error sending handshake ack to agentd.\n");
        retval = 103;
        goto cleanup_handshake_resp;
    }

    /* read a response. */
    retval =
        vcblockchain_protocol_recvresp(
            &sock, &suite, &server_iv, &shared_secret, &response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error getting handshake ack response.\n");
        retval = 104;
        goto cleanup_handshake_resp;
    }

    /* decode the response header. */
    retval =
        vcblockchain_protocol_response_decode_header(
            &request_id, &offset, &status, &response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error decoding response header.\n");
        retval = 105;
        goto cleanup_resp;
    }

    /* verify that the request id matches. */
    if (PROTOCOL_REQ_ID_HANDSHAKE_ACKNOWLEDGE != request_id)
    {
        fprintf(stderr, "Unexpected request id (%x).\n", request_id);
        retval = 106;
        goto cleanup_resp;
    }

    /* verify that the status was successful. */
    if (STATUS_SUCCESS != status)
    {
        fprintf(
            stderr, "Handshake was not acknowledged by server (%x).\n", status);
        retval = 107;
        goto cleanup_resp;
    }

    /* success. */
    retval = 0;
    goto cleanup_resp;

cleanup_resp:
    dispose((disposable_t*)&response);

cleanup_handshake_resp:
    dispose((disposable_t*)&server_pubkey);
    dispose((disposable_t*)&server_challenge_nonce);
    dispose((disposable_t*)&shared_secret);

cleanup_handshake_req:
    dispose((disposable_t*)&key_nonce);
    dispose((disposable_t*)&challenge_nonce);

cleanup_sock:
    dispose((disposable_t*)&sock);

cleanup_server_pub:
    release_retval =
        resource_release(
            vcblockchain_entity_public_cert_resource_handle(server_pub));
    if (STATUS_SUCCESS != release_retval)
    {
        retval = release_retval;
    }

cleanup_client_priv:
    release_retval =
        resource_release(
            vcblockchain_entity_private_cert_resource_handle(client_priv));
    if (STATUS_SUCCESS != release_retval)
    {
        retval = release_retval;
    }

cleanup_file:
    dispose((disposable_t*)&file);

cleanup_crypto_suite:
    dispose((disposable_t*)&suite);

cleanup_allocator:
    dispose((disposable_t*)&alloc_opts);

    return retval;
}

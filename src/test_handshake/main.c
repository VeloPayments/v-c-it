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

    int retval, release_retval, fd2;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    vccrypt_buffer_t cert2, key_nonce, challenge_nonce, server_pubkey,
                     server_challenge_nonce, shared_secret;
    vcblockchain_entity_private_cert* client_priv;
    vcblockchain_entity_public_cert* server_pub;
    file file;
    ssock sock;
    const rcpr_uuid* client_id;
    vpr_uuid server_id;
    uint32_t offset, status;
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

    /* stat the public key. */
    file_stat_st fst;
    retval = file_stat(&file, "agentd.pub", &fst);
    if (VCTOOL_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Could not stat agentd.pub.\n");
        retval = 8;
        goto cleanup_client_priv;
    }

    /* create the certificate buffer. */
    size_t file_size = fst.fst_size;
    retval = vccrypt_buffer_init(&cert2, suite.alloc_opts, file_size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Could not create certificate buffer.\n");
        retval = 9;
        goto cleanup_client_priv;
    }

    /* open file. */
    retval =
        file_open(
            &file, &fd2, "agentd.pub", O_RDONLY, 0);
    if (VCTOOL_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Could not open agentd.pub for reading.\n");
        retval = 10;
        goto cleanup_cert2;
    }

    /* read contents into certificate buffer. */
    size_t read_bytes;
    retval = file_read(&file, fd2, cert2.data, cert2.size, &read_bytes);
    if (VCTOOL_STATUS_SUCCESS != retval || read_bytes != cert2.size)
    {
        fprintf(stderr, "Error reading from agentd.pub.\n");
        retval = 11;
        goto cleanup_fd2;
    }

    /* decode public certificate. */
    retval =
        vcblockchain_entity_public_cert_decode(&server_pub, &suite, &cert2);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error decoding public certificate.\n");
        retval = 12;
        goto cleanup_fd2;
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

    /* send handshake acknowledge. */
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

    /* success. */
    retval = 0;
    goto cleanup_handshake_resp;

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

cleanup_fd2:
    file_close(&file, fd2);

cleanup_cert2:
    dispose((disposable_t*)&cert2);

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

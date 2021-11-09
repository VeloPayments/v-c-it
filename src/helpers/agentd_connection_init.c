/**
 * \file helpers/agentd_connection_init.c
 *
 * \brief Initialize a connection to an agentd instance.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <fcntl.h>
#include <helpers/cert_helpers.h>
#include <helpers/conn_helpers.h>
#include <helpers/status_codes.h>
#include <rcpr/resource.h>
#include <rcpr/uuid.h>
#include <stdio.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/error_codes.h>
#include <vccrypt/compare.h>

RCPR_IMPORT_resource;
RCPR_IMPORT_uuid;

/**
 * \brief Connect to agentd using the provided certificate files to establish
 * the connection.
 *
 * This method initializes and returns a shared secret, client_iv, server_iv,
 * entity private certificate, and ssock instance on success. The shared secret
 * and ssock instance are both disposable and must be disposed by calling \ref
 * dispose when they are no longer needed. The private entity certificate is a
 * resource and must have its resource handle released by calling \ref
 * resource_release when it is no longer needed. The two IV values are used in
 * subsequent request and response calls in order to derive the per-message key
 * needed to encrypt or decrypt these messages.
 *
 * \param sock          Pointer to a ssock struct that will be initialized on
 *                      success with the socket connection to agentd.
 * \param cert          Pointer to the entity private certificate pointer that
 *                      will receive the client private entity certificate on
 *                      success.
 * \param shared_secret Pointer to a vccrypt buffer that will be initialized on
 *                      success with the shared secret for this session.
 * \param client_iv     Pointer to the uint64_t value that will be updated with
 *                      the client_iv on success.
 * \param server_iv     Pointer to the uint64_t value that will be updated with
 *                      the server_iv on success.
 * \param file          The OS file abstraction to use for this operation.
 * \param suite         The crypto suite to use for this operation.
 * \param hostaddr      The host IP address for this operation.
 * \param hostport      The host port for this operation.
 * \param clientpriv    The file name of the client private certificate (must
 *                      not be encrypted).
 * \param serverpub     The file name of the server public certificate.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status agentd_connection_init(
    ssock* sock, vcblockchain_entity_private_cert** cert,
    vccrypt_buffer_t* shared_secret, uint64_t* client_iv, uint64_t* server_iv,
    file* file, vccrypt_suite_options_t* suite, const char* hostaddr,
    unsigned int hostport, const char* clientpriv, const char* serverpub)
{
    bool success = false;
    status retval, release_retval;
    uint32_t status, offset, request_id;
    vcblockchain_entity_public_cert* server_cert;
    const vccrypt_buffer_t* client_pubkey;
    const vccrypt_buffer_t* client_privkey;
    const vccrypt_buffer_t* server_pubkey;
    const rcpr_uuid* client_id;
    const rcpr_uuid* server_id;
    rcpr_uuid server_id_from_server;
    vccrypt_buffer_t key_nonce;
    vccrypt_buffer_t challenge_nonce;
    vccrypt_buffer_t server_pubkey_from_server;
    vccrypt_buffer_t server_challenge_nonce;
    vccrypt_buffer_t response;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != sock);
    MODEL_ASSERT(NULL != cert);
    MODEL_ASSERT(NULL != shared_secret);
    MODEL_ASSERT(NULL != client_iv);
    MODEL_ASSERT(NULL != server_iv);
    MODEL_ASSERT(prop_file_valid(file));
    MODEL_ASSERT(prop_vccrypt_crypto_suite_valid(suite));
    MODEL_ASSERT(NULL != hostaddr);
    MODEL_ASSERT(hostport < 65536);
    MODEL_ASSERT(NULL != clientpriv);
    MODEL_ASSERT(NULL != serverpub);

    /* read the private key. */
    retval =
        entity_private_certificate_create_from_file(
            cert, file, suite, clientpriv);
    if (STATUS_SUCCESS != retval)
    {
        goto done;
    }

    /*read the public key. */
    retval =
        entity_public_certificate_create_from_file(
            &server_cert, file, suite, serverpub);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_cert;
    }

    /* open socket connection to agentd. */
    retval = ssock_init_from_host_address(sock, hostaddr, hostport);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error connecting to agentd.\n");
        retval = ERROR_AGENTD_SOCKET_CONNECT;
        goto cleanup_server_cert;
    }

    /* get client artifact id. */
    retval =
        vcblockchain_entity_get_artifact_id(&client_id, *cert);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_sock;
    }

    /* get client public encryption key. */
    retval =
        vcblockchain_entity_get_public_encryption_key(
            &client_pubkey, *cert);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_sock;
    }

    /* get client private encryption key. */
    retval =
        vcblockchain_entity_private_cert_get_private_encryption_key(
            &client_privkey, *cert);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_sock;
    }

    /* get server artifact id. */
    retval =
        vcblockchain_entity_get_artifact_id(&server_id, server_cert);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_sock;
    }

    /* get server public encryption key. */
    retval =
        vcblockchain_entity_get_public_encryption_key(
            &server_pubkey, server_cert);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_sock;
    }

    /* send handshake request. */
    retval =
        vcblockchain_protocol_sendreq_handshake_request(
            sock, suite, (const vpr_uuid*)client_id, &key_nonce,
            &challenge_nonce);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error sending handshake request to agentd.\n");
        retval = ERROR_SEND_HANDSHAKE_REQ;
        goto cleanup_sock;
    }

    /* receive handshake response. */
    retval =
        vcblockchain_protocol_recvresp_handshake_request(
            sock, suite, (vpr_uuid*)&server_id_from_server,
            &server_pubkey_from_server, client_privkey, &key_nonce,
            &challenge_nonce, &server_challenge_nonce, shared_secret, &offset,
            &status);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        fprintf(
            stderr,
            "Error receiving handshake response from agentd (%x).\n", retval);
        retval = ERROR_RECV_HANDSHAKE_RESP;
        goto cleanup_handshake_req;
    }

    /* verify that the server ids match. */
    if (crypto_memcmp(server_id, &server_id_from_server, 16))
    {
        fprintf(stderr, "Server UUIDs do not match!\n");
        retval = ERROR_SERVER_ID_MISMATCH;
        goto cleanup_handshake_resp;
    }

    /* verify that the server pubkey matches. */
    if (server_pubkey_from_server.size != server_pubkey->size
     || crypto_memcmp(
            server_pubkey->data, server_pubkey_from_server.data,
            server_pubkey->size))
    {
        fprintf(stderr, "Server public keys do not match!\n");
        retval = ERROR_SERVER_KEY_MISMATCH;
        goto cleanup_handshake_resp;
    }

    /* send handshake acknowledge request. */
    retval =
        vcblockchain_protocol_sendreq_handshake_ack(
            sock, suite, client_iv, server_iv, shared_secret,
            &server_challenge_nonce);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error sending handshake ack to agentd.\n");
        retval = ERROR_SEND_HANDSHAKE_ACK;
        goto cleanup_handshake_resp;
    }

    /* read a response. */
    retval =
        vcblockchain_protocol_recvresp(
            sock, suite, server_iv, shared_secret, &response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error getting handshake ack response.\n");
        retval = ERROR_RECV_HANDSHAKE_ACK;
        goto cleanup_handshake_resp;
    }

    /* decode the response header. */
    retval =
        vcblockchain_protocol_response_decode_header(
            &request_id, &offset, &status, &response);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error decoding response header.\n");
        retval = ERROR_DECODE_HANDSHAKE_ACK;
        goto cleanup_resp;
    }

    /* verify that the request id matches. */
    if (PROTOCOL_REQ_ID_HANDSHAKE_ACKNOWLEDGE != request_id)
    {
        fprintf(stderr, "Unexpected request id (%x).\n", request_id);
        retval = ERROR_HANDSHAKE_ACK_REQUEST_ID;
        goto cleanup_resp;
    }

    /* verify that the status was successful. */
    if (STATUS_SUCCESS != status)
    {
        fprintf(
            stderr, "Handshake was not acknowledged by server (%x).\n", status);
        retval = ERROR_HANDSHAKE_ACK_STATUS;
        goto cleanup_resp;
    }

    /* success. */
    success = true;
    goto cleanup_resp;

cleanup_resp:
    dispose((disposable_t*)&response);

cleanup_handshake_resp:
    dispose((disposable_t*)&server_pubkey_from_server);
    dispose((disposable_t*)&server_challenge_nonce);
    if (!success)
    {
        dispose((disposable_t*)shared_secret);
        shared_secret = NULL;
    }

cleanup_handshake_req:
    dispose((disposable_t*)&key_nonce);
    dispose((disposable_t*)&challenge_nonce);

cleanup_sock:
    if (!success)
    {
        dispose((disposable_t*)sock);
        sock = NULL;
    }

cleanup_server_cert:
    release_retval =
        resource_release(
            vcblockchain_entity_public_cert_resource_handle(server_cert));
    if (STATUS_SUCCESS != release_retval)
    {
        retval = release_retval;
    }

cleanup_cert:
    if (!success)
    {
        release_retval =
            resource_release(
                vcblockchain_entity_private_cert_resource_handle(*cert));    
        if (STATUS_SUCCESS != release_retval)
        {
            retval = release_retval;
        }

        cert = NULL;
    }

done:
    /* if something went wrong during cleanup, attempt to clean up return
     * values. */
    if (success && STATUS_SUCCESS != retval)
    {
        if (shared_secret != NULL)
        {
            dispose((disposable_t*)shared_secret);
            shared_secret = NULL;
        }

        if (sock != NULL)
        {
            dispose((disposable_t*)sock);
            sock = NULL;
        }

        if (cert != NULL)
        {
            release_retval =
                resource_release(
                    vcblockchain_entity_private_cert_resource_handle(*cert));
            if (STATUS_SUCCESS != release_retval)
            {
                retval = release_retval;
            }

            cert = NULL;
        }
    }

    return retval;
}

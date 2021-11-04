/**
 * \file helpers/conn_helpers.h
 *
 * \brief Helpers for connecting to agentd.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#pragma once

#include <rcpr/status.h>
#include <vcblockchain/entity_cert.h>
#include <vcblockchain/ssock.h>
#include <vctool/file.h>

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
    unsigned int hostport, const char* clientpriv, const char* serverpub);

/**
 * \file helpers/conn_helpers.h
 *
 * \brief Helpers for connecting to agentd.
 *
 * \copyright 2021-2022 Velo Payments, Inc.  All rights reserved.
 */

#pragma once

#include <rcpr/psock.h>
#include <rcpr/status.h>
#include <vcblockchain/entity_cert.h>
#include <vctool/file.h>

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

/**
 * \brief Connect to agentd using the provided certificate files to establish
 * the connection.
 *
 * This method initializes and returns a shared secret, client_iv, server_iv,
 * entity private certificate, and psock instance on success. The shared secret
 * is disposable and must be disposed by calling \ref
 * dispose when it is no longer needed. The psock instance is a resource and
 * must be released by calling \ref resource_release when it is no longer
 * needed. The private entity certificate is a resource and must have its
 * resource handle released by calling \ref resource_release when it is no
 * longer needed. The two IV values are used in subsequent request and response
 * calls in order to derive the per-message key needed to encrypt or decrypt
 * these messages.
 *
 * \param sock          Pointer to a psock pointer that will receive the psock
 *                      instance on success with the socket connection to
 *                      agentd.
 * \param alloc         The allocator to use for this operation.
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
    RCPR_SYM(psock)** sock, RCPR_SYM(allocator)* alloc,
    vcblockchain_entity_private_cert** cert, vccrypt_buffer_t* shared_secret,
    uint64_t* client_iv, uint64_t* server_iv, file* file,
    vccrypt_suite_options_t* suite, const char* hostaddr, unsigned int hostport,
    const char* clientpriv, const char* serverpub);

/**
 * \brief Submit and verify the response from submitting a transaction.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param txn_uuid          The uuid of this transaction.
 * \param artifact_uuid     The uuid of the artifact modified by this
 *                          transaction.
 * \param cert              The certificate contents of this transaction.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status submit_and_verify_txn(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, const vpr_uuid* txn_uuid,
    const vpr_uuid* artifact_uuid, const vccrypt_buffer_t* cert);

/**
 * \brief Request the next block ID for a given block ID from the agentd
 * instance.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param block_id          The block id to query.
 * \param next_block_id     Variable to hold the next block id on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_next_block_id(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, const vpr_uuid* block_id,
    vpr_uuid* next_block_id);

/**
 * \brief Request the prev block ID for a given block ID from the agentd
 * instance.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param block_id          The block id to query.
 * \param prev_block_id     Variable to hold the prev block id on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_prev_block_id(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, const vpr_uuid* block_id,
    vpr_uuid* prev_block_id);

/**
 * \brief Request a block by ID from the agentd instance.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param block_id          The block id to query.
 * \param block_cert        Pointer to an uninitialized vccrypt buffer that is
 *                          initialized by the block certificate on success.
 * \param prev_block_id     UUID initialized with the previous block id on
 *                          success.
 * \param next_block_id     UUID initialized with the next block id on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_block(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, const vpr_uuid* block_id,
    vccrypt_buffer_t* block_cert, vpr_uuid* prev_block_id,
    vpr_uuid* next_block_id);

/**
 * \brief Request the current last ID from the agentd instance.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param last_block_id     Variable to hold the last block id on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_last_block_id(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, vpr_uuid* last_block_id);

/**
 * \brief Request the first txn ID for a given artifact ID from the agentd
 * instance.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param artifact_id       The artifact id to query.
 * \param first_txn_id      Variable to hold the first txn id on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_artifact_first_txn_id(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, const vpr_uuid* artifact_id,
    vpr_uuid* first_txn_id);

/**
 * \brief Request the last txn ID for a given artifact ID from the agentd
 * instance.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param artifact_id       The artifact id to query.
 * \param last_txn_id       Variable to hold the last txn id on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_artifact_last_txn_id(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, const vpr_uuid* artifact_id,
    vpr_uuid* last_txn_id);

/**
 * \brief Request a transaction by ID from the agentd instance.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param txn_id            The transaction id to query.
 * \param txn_cert          Pointer to an uninitialized vccrypt buffer that is
 *                          initialized by the txn certificate on success.
 * \param prev_txn_id       UUID initialized with the previous transaction id on
 *                          success.
 * \param next_txn_id       UUID initialized with the next transaction id on
 *                          success.
 * \param artifact_id       UUID initialized with the artifact id of this
 *                          transaction on success.
 * \param block_id          UUID initialized with the block id of this
 *                          transaction on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_txn(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, const vpr_uuid* txn_id,
    vccrypt_buffer_t* txn_cert, vpr_uuid* prev_txn_id, vpr_uuid* next_txn_id,
    vpr_uuid* artifact_id, vpr_uuid* block_id);

/**
 * \brief Request a block id by height.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param height            The height to query.
 * \param block_id          Variable to hold the block id on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_block_id_by_height(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, uint64_t height, vpr_uuid* block_id);

/**
 * \brief Request the next transaction ID for a given transaction ID from the
 * agentd instance.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param txn_id            The txn id to query.
 * \param next_txn_id       Variable to hold the next txn id on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_next_txn_id(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, const vpr_uuid* txn_id,
    vpr_uuid* next_txn_id);

/**
 * \brief Request the prev transaction ID for a given transaction ID from the
 * agentd instance.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param txn_id            The txn id to query.
 * \param prev_txn_id       Variable to hold the prev txn id on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_prev_txn_id(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, const vpr_uuid* txn_id,
    vpr_uuid* prev_txn_id);

/**
 * \brief Request the transaction block ID for a given transaction ID from the
 * agentd instance.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param txn_id            The txn id to query.
 * \param block_id          Variable to hold the block id on success.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_txn_block_id(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, const vpr_uuid* txn_id,
    vpr_uuid* block_id);

/**
 * \brief Request that the extended API be enabled for this entity on this
 * connection.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param offset            The offset to use for this request.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status send_and_verify_enable_extended_api(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, uint32_t offset);

/**
 * \brief Send an extended api ping protocol request and response.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 * \param offset            The offset to use for this request.
 * \param ping_sentinel_id  The UUID of the ping sentinel.
 * \param payload_size      The size of the payload to send.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status send_and_verify_ping_request(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, uint32_t offset,
    const vpr_uuid* ping_sentinel_id, size_t payload_size);

/**
 * \brief Get and verify the connection status.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status get_and_verify_status(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret);

/**
 * \brief Send and verify the close connection request.
 *
 * \param sock              The socket connection with agentd.
 * \param alloc             The allocator to use for this operation.
 * \param suite             The crypto suite to use for this operation.
 * \param client_iv         The client-side initialization vector counter.
 * \param server_iv         The server-side initialization vector counter.
 * \param shared_secret     The computed shared secret for this session.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status send_and_verify_close_connection(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc,
    vccrypt_suite_options_t* suite, uint64_t* client_iv, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret);

#if defined(__cplusplus)
}
#endif /* defined(__cplusplus) */

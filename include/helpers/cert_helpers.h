/**
 * \file helpers/cert_helpers.h
 *
 * \brief Helpers for parsing entity certificates.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#pragma once

#include <rcpr/status.h>
#include <rcpr/uuid.h>
#include <vcblockchain/entity_cert.h>
#include <vccert/builder.h>
#include <vccert/parser.h>
#include <vctool/file.h>

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

/**
 * \brief Read a private key and create an entity private certificate instance.
 *
 * \param cert          Pointer to the entity private certificate pointer that
 *                      will receive this instance on success.
 * \param file          The OS file abstraction to use for this operation.
 * \param suite         The crypto suite to use for this operation.
 * \param filename      The name of the file that holds the certificate.
 *
 * \note On success, an entity private certificate instance is created. This is
 * owned by the caller.  When no longer needed, the caller should call
 * \ref resource_release on its resource handle to release the resource.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status entity_private_certificate_create_from_file(
    vcblockchain_entity_private_cert** cert, file* file,
    vccrypt_suite_options_t* suite, const char* filename);

/**
 * \brief Read a public key and create an entity public certificate instance.
 *
 * \param cert          Pointer to the entity public certificate pointer that
 *                      will receive this instance on success.
 * \param file          The OS file abstraction to use for this operation.
 * \param suite         The crypto suite to use for this operation.
 * \param filename      The name of the file that holds the certificate.
 *
 * \note On success, an entity public certificate instance is created. This is
 * owned by the caller.  When no longer needed, the caller should call
 * \ref resource_release on its resource handle to release the resource.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status entity_public_certificate_create_from_file(
    vcblockchain_entity_public_cert** cert, file* file,
    vccrypt_suite_options_t* suite, const char* filename);

/**
 * \brief Create a transaction certificate suitable for testing.
 *
 * \param cert_buffer       Pointer to an uninitialized certificate buffer that
 *                          is initialized with the contents of this certificate
 *                          on success.
 * \param txn_uuid          Pointer to a uuid field that is populated with the
 *                          transaction uuid on success.
 * \param artifact_uuid     Pointer to a uuid field that is populated with the
 *                          artifact uuid on success.
 * \param builder_opts      Certificate builder options for this operation.
 * \param client_id         ID of the client signing this certificate.
 * \param client_privkey    Private signing key of the client.
 *
 * \note On success, the caller owns the cert_buffer and must dispose it when it
 * is no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status create_transaction_cert(
    vccrypt_buffer_t* cert_buffer, RCPR_SYM(rcpr_uuid)* txn_uuid,
    RCPR_SYM(rcpr_uuid)* artifact_uuid, vccert_builder_options_t* builder_opts,
    const RCPR_SYM(rcpr_uuid)* signer_id,
    const vccrypt_buffer_t* client_privkey);

/**
 * \brief Create the next transaction cert for an artifact.
 *
 * \param cert_buffer       Pointer to an uninitialized certificate buffer that
 *                          is initialized with the contents of this certificate
 *                          on success.
 * \param txn_uuid          Pointer to a uuid field that is populated with the
 *                          transaction uuid on success.
 * \param prev_txn_uuid     The previous transaction uuid.
 * \param artifact_uuid     The artifact uuid.
 * \param old_state         The old state.
 * \param new_state         The new state.
 * \param builder_opts      Certificate builder options for this operation.
 * \param client_id         ID of the client signing this certificate.
 * \param client_privkey    Private signing key of the client.
 *
 * \note On success, the caller owns the cert_buffer and must dispose it when it
 * is no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status create_next_transaction_cert(
    vccrypt_buffer_t* cert_buffer, RCPR_SYM(rcpr_uuid)* txn_uuid,
    const RCPR_SYM(rcpr_uuid)* prev_txn_uuid,
    const RCPR_SYM(rcpr_uuid)* artifact_uuid, uint32_t old_state,
    uint32_t new_state, vccert_builder_options_t* builder_opts,
    const RCPR_SYM(rcpr_uuid)* signer_id,
    const vccrypt_buffer_t* client_privkey);

/**
 * \brief Attempt to find a transaction in a block, using the raw transaction
 * certificate.
 *
 * \param block_cert        Pointer to a buffer holding the block certificate.
 * \param txn_cert          Pointer to a buffer holding the transaction cert.
 * \param parser_options    Parser options structure to use to create a parser
 *                          instance.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success (the txn was found).
 *      - a non-zero error code on failure.
 */
status find_transaction_in_block(
    const vccrypt_buffer_t* block_cert, const vccrypt_buffer_t* txn_cert,
    vccert_parser_options_t* parser_options);

#if defined(__cplusplus)
}
#endif /*defined(__cplusplus)*/

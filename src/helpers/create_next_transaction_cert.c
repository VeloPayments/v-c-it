/**
 * \file helpers/create_next_transaction_cert.c
 *
 * \brief Create the next test transaction certificate.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <helpers/cert_helpers.h>
#include <helpers/status_codes.h>
#include <string.h>
#include <vccert/fields.h>

RCPR_IMPORT_uuid;

static const rcpr_uuid TEST_CERT_TYPE = { .data = {
    0x2f, 0x0f, 0xc2, 0xd4, 0x42, 0x7f, 0x4e, 0x5e,
    0x82, 0x69, 0xfc, 0x0e, 0x65, 0x12, 0xba, 0xf5 } };

static const rcpr_uuid TEST_ARTIFACT_TYPE = { .data = {
    0x67, 0x7f, 0x58, 0xf7, 0xb0, 0xa8, 0x45, 0x07,
    0x9e, 0xff, 0x6b, 0x18, 0x1d, 0xb7, 0x06, 0xb7 } };

static status create_random_uuids(
    vccrypt_suite_options_t* suite, rcpr_uuid* txn_uuid);

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
    const vccrypt_buffer_t* client_privkey)
{
    status retval;
    vccert_builder_context_t builder;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != cert_buffer);
    MODEL_ASSERT(NULL != txn_uuid);
    MODEL_ASSERT(NULL != prev_txn_uuid);
    MODEL_ASSERT(NULL != artifact_uuid);
    MODEL_ASSERT(prop_valid_builder_options(builder_opts));

    /* create random UUIDs for the transaction and artifact ids. */
    retval =
        create_random_uuids(
            builder_opts->crypto_suite, txn_uuid);
    if (STATUS_SUCCESS != retval)
    {
        goto done;
    }

    /* create a certificate builder instance. */
    retval = vccert_builder_init(
        builder_opts, &builder, 16384);
    if (STATUS_SUCCESS != retval)
    {
        goto done;
    }

    /* add certificate version. */
    retval =
        vccert_builder_add_short_uint32(
            &builder, VCCERT_FIELD_TYPE_CERTIFICATE_VERSION, 0x00010000);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add crypto suite. */
    retval =
        vccert_builder_add_short_uint16(
            &builder, VCCERT_FIELD_TYPE_CERTIFICATE_CRYPTO_SUITE,
            VCCRYPT_SUITE_VELO_V1);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add certificate type. */
    retval =
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_CERTIFICATE_TYPE, TEST_CERT_TYPE.data);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add artifact type. */
    retval =
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_ARTIFACT_TYPE, TEST_ARTIFACT_TYPE.data);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add transaction id (certificate id). */
    retval =
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_CERTIFICATE_ID, txn_uuid->data);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add artifact id. */
    retval =
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_ARTIFACT_ID, artifact_uuid->data);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add previous certificate id. */
    retval =
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_PREVIOUS_CERTIFICATE_ID,
            prev_txn_uuid->data);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add previous artifact state. */
    retval =
        vccert_builder_add_short_uint32(
            &builder, VCCERT_FIELD_TYPE_PREVIOUS_ARTIFACT_STATE, old_state);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add new artifact state. */
    retval =
        vccert_builder_add_short_uint32(
            &builder, VCCERT_FIELD_TYPE_NEW_ARTIFACT_STATE, new_state);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add our custom field. */
    const char* test_message = "this is a test.";
    const size_t test_message_size = strlen(test_message);
    retval =
        vccert_builder_add_short_buffer(
            &builder, 0x0400, (const uint8_t*)test_message, test_message_size);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* sign the certificate. */
    retval =
        vccert_builder_sign(
            &builder, signer_id->data, client_privkey);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* get the signed certificate pointer and size. */
    size_t cert_size = 0;
    const uint8_t* cert = vccert_builder_emit(&builder, &cert_size);

    /* create a buffer large enough for this certficate. */
    retval =
        vccrypt_buffer_init(cert_buffer, builder_opts->alloc_opts, cert_size);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* copy data to the caller's cert buffer. */
    retval =
        vccrypt_buffer_read_data(cert_buffer, cert, cert_size);
    if (STATUS_SUCCESS != retval)
    {
        dispose((disposable_t*)cert_buffer);
        goto cleanup_builder;
    }

    /* success. */
    retval = STATUS_SUCCESS;
    goto cleanup_builder;

cleanup_builder:
    dispose((disposable_t*)&builder);

done:
    return retval;
}

/**
 * \brief Create random UUIDs for the certificate.
 *
 * \param suite         The crypto suite to use for this operation.
 * \param txn_uuid      Pointer to UUID field to receive the transaction UUID.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
static status create_random_uuids(
    vccrypt_suite_options_t* suite, rcpr_uuid* txn_uuid)
{
    status retval;
    vccrypt_prng_context_t prng;

    /* parameter sanity checks. */
    MODEL_ASSERT(prop_vccrypt_suite_valid(suite));
    MODEL_ASSERT(NULL != txn_uuid);
    MODEL_ASSERT(NULL != artifact_uuid);

    /* create a prng instance. */
    retval = vccrypt_suite_prng_init(suite, &prng);
    if (STATUS_SUCCESS != retval)
    {
        goto done;
    }

    /* create a random transaction uuid. */
    retval = vccrypt_prng_read_c(&prng, txn_uuid->data, 16);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_prng;
    }

    /* success. */
    retval = STATUS_SUCCESS;
    goto cleanup_prng;

cleanup_prng:
    dispose((disposable_t*)&prng);

done:
    return retval;
}

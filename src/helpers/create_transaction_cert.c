/**
 * \file helpers/create_transaction_cert.c
 *
 * \brief Create a test transaction certificate.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <helpers/cert_helpers.h>
#include <string.h>
#include <vccert/fields.h>

RCPR_IMPORT_uuid;

static const rcpr_uuid TEST_CERT_TYPE = { .data = {
    0x76, 0x13, 0x1b, 0x90, 0xc1, 0x0f, 0x47, 0xfb,
    0xab, 0x83, 0x86, 0x0d, 0x87, 0xf1, 0x3c, 0x08 } };

static const rcpr_uuid TEST_ARTIFACT_TYPE = { .data = {
    0x67, 0x7f, 0x58, 0xf7, 0xb0, 0xa8, 0x45, 0x07,
    0x9e, 0xff, 0x6b, 0x18, 0x1d, 0xb7, 0x06, 0xb7 } };

static const rcpr_uuid TEST_CERT_ID = { .data = {
    0x7a, 0x9d, 0x22, 0xe3, 0x99, 0x70, 0x4e, 0x35,
    0xa4, 0x62, 0x85, 0x2e, 0xa1, 0x40, 0xcd, 0x47 } };

static const rcpr_uuid TEST_ARTIFACT_ID = { .data = {
    0x7e, 0x5b, 0x76, 0xc4, 0x18, 0x33, 0x4d, 0x74,
    0xa5, 0xb8, 0x0d, 0x6f, 0x8f, 0x82, 0xa8, 0x5d } };

static const rcpr_uuid ZERO_UUID = { .data = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

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
    vccrypt_buffer_t* cert_buffer, rcpr_uuid* txn_uuid,
    rcpr_uuid* artifact_uuid, vccert_builder_options_t* builder_opts,
    const rcpr_uuid* signer_id, const vccrypt_buffer_t* client_privkey)
{
    status retval;
    vccert_builder_context_t builder;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != cert_buffer);
    MODEL_ASSERT(NULL != txn_uuid);
    MODEL_ASSERT(NULL != artifact_uuid);
    MODEL_ASSERT(prop_valid_builder_options(builder_opts));

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
            &builder, VCCERT_FIELD_TYPE_CERTIFICATE_ID, TEST_CERT_ID.data);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add artifact id. */
    retval =
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_ARTIFACT_ID, TEST_ARTIFACT_ID.data);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add previous certificate id. */
    retval =
        vccert_builder_add_short_UUID(
            &builder, VCCERT_FIELD_TYPE_PREVIOUS_CERTIFICATE_ID,
            ZERO_UUID.data);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add previous artifact state. */
    retval =
        vccert_builder_add_short_uint32(
            &builder, VCCERT_FIELD_TYPE_PREVIOUS_ARTIFACT_STATE, 0xFFFFFFFF);
    if (STATUS_SUCCESS != retval)
    {
        goto cleanup_builder;
    }

    /* add new artifact state. */
    retval =
        vccert_builder_add_short_uint32(
            &builder, VCCERT_FIELD_TYPE_NEW_ARTIFACT_STATE, 0x00000000);
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
    memcpy(txn_uuid, &TEST_CERT_ID, sizeof(TEST_CERT_ID));
    memcpy(artifact_uuid, &TEST_ARTIFACT_ID, sizeof(TEST_ARTIFACT_ID));
    retval = STATUS_SUCCESS;
    goto cleanup_builder;

cleanup_builder:
    dispose((disposable_t*)&builder);

done:
    return retval;
}

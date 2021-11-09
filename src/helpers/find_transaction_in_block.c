/**
 * \file helpers/find_transaction_in_block.c
 *
 * \brief Attempt to find a transaction in the given block.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <helpers/cert_helpers.h>
#include <stdio.h>
#include <vccert/fields.h>
#include <vccrypt/compare.h>

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
    vccert_parser_options_t* parser_options)
{
    status retval;
    vccert_parser_context_t parser;
    const uint8_t* txn_bytes;
    size_t txn_size;

    /* parameter sanity checks. */
    MODEL_ASSERT(prop_buffer_valid(block_cert));
    MODEL_ASSERT(prop_buffer_valid(txn_cert));
    MODEL_ASSERT(prop_parser_options_valid(parser_options));

    /* create a parser instance. */
    retval =
        vccert_parser_init(
            parser_options, &parser, block_cert->data, block_cert->size);
    if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error creating parser instance.\n");
        retval = 240;
        goto done;
    }

    /* attempt to find the first field. */
    retval =
        vccert_parser_find_short(
            &parser, VCCERT_FIELD_TYPE_WRAPPED_TRANSACTION_TUPLE,
            &txn_bytes, &txn_size);
    if (VCCERT_ERROR_PARSER_FIELD_NEXT_FIELD_NOT_FOUND == retval)
    {
        fprintf(stderr, "transaction not found.\n");
        retval = 241;
        goto cleanup_parser;
    }
    else if (STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "error searching for field.\n");
        retval = 241;
        goto cleanup_parser;
    }

    /* iterate through. */
    do
    {
        /* does this transaction match ours? */
        if (txn_size == txn_cert->size
         && !crypto_memcmp(txn_bytes, txn_cert->data, txn_size))
        {
            printf("Certificate found in block.\n");
            retval = STATUS_SUCCESS;
            goto cleanup_parser;
        }

        /* skip to the next field. */
        retval =
            vccert_parser_find_next(
                &parser, &txn_bytes, &txn_size);

    } while (STATUS_SUCCESS == retval);

    /* if we've made it this far, the transaction wasn't found. */
    fprintf(stderr, "transaction not found.\n");
    retval = 241;
    goto cleanup_parser;

cleanup_parser:
    dispose((disposable_t*)&parser);

done:
    return retval;
}

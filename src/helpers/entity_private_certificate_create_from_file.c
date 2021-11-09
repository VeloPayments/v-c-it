/**
 * \file helpers/entity_private_certificate_create_from_file.c
 *
 * \brief Create an entity private certificate from a file.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <fcntl.h>
#include <helpers/cert_helpers.h>
#include <helpers/status_codes.h>
#include <stdio.h>
#include <vcblockchain/error_codes.h>

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
    vccrypt_suite_options_t* suite, const char* filename)
{
    int retval, fd;
    vccrypt_buffer_t buf;

    MODEL_ASSERT(NULL != cert);
    MODEL_ASSERT(prop_file_valid(file));
    MODEL_ASSERT(NULL != filename);

    /* stat the file. */
    file_stat_st fst;
    retval = file_stat(file, filename, &fst);
    if (VCTOOL_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Could not stat %s.\n", filename);
        retval = ERROR_PRIVATE_CERT_STAT;
        goto done;
    }

    /* create the certificate buffer. */
    size_t file_size = fst.fst_size;
    retval = vccrypt_buffer_init(&buf, suite->alloc_opts, file_size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Could not create certificate buffer.\n");
        retval = ERROR_PRIVATE_CERT_BUFFER_CREATE;
        goto done;
    }

    /* open file. */
    retval =
        file_open(
            file, &fd, filename, O_RDONLY, 0);
    if (VCTOOL_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Could not open %s for reading.\n", filename);
        retval = ERROR_PRIVATE_CERT_FILE_OPEN;
        goto cleanup_buf;
    }

    /* read contents into certificate buffer. */
    size_t read_bytes;
    retval = file_read(file, fd, buf.data, buf.size, &read_bytes);
    if (VCTOOL_STATUS_SUCCESS != retval || read_bytes != buf.size)
    {
        fprintf(stderr, "Error reading from %s.\n", filename);
        retval = ERROR_PRIVATE_CERT_FILE_READ;
        goto cleanup_fd;
    }

    /* decode private certificate. */
    retval =
        vcblockchain_entity_private_cert_decode(cert, suite, &buf);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        fprintf(stderr, "Error decoding private certificate.\n");
        retval = ERROR_PRIVATE_CERT_FILE_PARSE;
        goto cleanup_fd;
    }

    /* success. */
    retval = STATUS_SUCCESS;
    goto cleanup_fd;

cleanup_fd:
    close(fd);

cleanup_buf:
    dispose((disposable_t*)&buf);

done:
    return retval;
}

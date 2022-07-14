/**
 * \file helpers/ping_protocol/serialization.h
 *
 * \brief Serialization methods for the extended API ping protocol.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#pragma once

#include <helpers/ping_protocol/data.h>

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

/**
 * \brief Encode a ping request using the given parameters.
 *
 * \param buffer                Pointer to an uninitialized buffer to receive
 *                              the encoded packet.
 * \param alloc_opts            The allocator options to use for this operation.
 * \param offset                The offset to use for this request.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request. The caller owns this buffer and must \ref dispose() it when it is no
 * longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status ping_protocol_encode_req_ping(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts, uint32_t offset);

/**
 * \brief Decode a ping request.
 *
 * \param req                   The decoded request buffer.
 * \param alloc_opts            The allocator options to use for this operation.
 * \param payload               Pointer to the payload to decode.
 * \param payload_size          Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() of it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status ping_protocol_decode_req_ping(
    ping_protocol_req_ping* req, allocator_options_t* alloc_opts,
    const void* payload, size_t payload_size);

#if defined(__cplusplus)
}
#endif /*defined(__cplusplus)*/

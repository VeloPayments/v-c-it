/**
 * \file helpers/ping_protocol/verbs.c
 *
 * \brief UUIDs for the ping protocol verbs.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <helpers/ping_protocol/verbs.h>

/**
 * \brief The ping verb.
 */
vpr_uuid HELPERS_PING_PROTOCOL_VERB_PING = { .data = {
        0x70, 0xce, 0x5e, 0x26, 0x7e, 0x2c, 0x45, 0x97,
        0xa2, 0x19, 0x02, 0x09, 0x58, 0xf7, 0xcf, 0x99
    }
};

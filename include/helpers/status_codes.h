/**
 * \file helpers/status_codes.h
 *
 * \brief Status codes for integration tests.
 *
 * \copyright 2021 Velo Payments.  See License.txt for license terms.
 */

#pragma once

#define ERROR_CRYPTO_SUITE_INIT                           1
#define ERROR_FILE_ABSTRACTION_INIT                       2
#define ERROR_CERTIFICATE_BUILDER_INIT                    3
#define ERROR_CERTIFICATE_PARSER_INIT                     4
#define ERROR_TRANSACTION_CERT_CREATE                     5
#define ERROR_SEND_BLOCK_REQ                              6
#define ERROR_RECV_BLOCK_RESP                             7
#define ERROR_DECODE_BLOCK_RESP                           8
#define ERROR_GET_BLOCK_REQUEST_ID                        9
#define ERROR_GET_BLOCK_STATUS                           10
#define ERROR_GET_BLOCK_OFFSET                           11
#define ERROR_DECODE_BLOCK_RESP_DATA                     12
#define ERROR_SEND_TXN_REQ                               13
#define ERROR_RECV_TXN_RESP                              14
#define ERROR_DECODE_TXN_RESP                            15
#define ERROR_TXN_SUBMIT_REQUEST_ID                      16
#define ERROR_TXN_SUBMIT_STATUS                          17
#define ERROR_TXN_SUBMIT_OFFSET                          18
#define ERROR_SEND_NEXT_BLOCK_ID_REQ                     19
#define ERROR_RECV_NEXT_BLOCK_ID_RESP                    20
#define ERROR_DECODE_NEXT_BLOCK_ID                       21
#define ERROR_NEXT_BLOCK_ID_REQUEST_ID                   22
#define ERROR_NEXT_BLOCK_ID_STATUS                       23
#define ERROR_NEXT_BLOCK_ID_OFFSET                       24
#define ERROR_DECODE_NEXT_BLOCK_ID_DATA                  25
#define ERROR_PARSER_INIT                                26
#define ERROR_TXN_NOT_FOUND                              27
#define ERROR_TXN_SEARCH_FAILED                          28
#define ERROR_PUBLIC_CERT_STAT                           29
#define ERROR_PUBLIC_CERT_BUFFER_CREATE                  30
#define ERROR_PUBLIC_CERT_FILE_OPEN                      31
#define ERROR_PUBLIC_CERT_FILE_READ                      32
#define ERROR_PUBLIC_CERT_FILE_PARSE                     33
#define ERROR_AGENTD_SOCKET_CONNECT                      34
#define ERROR_PRIVATE_CERT_STAT                          35
#define ERROR_PRIVATE_CERT_BUFFER_CREATE                 36
#define ERROR_PRIVATE_CERT_FILE_OPEN                     37
#define ERROR_PRIVATE_CERT_FILE_READ                     38
#define ERROR_PRIVATE_CERT_FILE_PARSE                    39
#define ERROR_SEND_LATEST_BLOCK_ID_REQ                   40
#define ERROR_RECV_LATEST_BLOCK_ID_RESP                  41
#define ERROR_DECODE_LATEST_BLOCK_ID                     42
#define ERROR_LATEST_BLOCK_ID_REQUEST_ID                 43
#define ERROR_LATEST_BLOCK_ID_STATUS                     44
#define ERROR_LATEST_BLOCK_ID_OFFSET                     45
#define ERROR_DECODE_LATEST_BLOCK_ID_DATA                46
#define ERROR_LATEST_BLOCK_ID_MISMATCH                   47
#define ERROR_NEXT_ID_LATEST_ID_MISMATCH                 48
#define ERROR_PREV_ID_ROOT_ID_MISMATCH                   49
#define ERROR_PREV_ID_ROOT_ID_MISMATCH2                  50
#define ERROR_NEXT_NEXT_BLOCK_ID_MISMATCH                51
#define ERROR_SEND_PREV_BLOCK_ID_REQ                     52
#define ERROR_RECV_PREV_BLOCK_ID_RESP                    53
#define ERROR_DECODE_PREV_BLOCK_ID                       54
#define ERROR_PREV_BLOCK_ID_REQUEST_ID                   55
#define ERROR_PREV_BLOCK_ID_STATUS                       56
#define ERROR_PREV_BLOCK_ID_OFFSET                       57
#define ERROR_DECODE_PREV_BLOCK_ID_DATA                  58
#define ERROR_TXN_ID_FIRST_ID_MISMATCH                   59
#define ERROR_SEND_FIRST_TXN_ID_REQ                      60
#define ERROR_RECV_FIRST_TXN_ID_RESP                     61
#define ERROR_DECODE_FIRST_TXN_ID                        62
#define ERROR_FIRST_TXN_ID_REQUEST_ID                    63
#define ERROR_FIRST_TXN_ID_STATUS                        64
#define ERROR_FIRST_TXN_ID_OFFSET                        65
#define ERROR_DECODE_FIRST_TXN_ID_DATA                   66
#define ERROR_TXN_ID_LAST_ID_MISMATCH                    67
#define ERROR_SEND_LAST_TXN_ID_REQ                       68
#define ERROR_RECV_LAST_TXN_ID_RESP                      69
#define ERROR_DECODE_LAST_TXN_ID                         70
#define ERROR_LAST_TXN_ID_REQUEST_ID                     71
#define ERROR_LAST_TXN_ID_STATUS                         72
#define ERROR_LAST_TXN_ID_OFFSET                         73
#define ERROR_DECODE_LAST_TXN_ID_DATA                    74
#define ERROR_TXN_PREV_ID_ZERO_ID_MISMATCH               75
#define ERROR_TXN_NEXT_ID_FF_ID_MISMATCH                 76
#define ERROR_TXN_ARTIFACT_ID_MISMATCH                   77
#define ERROR_TXN_BLOCK_ID_MISMATCH                      78
#define ERROR_GET_TXN_REQUEST_ID                         79
#define ERROR_GET_TXN_STATUS                             80
#define ERROR_GET_TXN_OFFSET                             81
#define ERROR_DECODE_TXN_RESP_DATA                       82
#define ERROR_BLOCK_ID_1_MISMATCH                        83
#define ERROR_SEND_BLOCK_ID_BY_HEIGHT_REQ                84
#define ERROR_RECV_BLOCK_ID_BY_HEIGHT_RESP               85
#define ERROR_DECODE_BLOCK_ID_BY_HEIGHT                  86
#define ERROR_BLOCK_ID_BY_HEIGHT_REQUEST_ID              87
#define ERROR_BLOCK_ID_BY_HEIGHT_STATUS                  88
#define ERROR_BLOCK_ID_BY_HEIGHT_OFFSET                  89
#define ERROR_DECODE_BLOCK_ID_BY_HEIGHT_DATA             90
#define ERROR_BLOCK_ID_0_MISMATCH                        91
#define ERROR_SEND_NEXT_TXN_ID_REQ                       92
#define ERROR_RECV_NEXT_TXN_ID_RESP                      93
#define ERROR_DECODE_NEXT_TXN_ID                         94
#define ERROR_NEXT_TXN_ID_REQUEST_ID                     95
#define ERROR_NEXT_TXN_ID_STATUS                         96
#define ERROR_NEXT_TXN_ID_OFFSET                         97
#define ERROR_DECODE_NEXT_TXN_ID_DATA                    98
#define ERROR_SEND_PREV_TXN_ID_REQ                       99
#define ERROR_SEND_HANDSHAKE_REQ                        101
#define ERROR_RECV_HANDSHAKE_RESP                       102
#define ERROR_SERVER_ID_MISMATCH                        103
#define ERROR_SERVER_KEY_MISMATCH                       104
#define ERROR_SEND_HANDSHAKE_ACK                        105
#define ERROR_RECV_HANDSHAKE_ACK                        106
#define ERROR_DECODE_HANDSHAKE_ACK                      107
#define ERROR_HANDSHAKE_ACK_REQUEST_ID                  108
#define ERROR_HANDSHAKE_ACK_STATUS                      109
#define ERROR_RECV_PREV_TXN_ID_RESP                     100
#define ERROR_DECODE_PREV_TXN_ID                        110
#define ERROR_PREV_TXN_ID_REQUEST_ID                    111
#define ERROR_PREV_TXN_ID_STATUS                        112
#define ERROR_PREV_TXN_ID_OFFSET                        113
#define ERROR_DECODE_PREV_TXN_ID_DATA                   114
#define ERROR_SEND_TXN_BLOCK_ID_REQ                     115
#define ERROR_RECV_TXN_BLOCK_ID_RESP                    116
#define ERROR_DECODE_TXN_BLOCK_ID                       117
#define ERROR_TXN_BLOCK_ID_REQUEST_ID                   118
#define ERROR_TXN_BLOCK_ID_STATUS                       119
#define ERROR_TXN_BLOCK_ID_OFFSET                       120
#define ERROR_DECODE_TXN_BLOCK_ID_DATA                  121
#define ERROR_SEND_STATUS_REQ                           122
#define ERROR_RECV_STATUS_RESP                          123
#define ERROR_DECODE_STATUS                             124
#define ERROR_STATUS_REQUEST_ID                         125
#define ERROR_STATUS_STATUS                             126
#define ERROR_STATUS_OFFSET                             127
#define ERROR_DECODE_STATUS_DATA                        128
#define ERROR_SEND_CLOSE_REQ                            129
#define ERROR_RECV_CLOSE_RESP                           130
#define ERROR_DECODE_CLOSE                              131
#define ERROR_CLOSE_REQUEST_ID                          132
#define ERROR_CLOSE_STATUS                              133
#define ERROR_CLOSE_OFFSET                              134
#define ERROR_DECODE_CLOSE_DATA                         135
#define ERROR_EXTENDED_API_ENABLE_REQ                   136
#define ERROR_RECV_EXTENDED_API_ENABLE_RESP             137
#define ERROR_DECODE_EXTENDED_API_ENABLE_HEADER         138
#define ERROR_EXTENDED_API_ENABLE_REQUEST_ID            139
#define ERROR_EXTENDED_API_ENABLE_STATUS                140
#define ERROR_EXTENDED_API_ENABLE_OFFSET                141
#define ERROR_DECODE_EXTENDED_API_ENABLE                142

/* status codes specific to submit_multiple_txns test. */
#define ERROR_TXN1_PREV_ID_MISMATCH                     200
#define ERROR_TXN1_NEXT_ID_MISMATCH                     201
#define ERROR_TXN1_ARTIFACT_ID_MISMATCH                 202
#define ERROR_TXN2_PREV_ID_MISMATCH                     203
#define ERROR_TXN2_NEXT_ID_MISMATCH                     204
#define ERROR_TXN2_ARTIFACT_ID_MISMATCH                 205
#define ERROR_TXN3_PREV_ID_MISMATCH                     206
#define ERROR_TXN3_NEXT_ID_MISMATCH                     207
#define ERROR_TXN3_ARTIFACT_ID_MISMATCH                 208
#define ERROR_TXN1_NEXT_ID_MISMATCH2                    209
#define ERROR_TXN2_NEXT_ID_MISMATCH2                    210
#define ERROR_TXN3_PREV_ID_MISMATCH2                    211
#define ERROR_TXN2_PREV_ID_MISMATCH2                    212
#define ERROR_TXN1_BLOCK_ID_MISMATCH                    213
#define ERROR_TXN2_BLOCK_ID_MISMATCH                    214
#define ERROR_TXN3_BLOCK_ID_MISMATCH                    215

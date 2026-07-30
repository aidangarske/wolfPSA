/* service.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfPSA.
 *
 * wolfPSA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfPSA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* PSA Firmware Framework secure-side API (FF-M 1.1), SFN model.
 *
 * A service is a function called directly on the client's stack, so the
 * blocking primitives of the IPC model (psa_wait, psa_get, psa_reply) are not
 * part of this surface. */

#ifndef PSA_SERVICE_H
#define PSA_SERVICE_H

#include <stddef.h>
#include <stdint.h>

#include "psa/error.h"
#include "psa/client.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSA_MSG_TYPE_CONNECT        (-1)
#define PSA_MSG_TYPE_DISCONNECT     (-2)

typedef int32_t psa_signal_t;

/* Identifies the caller so a service can separate clients. Non-secure callers
 * are negative, secure partitions positive, per FF-M. */
typedef int32_t psa_client_id_t;

#define PSA_CLIENT_ID_NON_SECURE    (-1)

typedef struct psa_msg_t {
    int32_t         type;
    psa_handle_t    handle;
    psa_client_id_t client_id;
    void           *rhandle;
    size_t          in_size[PSA_MAX_IOVEC];
    size_t          out_size[PSA_MAX_IOVEC];
} psa_msg_t;

/**
 * \brief Read from an input vector of the current message.
 *
 * \param msg_handle  Handle from the message being served.
 * \param invec_idx   Input vector index.
 * \param buffer      Destination.
 * \param num_bytes   Bytes to read.
 * \return Bytes actually copied.
 */
size_t psa_read(psa_handle_t msg_handle, uint32_t invec_idx,
                void *buffer, size_t num_bytes);

/**
 * \brief Advance past bytes of an input vector without copying them.
 *
 * \param msg_handle  Handle from the message being served.
 * \param invec_idx   Input vector index.
 * \param num_bytes   Bytes to skip.
 * \return Bytes actually skipped.
 */
size_t psa_skip(psa_handle_t msg_handle, uint32_t invec_idx,
                size_t num_bytes);

/**
 * \brief Write to an output vector of the current message.
 *
 * \param msg_handle  Handle from the message being served.
 * \param outvec_idx  Output vector index.
 * \param buffer      Source.
 * \param num_bytes   Bytes to write.
 */
void psa_write(psa_handle_t msg_handle, uint32_t outvec_idx,
               const void *buffer, size_t num_bytes);

/**
 * \brief Associate caller-defined state with the connection.
 *
 * \param msg_handle  Handle from the message being served.
 * \param rhandle     Value to associate.
 */
void psa_set_rhandle(psa_handle_t msg_handle, void *rhandle);

/**
 * \brief Terminate a misbehaving client.
 *
 * \param client_id  Caller to terminate.
 */
void psa_panic(void);

/* A service entry point under the SFN model. */
typedef psa_status_t (*psa_service_sfn_t)(const psa_msg_t *msg);

/**
 * \brief Register a service so psa_connect()/psa_call() can reach it.
 *
 * Static registration replaces the manifest-driven partition table used by a
 * full IPC implementation.
 *
 * \param sid      Service identifier.
 * \param version  Service version.
 * \param sfn      Entry point.
 * \return PSA_SUCCESS, or an error if the table is full or sid is duplicated.
 */
psa_status_t wolfPSA_Service_Register(uint32_t sid, uint32_t version,
                                      psa_service_sfn_t sfn);

/**
 * \brief Remove every registered service.
 */
void wolfPSA_Service_ResetAll(void);

#ifdef __cplusplus
}
#endif

#endif /* PSA_SERVICE_H */

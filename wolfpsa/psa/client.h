/* client.h
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

/* PSA Firmware Framework client API (FF-M 1.1), SFN model.
 *
 * SFN dispatches a call straight to the service's entry point, so there is no
 * message queue and psa_connect() returns a static handle rather than
 * establishing a session. */

#ifndef PSA_CLIENT_H
#define PSA_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "psa/error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSA_FRAMEWORK_VERSION       (0x0101u)
#define PSA_VERSION_NONE            (0u)

#define PSA_NULL_HANDLE             ((psa_handle_t)0)

#define PSA_MAX_IOVEC               (4u)

#define PSA_IPC_CALL                (0)

typedef int32_t psa_handle_t;

#define PSA_HANDLE_IS_VALID(handle) ((psa_handle_t)(handle) > 0)
#define PSA_HANDLE_TO_ERROR(handle) ((psa_status_t)(handle))

typedef struct psa_invec {
    const void *base;
    size_t      len;
} psa_invec;

typedef struct psa_outvec {
    void   *base;
    size_t  len;
} psa_outvec;

/**
 * \brief Report the implemented Firmware Framework version.
 *
 * \return PSA_FRAMEWORK_VERSION.
 */
uint32_t psa_framework_version(void);

/**
 * \brief Report the version of a registered service.
 *
 * \param sid  Service identifier.
 * \return The service version, or PSA_VERSION_NONE if not present.
 */
uint32_t psa_version(uint32_t sid);

/**
 * \brief Obtain a handle for a service.
 *
 * Under SFN this validates the service and version and returns a static
 * handle; no session state is created.
 *
 * \param sid      Service identifier.
 * \param version  Requested version.
 * \return A handle, or a negative psa_status_t on failure.
 */
psa_handle_t psa_connect(uint32_t sid, uint32_t version);

/**
 * \brief Invoke a service.
 *
 * \param handle   Handle from psa_connect(), or a static handle.
 * \param type     Request type; PSA_IPC_CALL for a normal request.
 * \param in_vec   Input vectors.
 * \param in_len   Number of input vectors (max PSA_MAX_IOVEC).
 * \param out_vec  Output vectors.
 * \param out_len  Number of output vectors (in_len + out_len <= PSA_MAX_IOVEC).
 * \return The service's status, or an error.
 */
psa_status_t psa_call(psa_handle_t handle, int32_t type,
                      const psa_invec *in_vec, size_t in_len,
                      psa_outvec *out_vec, size_t out_len);

/**
 * \brief Release a handle.
 *
 * \param handle  Handle from psa_connect().
 */
void psa_close(psa_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif /* PSA_CLIENT_H */

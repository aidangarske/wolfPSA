/* internal_trusted_storage.h
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

/* PSA Internal Trusted Storage API 1.0. Records are held by the
 * wolfPSA_Store_* backend, so confidentiality and replay protection are
 * whatever that backend provides. */

#ifndef PSA_INTERNAL_TRUSTED_STORAGE_H
#define PSA_INTERNAL_TRUSTED_STORAGE_H

#include <stddef.h>
#include <stdint.h>

#include "psa/error.h"
#include "psa/storage_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSA_ITS_API_VERSION_MAJOR 1
#define PSA_ITS_API_VERSION_MINOR 0

/**
 * \brief Create or overwrite a record.
 *
 * Overwriting a record created with PSA_STORAGE_FLAG_WRITE_ONCE fails with
 * PSA_ERROR_NOT_PERMITTED.
 *
 * \param uid           Non-zero caller-chosen identifier.
 * \param data_length   Length of p_data in bytes.
 * \param p_data        Data to store. May be NULL only if data_length is 0.
 * \param create_flags  PSA_STORAGE_FLAG_* bitmask.
 * \return PSA_SUCCESS or an error code.
 */
psa_status_t psa_its_set(psa_storage_uid_t uid,
                         size_t data_length,
                         const void *p_data,
                         psa_storage_create_flags_t create_flags);

/**
 * \brief Read all or part of a record.
 *
 * \param uid            Identifier of the record.
 * \param data_offset    Offset within the record to start reading.
 * \param data_size      Number of bytes to read.
 * \param p_data         Output buffer.
 * \param p_data_length  Output: bytes actually written to p_data.
 * \return PSA_SUCCESS or an error code.
 */
psa_status_t psa_its_get(psa_storage_uid_t uid,
                         size_t data_offset,
                         size_t data_size,
                         void *p_data,
                         size_t *p_data_length);

/**
 * \brief Report size and flags of a record without reading it.
 *
 * \param uid     Identifier of the record.
 * \param p_info  Output: capacity, size and flags.
 * \return PSA_SUCCESS or an error code.
 */
psa_status_t psa_its_get_info(psa_storage_uid_t uid,
                              struct psa_storage_info_t *p_info);

/**
 * \brief Remove a record.
 *
 * Removing a record created with PSA_STORAGE_FLAG_WRITE_ONCE fails with
 * PSA_ERROR_NOT_PERMITTED.
 *
 * \param uid  Identifier of the record.
 * \return PSA_SUCCESS or an error code.
 */
psa_status_t psa_its_remove(psa_storage_uid_t uid);

#ifdef __cplusplus
}
#endif

#endif /* PSA_INTERNAL_TRUSTED_STORAGE_H */

/* psa_its.c
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

#include <string.h>

#include "psa/internal_trusted_storage.h"
#include "psa_store.h"
#include "psa_trace.h"

/* A uid is 64-bit but the backend takes two unsigned longs, so it is split
 * rather than truncated; on a 32-bit target a cast would alias records. */
#define ITS_UID_LO(uid) ((unsigned long)((uid) & 0xFFFFFFFFu))
#define ITS_UID_HI(uid) ((unsigned long)(((uid) >> 32) & 0xFFFFFFFFu))

#define ITS_MAGIC 0x53544901u /* "\1ITS" */

/* Written ahead of the payload so flags and length survive a reboot. */
typedef struct {
    uint32_t magic;
    uint32_t flags;
    uint32_t length;
} its_header_t;

static psa_status_t its_read_header(psa_storage_uid_t uid, its_header_t *hdr,
                                    void **store_out)
{
    void *store = NULL;
    int ret;

    ret = wolfPSA_Store_Open(WOLFPSA_STORE_ITS, ITS_UID_LO(uid),
                             ITS_UID_HI(uid), 1, &store);
    if (ret != 0) {
        return PSA_ERROR_DOES_NOT_EXIST;
    }

    ret = wolfPSA_Store_Read(store, (unsigned char *)hdr, (int)sizeof(*hdr));
    if (ret != (int)sizeof(*hdr)) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_DATA_CORRUPT;
    }
    if (hdr->magic != ITS_MAGIC) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_DATA_CORRUPT;
    }

    if (store_out != NULL) {
        *store_out = store;
    }
    else {
        wolfPSA_Store_Close(store);
    }
    return PSA_SUCCESS;
}

psa_status_t psa_its_set(psa_storage_uid_t uid, size_t data_length,
                         const void *p_data,
                         psa_storage_create_flags_t create_flags)
{
    its_header_t hdr;
    void *store = NULL;
    psa_status_t status;
    int ret;

    wolfpsa_trace("psa_its_set(uid=%llu len=%zu flags=0x%08x)",
                  (unsigned long long)uid, data_length,
                  (unsigned)create_flags);

    if (uid == 0u) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((p_data == NULL) && (data_length > 0u)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((create_flags & ~(PSA_STORAGE_FLAG_WRITE_ONCE |
                          PSA_STORAGE_FLAG_NO_CONFIDENTIALITY |
                          PSA_STORAGE_FLAG_NO_REPLAY_PROTECTION)) != 0u) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* A write-once record may not be replaced, so the existing header has to
     * be consulted before anything is overwritten. */
    status = its_read_header(uid, &hdr, NULL);
    if (status == PSA_SUCCESS) {
        if ((hdr.flags & PSA_STORAGE_FLAG_WRITE_ONCE) != 0u) {
            return PSA_ERROR_NOT_PERMITTED;
        }
    }
    else if (status == PSA_ERROR_DATA_CORRUPT) {
        return status;
    }

    ret = wolfPSA_Store_OpenSz(WOLFPSA_STORE_ITS, ITS_UID_LO(uid),
                               ITS_UID_HI(uid), 0,
                               (int)(sizeof(its_header_t) + data_length),
                               &store);
    if (ret != 0) {
        return PSA_ERROR_INSUFFICIENT_STORAGE;
    }

    hdr.magic = ITS_MAGIC;
    hdr.flags = (uint32_t)create_flags;
    hdr.length = (uint32_t)data_length;

    ret = wolfPSA_Store_Write(store, (unsigned char *)&hdr,
                              (int)sizeof(hdr));
    if (ret != (int)sizeof(hdr)) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_STORAGE_FAILURE;
    }

    if (data_length > 0u) {
        ret = wolfPSA_Store_Write(store, (unsigned char *)p_data,
                                  (int)data_length);
        if (ret != (int)data_length) {
            wolfPSA_Store_Close(store);
            return PSA_ERROR_STORAGE_FAILURE;
        }
    }

    wolfPSA_Store_Close(store);
    return PSA_SUCCESS;
}

psa_status_t psa_its_get(psa_storage_uid_t uid, size_t data_offset,
                         size_t data_size, void *p_data,
                         size_t *p_data_length)
{
    its_header_t hdr;
    void *store = NULL;
    psa_status_t status;
    unsigned char skip[32];
    size_t remaining;
    size_t to_read;
    int ret;

    wolfpsa_trace("psa_its_get(uid=%llu off=%zu size=%zu)",
                  (unsigned long long)uid, data_offset, data_size);

    if ((uid == 0u) || (p_data_length == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((p_data == NULL) && (data_size > 0u)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    *p_data_length = 0;

    status = its_read_header(uid, &hdr, &store);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (data_offset > (size_t)hdr.length) {
        wolfPSA_Store_Close(store);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* The backend is sequential, so the offset is consumed by reading and
     * discarding rather than by seeking. */
    remaining = data_offset;
    while (remaining > 0u) {
        to_read = (remaining < sizeof(skip)) ? remaining : sizeof(skip);
        ret = wolfPSA_Store_Read(store, skip, (int)to_read);
        if (ret != (int)to_read) {
            wolfPSA_Store_Close(store);
            return PSA_ERROR_DATA_CORRUPT;
        }
        remaining -= to_read;
    }

    to_read = (size_t)hdr.length - data_offset;
    if (to_read > data_size) {
        to_read = data_size;
    }

    if (to_read > 0u) {
        ret = wolfPSA_Store_Read(store, (unsigned char *)p_data, (int)to_read);
        if (ret != (int)to_read) {
            wolfPSA_Store_Close(store);
            return PSA_ERROR_DATA_CORRUPT;
        }
    }

    wolfPSA_Store_Close(store);
    *p_data_length = to_read;
    return PSA_SUCCESS;
}

psa_status_t psa_its_get_info(psa_storage_uid_t uid,
                              struct psa_storage_info_t *p_info)
{
    its_header_t hdr;
    psa_status_t status;

    wolfpsa_trace("psa_its_get_info(uid=%llu)", (unsigned long long)uid);

    if ((uid == 0u) || (p_info == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = its_read_header(uid, &hdr, NULL);
    if (status != PSA_SUCCESS) {
        return status;
    }

    p_info->size = (size_t)hdr.length;
    p_info->capacity = (size_t)hdr.length;
    p_info->flags = (psa_storage_create_flags_t)hdr.flags;
    return PSA_SUCCESS;
}

psa_status_t psa_its_remove(psa_storage_uid_t uid)
{
    its_header_t hdr;
    psa_status_t status;
    int ret;

    wolfpsa_trace("psa_its_remove(uid=%llu)", (unsigned long long)uid);

    if (uid == 0u) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = its_read_header(uid, &hdr, NULL);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if ((hdr.flags & PSA_STORAGE_FLAG_WRITE_ONCE) != 0u) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    ret = wolfPSA_Store_Remove(WOLFPSA_STORE_ITS, ITS_UID_LO(uid),
                               ITS_UID_HI(uid));
    if (ret != 0) {
        return PSA_ERROR_STORAGE_FAILURE;
    }
    return PSA_SUCCESS;
}

/* storage_common.h
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

/* Definitions shared by the PSA Internal Trusted Storage and Protected
 * Storage APIs (PSA Storage API 1.0). */

#ifndef PSA_STORAGE_COMMON_H
#define PSA_STORAGE_COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t psa_storage_uid_t;
typedef uint32_t psa_storage_create_flags_t;

#define PSA_STORAGE_FLAG_NONE                    0u
#define PSA_STORAGE_FLAG_WRITE_ONCE              (1u << 0)
#define PSA_STORAGE_FLAG_NO_CONFIDENTIALITY      (1u << 1)
#define PSA_STORAGE_FLAG_NO_REPLAY_PROTECTION    (1u << 2)

/* Returned by psa_its_get_support(); set_extended is not implemented. */
#define PSA_STORAGE_SUPPORT_SET_EXTENDED         (1u << 0)

struct psa_storage_info_t {
    size_t                     capacity;
    size_t                     size;
    psa_storage_create_flags_t flags;
};

#ifdef __cplusplus
}
#endif

#endif /* PSA_STORAGE_COMMON_H */

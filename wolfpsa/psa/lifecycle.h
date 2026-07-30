/* lifecycle.h
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

/* PSA Root of Trust lifecycle state, as reported to secure partitions. */

#ifndef PSA_LIFECYCLE_H
#define PSA_LIFECYCLE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PSA_LIFECYCLE_PSA_STATE_MASK            (0xff00u)
#define PSA_LIFECYCLE_IMP_STATE_MASK            (0x00ffu)

#define PSA_LIFECYCLE_UNKNOWN                   (0x0000u)
#define PSA_LIFECYCLE_ASSEMBLY_AND_TEST         (0x1000u)
#define PSA_LIFECYCLE_PSA_ROT_PROVISIONING      (0x2000u)
#define PSA_LIFECYCLE_SECURED                   (0x3000u)
#define PSA_LIFECYCLE_NON_PSA_ROT_DEBUG         (0x4000u)
#define PSA_LIFECYCLE_RECOVERABLE_PSA_ROT_DEBUG (0x5000u)
#define PSA_LIFECYCLE_DECOMMISSIONED            (0x6000u)

/**
 * \brief Report the current PSA RoT lifecycle state.
 *
 * The platform supplies the value through wolfPSA_Lifecycle_GetState(); when
 * no platform hook is linked, PSA_LIFECYCLE_UNKNOWN is reported rather than
 * claiming a state the device cannot substantiate.
 *
 * \return One of the PSA_LIFECYCLE_* values.
 */
uint32_t psa_rot_lifecycle_state(void);

/**
 * \brief Platform hook supplying the lifecycle state.
 *
 * Implement on the target to report a real state. Weakly defined so a build
 * without a platform implementation still links.
 *
 * \param state  Output: a PSA_LIFECYCLE_* value.
 * \return 0 on success, non-zero if the state cannot be determined.
 */
int wolfPSA_Lifecycle_GetState(uint32_t *state);

#ifdef __cplusplus
}
#endif

#endif /* PSA_LIFECYCLE_H */

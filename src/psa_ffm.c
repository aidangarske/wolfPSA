/* psa_ffm.c
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

/* PSA Firmware Framework, SFN model. A call runs the service on the caller's
 * stack, so the iovecs stay addressable for the duration and psa_read /
 * psa_write copy against them directly. */

#include <string.h>

#include "psa/client.h"
#include "psa/service.h"
#include "psa/lifecycle.h"
#include "psa_trace.h"

#ifndef WOLFPSA_MAX_SERVICES
#define WOLFPSA_MAX_SERVICES 8
#endif

typedef struct {
    uint32_t          sid;
    uint32_t          version;
    psa_service_sfn_t sfn;
    int               in_use;
} wolfpsa_service_t;

static wolfpsa_service_t g_services[WOLFPSA_MAX_SERVICES];

/* The call in progress. SFN is synchronous and non-reentrant, so one frame is
 * enough; nesting would need a stack of these. */
typedef struct {
    const psa_invec *in_vec;
    size_t           in_len;
    psa_outvec      *out_vec;
    size_t           out_len;
    size_t           in_offset[PSA_MAX_IOVEC];
    size_t           out_offset[PSA_MAX_IOVEC];
    int              active;
} wolfpsa_call_frame_t;

static wolfpsa_call_frame_t g_frame;

/* Handles are indices into g_services, biased so 0 stays PSA_NULL_HANDLE. */
#define SVC_HANDLE(idx)  ((psa_handle_t)((idx) + 1))
#define SVC_INDEX(h)     ((int)((h) - 1))

static wolfpsa_service_t *service_from_handle(psa_handle_t handle)
{
    int idx;

    if (!PSA_HANDLE_IS_VALID(handle)) {
        return NULL;
    }
    idx = SVC_INDEX(handle);
    if ((idx < 0) || (idx >= WOLFPSA_MAX_SERVICES)) {
        return NULL;
    }
    if (!g_services[idx].in_use) {
        return NULL;
    }
    return &g_services[idx];
}

psa_status_t wolfPSA_Service_Register(uint32_t sid, uint32_t version,
                                      psa_service_sfn_t sfn)
{
    int i;
    int free_slot = -1;

    if (sfn == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    for (i = 0; i < WOLFPSA_MAX_SERVICES; i++) {
        if (g_services[i].in_use && (g_services[i].sid == sid)) {
            return PSA_ERROR_ALREADY_EXISTS;
        }
        if (!g_services[i].in_use && (free_slot < 0)) {
            free_slot = i;
        }
    }
    if (free_slot < 0) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    g_services[free_slot].sid = sid;
    g_services[free_slot].version = version;
    g_services[free_slot].sfn = sfn;
    g_services[free_slot].in_use = 1;
    return PSA_SUCCESS;
}

void wolfPSA_Service_ResetAll(void)
{
    memset(g_services, 0, sizeof(g_services));
    memset(&g_frame, 0, sizeof(g_frame));
}

uint32_t psa_framework_version(void)
{
    return PSA_FRAMEWORK_VERSION;
}

uint32_t psa_version(uint32_t sid)
{
    int i;

    for (i = 0; i < WOLFPSA_MAX_SERVICES; i++) {
        if (g_services[i].in_use && (g_services[i].sid == sid)) {
            return g_services[i].version;
        }
    }
    return PSA_VERSION_NONE;
}

psa_handle_t psa_connect(uint32_t sid, uint32_t version)
{
    int i;

    for (i = 0; i < WOLFPSA_MAX_SERVICES; i++) {
        if (g_services[i].in_use && (g_services[i].sid == sid)) {
            if (g_services[i].version < version) {
                return (psa_handle_t)PSA_ERROR_CONNECTION_REFUSED;
            }
            return SVC_HANDLE(i);
        }
    }
    return (psa_handle_t)PSA_ERROR_CONNECTION_REFUSED;
}

void psa_close(psa_handle_t handle)
{
    /* SFN keeps no per-connection state, so there is nothing to release. The
     * call still validates the handle so misuse is not silently accepted. */
    (void)service_from_handle(handle);
}

psa_status_t psa_call(psa_handle_t handle, int32_t type,
                      const psa_invec *in_vec, size_t in_len,
                      psa_outvec *out_vec, size_t out_len)
{
    wolfpsa_service_t *svc;
    psa_msg_t msg;
    psa_status_t status;
    size_t i;

    wolfpsa_trace("psa_call(handle=%d type=%d in=%zu out=%zu)",
                  (int)handle, (int)type, in_len, out_len);

    svc = service_from_handle(handle);
    if (svc == NULL) {
        return PSA_ERROR_INVALID_HANDLE;
    }
    if ((in_len > PSA_MAX_IOVEC) || (out_len > PSA_MAX_IOVEC) ||
        ((in_len + out_len) > PSA_MAX_IOVEC)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (((in_len > 0u) && (in_vec == NULL)) ||
        ((out_len > 0u) && (out_vec == NULL))) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    /* Nesting would overwrite the frame the outer call is still reading. */
    if (g_frame.active) {
        return PSA_ERROR_BAD_STATE;
    }

    memset(&msg, 0, sizeof(msg));
    msg.type = type;
    msg.handle = handle;
    msg.client_id = PSA_CLIENT_ID_NON_SECURE;
    for (i = 0; i < in_len; i++) {
        msg.in_size[i] = in_vec[i].len;
    }
    for (i = 0; i < out_len; i++) {
        msg.out_size[i] = out_vec[i].len;
    }

    memset(&g_frame, 0, sizeof(g_frame));
    g_frame.in_vec = in_vec;
    g_frame.in_len = in_len;
    g_frame.out_vec = out_vec;
    g_frame.out_len = out_len;
    g_frame.active = 1;

    status = svc->sfn(&msg);

    /* Report what the service actually wrote, per FF-M. */
    for (i = 0; i < out_len; i++) {
        out_vec[i].len = g_frame.out_offset[i];
    }
    g_frame.active = 0;
    return status;
}

size_t psa_read(psa_handle_t msg_handle, uint32_t invec_idx,
                void *buffer, size_t num_bytes)
{
    size_t avail;
    size_t to_copy;

    (void)msg_handle;

    if (!g_frame.active || (buffer == NULL) ||
        (invec_idx >= g_frame.in_len)) {
        return 0;
    }

    avail = g_frame.in_vec[invec_idx].len - g_frame.in_offset[invec_idx];
    to_copy = (num_bytes < avail) ? num_bytes : avail;
    if (to_copy > 0u) {
        memcpy(buffer,
               (const unsigned char *)g_frame.in_vec[invec_idx].base +
                   g_frame.in_offset[invec_idx],
               to_copy);
        g_frame.in_offset[invec_idx] += to_copy;
    }
    return to_copy;
}

size_t psa_skip(psa_handle_t msg_handle, uint32_t invec_idx,
                size_t num_bytes)
{
    size_t avail;
    size_t to_skip;

    (void)msg_handle;

    if (!g_frame.active || (invec_idx >= g_frame.in_len)) {
        return 0;
    }

    avail = g_frame.in_vec[invec_idx].len - g_frame.in_offset[invec_idx];
    to_skip = (num_bytes < avail) ? num_bytes : avail;
    g_frame.in_offset[invec_idx] += to_skip;
    return to_skip;
}

void psa_write(psa_handle_t msg_handle, uint32_t outvec_idx,
               const void *buffer, size_t num_bytes)
{
    size_t space;

    (void)msg_handle;

    if (!g_frame.active || (buffer == NULL) ||
        (outvec_idx >= g_frame.out_len)) {
        return;
    }

    space = g_frame.out_vec[outvec_idx].len - g_frame.out_offset[outvec_idx];
    /* Overrunning the caller's buffer is a programming error in the service,
     * so refuse the write rather than truncate it silently. */
    if (num_bytes > space) {
        return;
    }

    memcpy((unsigned char *)g_frame.out_vec[outvec_idx].base +
               g_frame.out_offset[outvec_idx],
           buffer, num_bytes);
    g_frame.out_offset[outvec_idx] += num_bytes;
}

void psa_set_rhandle(psa_handle_t msg_handle, void *rhandle)
{
    /* Reverse handles belong to connection state, which SFN does not keep. */
    (void)msg_handle;
    (void)rhandle;
}

void psa_panic(void)
{
    /* A platform is expected to reset here; looping is the safe default when
     * no platform hook is linked, since returning would let a caller that
     * violated the framework contract keep running. */
    for (;;) {
    }
}

/* Weak so a platform can override it by simply linking its own definition;
 * without one the device must not claim a lifecycle state it cannot prove. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
int wolfPSA_Lifecycle_GetState(uint32_t *state)
{
    (void)state;
    return -1;
}
#endif

uint32_t psa_rot_lifecycle_state(void)
{
    uint32_t state = PSA_LIFECYCLE_UNKNOWN;

    if (wolfPSA_Lifecycle_GetState(&state) != 0) {
        return PSA_LIFECYCLE_UNKNOWN;
    }
    return state;
}

/* Exercise the PSA Firmware Framework SFN dispatch. */
#include <psa/client.h>
#include <psa/service.h>
#include <psa/lifecycle.h>
#include <stdio.h>
#include <string.h>

#define TEST_SID     0x00000101u
#define TEST_VERSION 2u

static int fails;
#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS: %s\n", name); } \
    else { printf("  FAIL: %s (line %d)\n", name, __LINE__); fails++; } } while (0)

/* Echoes invec 0 to outvec 0, uppercased, and reports the size it saw. */
static psa_status_t echo_sfn(const psa_msg_t *msg)
{
    unsigned char buf[64];
    size_t got, i;

    if (msg->type != PSA_IPC_CALL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    got = psa_read(msg->handle, 0, buf, sizeof(buf));
    for (i = 0; i < got; i++) {
        if (buf[i] >= 'a' && buf[i] <= 'z') buf[i] = (unsigned char)(buf[i] - 32);
    }
    psa_write(msg->handle, 0, buf, got);
    return (psa_status_t)got;
}

/* Tries to write more than the caller offered. */
static psa_status_t overrun_sfn(const psa_msg_t *msg)
{
    unsigned char big[128];
    memset(big, 'X', sizeof(big));
    psa_write(msg->handle, 0, big, sizeof(big));
    return PSA_SUCCESS;
}

int main(void)
{
    psa_handle_t h;
    psa_status_t st;
    char in[] = "hello framework";
    char out[64];
    psa_invec iv[1];
    psa_outvec ov[1];

    printf("=== PSA Firmware Framework (SFN) ===\n");
    wolfPSA_Service_ResetAll();

    CHECK(psa_framework_version() == 0x0101u, "framework version is 1.1");

    /* unknown service */
    CHECK(psa_version(0xDEAD) == PSA_VERSION_NONE, "unknown sid has no version");
    h = psa_connect(0xDEAD, 1);
    CHECK(!PSA_HANDLE_IS_VALID(h), "connect to unknown sid refused");

    /* register */
    st = wolfPSA_Service_Register(TEST_SID, TEST_VERSION, echo_sfn);
    CHECK(st == PSA_SUCCESS, "register service");
    st = wolfPSA_Service_Register(TEST_SID, TEST_VERSION, echo_sfn);
    CHECK(st == PSA_ERROR_ALREADY_EXISTS, "duplicate sid refused");
    CHECK(psa_version(TEST_SID) == TEST_VERSION, "version reported");

    /* version negotiation */
    h = psa_connect(TEST_SID, TEST_VERSION + 1);
    CHECK(!PSA_HANDLE_IS_VALID(h), "newer version than offered refused");
    h = psa_connect(TEST_SID, TEST_VERSION);
    CHECK(PSA_HANDLE_IS_VALID(h), "connect");

    /* round trip */
    iv[0].base = in;  iv[0].len = strlen(in);
    memset(out, 0, sizeof(out));
    ov[0].base = out; ov[0].len = sizeof(out);
    st = psa_call(h, PSA_IPC_CALL, iv, 1, ov, 1);
    CHECK(st == (psa_status_t)strlen(in), "service saw the whole invec");
    CHECK(strcmp(out, "HELLO FRAMEWORK") == 0, "outvec content");
    CHECK(ov[0].len == strlen(in), "outvec len reports bytes written");

    /* too many iovecs */
    st = psa_call(h, PSA_IPC_CALL, iv, 3, ov, 3);
    CHECK(st == PSA_ERROR_INVALID_ARGUMENT, "iovec budget enforced");

    /* bad handle */
    st = psa_call(PSA_NULL_HANDLE, PSA_IPC_CALL, iv, 1, ov, 1);
    CHECK(st == PSA_ERROR_INVALID_HANDLE, "null handle rejected");

    /* a service must not overrun the caller's outvec */
    st = wolfPSA_Service_Register(0x202, 1, overrun_sfn);
    CHECK(st == PSA_SUCCESS, "register overrun service");
    h = psa_connect(0x202, 1);
    memset(out, 0, sizeof(out));
    ov[0].base = out; ov[0].len = 8;
    st = psa_call(h, PSA_IPC_CALL, iv, 1, ov, 1);
    CHECK(ov[0].len == 0, "oversized service write refused");

    /* lifecycle reports UNKNOWN rather than claiming a state */
    CHECK(psa_rot_lifecycle_state() == PSA_LIFECYCLE_UNKNOWN,
          "lifecycle defaults to UNKNOWN");

    printf(fails ? "\n=== FAILURES: %d ===\n" : "\n=== ALL PASSED ===\n", fails);
    return fails ? 1 : 0;
}

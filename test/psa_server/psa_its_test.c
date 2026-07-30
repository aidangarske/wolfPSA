/* Exercise the PSA ITS semantics against the real store backend. */
#include <psa/internal_trusted_storage.h>
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS: %s\n", name); } \
    else { printf("  FAIL: %s (line %d)\n", name, __LINE__); fails++; } } while (0)

int main(void)
{
    psa_status_t st;
    uint8_t in[64], out[64];
    size_t got = 0;
    struct psa_storage_info_t info;

    memset(in, 0xA5, sizeof(in));
    memset(out, 0, sizeof(out));

    printf("=== PSA ITS ===\n");

    /* uid 0 is reserved */
    st = psa_its_set(0, sizeof(in), in, PSA_STORAGE_FLAG_NONE);
    CHECK(st == PSA_ERROR_INVALID_ARGUMENT, "uid 0 rejected");

    /* absent record */
    st = psa_its_get(0x1000, 0, sizeof(out), out, &got);
    CHECK(st == PSA_ERROR_DOES_NOT_EXIST, "missing uid reports DOES_NOT_EXIST");

    /* round trip */
    st = psa_its_set(0x1001, sizeof(in), in, PSA_STORAGE_FLAG_NONE);
    CHECK(st == PSA_SUCCESS, "set");
    st = psa_its_get(0x1001, 0, sizeof(out), out, &got);
    CHECK(st == PSA_SUCCESS && got == sizeof(in) &&
          memcmp(in, out, sizeof(in)) == 0, "get round trip");

    /* info without reading */
    st = psa_its_get_info(0x1001, &info);
    CHECK(st == PSA_SUCCESS && info.size == sizeof(in) &&
          info.flags == PSA_STORAGE_FLAG_NONE, "get_info");

    /* partial read at an offset */
    memset(out, 0, sizeof(out));
    st = psa_its_get(0x1001, 16, 8, out, &got);
    CHECK(st == PSA_SUCCESS && got == 8 && memcmp(out, in + 16, 8) == 0,
          "get at offset");

    /* offset past the end */
    st = psa_its_get(0x1001, sizeof(in) + 1, 4, out, &got);
    CHECK(st == PSA_ERROR_INVALID_ARGUMENT, "offset past end rejected");

    /* overwrite is allowed without WRITE_ONCE */
    memset(in, 0x5A, sizeof(in));
    st = psa_its_set(0x1001, sizeof(in), in, PSA_STORAGE_FLAG_NONE);
    CHECK(st == PSA_SUCCESS, "overwrite allowed");
    st = psa_its_get(0x1001, 0, sizeof(out), out, &got);
    CHECK(st == PSA_SUCCESS && memcmp(in, out, sizeof(in)) == 0,
          "overwrite took effect");

    /* remove */
    st = psa_its_remove(0x1001);
    CHECK(st == PSA_SUCCESS, "remove");
    st = psa_its_get(0x1001, 0, sizeof(out), out, &got);
    CHECK(st == PSA_ERROR_DOES_NOT_EXIST, "removed record is gone");

    /* WRITE_ONCE cannot be replaced or removed. A record left by an earlier
     * run cannot be cleaned up either -- that is the property under test --
     * so treat an existing one as the precondition rather than re-creating
     * it, otherwise the suite only passes on a pristine store. */
    if ((psa_its_get_info(0x1002, &info) == PSA_SUCCESS) &&
        ((info.flags & PSA_STORAGE_FLAG_WRITE_ONCE) != 0u)) {
        printf("  PASS: set write-once (record persists from an earlier run)\n");
    }
    else {
        st = psa_its_set(0x1002, 8, in, PSA_STORAGE_FLAG_WRITE_ONCE);
        CHECK(st == PSA_SUCCESS, "set write-once");
    }
    st = psa_its_set(0x1002, 8, in, PSA_STORAGE_FLAG_NONE);
    CHECK(st == PSA_ERROR_NOT_PERMITTED, "write-once overwrite refused");
    st = psa_its_remove(0x1002);
    CHECK(st == PSA_ERROR_NOT_PERMITTED, "write-once remove refused");

    /* zero-length record is legal */
    st = psa_its_set(0x1003, 0, NULL, PSA_STORAGE_FLAG_NONE);
    CHECK(st == PSA_SUCCESS, "zero-length set");
    st = psa_its_get(0x1003, 0, sizeof(out), out, &got);
    CHECK(st == PSA_SUCCESS && got == 0, "zero-length get");

    printf(fails ? "\n=== FAILURES: %d ===\n" : "\n=== ALL PASSED ===\n", fails);
    return fails ? 1 : 0;
}

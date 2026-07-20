/* crypto_config.h
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

#ifndef WOLFPSA_CRYPTO_CONFIG_H
#define WOLFPSA_CRYPTO_CONFIG_H


/* Hashes */
/* SHA-1 is deprecated; enable explicitly if wolfCrypt provides it. */
/* #define PSA_WANT_ALG_SHA_1 */
#define PSA_WANT_ALG_SHA_224
#define PSA_WANT_ALG_SHA_256
#define PSA_WANT_ALG_SHA_384
#define PSA_WANT_ALG_SHA_512

/* MAC */
#define PSA_WANT_ALG_HMAC
#define PSA_WANT_ALG_CMAC

/* Cipher */
#define PSA_WANT_ALG_CBC_NO_PADDING
#define PSA_WANT_ALG_CBC_PKCS7
#define PSA_WANT_ALG_CTR
#define PSA_WANT_ALG_CFB
#define PSA_WANT_ALG_OFB
#define PSA_WANT_ALG_ECB_NO_PADDING
#define PSA_WANT_ALG_STREAM_CIPHER

/* AEAD */
#define PSA_WANT_ALG_GCM
#define PSA_WANT_ALG_CCM
#define PSA_WANT_ALG_CHACHA20_POLY1305

/* Asymmetric signature */
#define PSA_WANT_ALG_ECDSA
#define PSA_WANT_ALG_ECDSA_ANY
#define PSA_WANT_ALG_DETERMINISTIC_ECDSA
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN
#define PSA_WANT_ALG_RSA_PSS

/* Asymmetric encryption */
#define PSA_WANT_ALG_RSA_OAEP
#define PSA_WANT_ALG_RSA_PKCS1V15_CRYPT

/* Key agreement */
#define PSA_WANT_ALG_ECDH

/* Key derivation */
#define PSA_WANT_ALG_HKDF
#define PSA_WANT_ALG_HKDF_EXTRACT
#define PSA_WANT_ALG_HKDF_EXPAND
#define PSA_WANT_ALG_TLS12_PRF
#define PSA_WANT_ALG_PBKDF2_HMAC

/* Key types */
#define PSA_WANT_KEY_TYPE_AES
#define PSA_WANT_KEY_TYPE_CHACHA20
#define PSA_WANT_KEY_TYPE_DERIVE
#define PSA_WANT_KEY_TYPE_HMAC
#define PSA_WANT_KEY_TYPE_RAW_DATA
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC
#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY

#define PSA_WANT_KEY_TYPE_ML_DSA
#define PSA_WANT_KEY_TYPE_ML_KEM
/* Curves */
#define PSA_WANT_ECC_SECP_R1_256
#define PSA_WANT_ECC_SECP_R1_384
#define PSA_WANT_ECC_SECP_R1_521

#endif

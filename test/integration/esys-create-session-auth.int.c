/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include "tss2_esys.h"

#include "esys_iutil.h"
#include "test-esys.h"
#define LOGMODULE test
#include "util/log.h"
#include "util/aux_util.h"

#if !defined(TEST_HASH_ALG)
#define TEST_HASH_ALG TPM2_ALG_SHA256
#endif

#if !defined(TEST_ENCRYPT_ALG)
#define TEST_ENCRYPT_ALG TPM2_ALG_AES
#endif

#if !defined(TEST_ENCRYPT_KEYBITS)
#define TEST_ENCRYPT_KEYBITS 128
#endif

#if !defined(TEST_SALTED_SESSION)
#define TEST_SALTED_SESSION 1
#endif

#if !defined(TEST_BOUND_SESSION)
#define TEST_BOUND_SESSION 0
#endif

/** This test is intended to test parameter encryption/decryption,
 *  session management, hmac computation, and session key generation.
 *
 * We start by creating a primary key with a non-empty auth value
 * (Esys_CreatePrimary). The primary key will be used as to salt and/or bind
 * the session (Esys_StartAuthSession). Parameter encryption and decryption will
 * be activated for the session. We then save and reload the session context,
 * and check the session attributes. The session will be used to Create a second
 * key by Eys_Create (with a password). This key will be Loaded to and a third
 * key will be created with the second key as parent key (Esys_Create). For a
 * bound session, this lets us test both authenticating to the bound object,
 * and to other objects, which use different calculations for the session key.
 *
 * This test is parameterized by several preprocessor macros (set using -D):
 * The hash algorithm used is controlled by TEST_HASH_ALG.
 * The type of encryption (including XOR obsfucation) and keysize is controlled
 * by TEST_ENCRYPT_ALG and TEST_ENCRYPT_KEYBITS. The use of salted or bound
 * sessions is controlled by TEST_SALTED_SESSION and TEST_BOUND_SESSION. By
 * default the primary key is RSA 2048, but TEST_ECC_CURVE will use a specified
 * ECC key instead. TEST_LARGE_AUTH will use an auth value for the primary key
 * that is larger than the digest size of SHA256, to test the handling of large
 * auth values.
 *
 * Tested ESYS commands:
 *  - Esys_ContextLoad() (M)
 *  - Esys_ContextSave() (M)
 *  - Esys_Create() (M)
 *  - Esys_CreatePrimary() (M)
 *  - Esys_FlushContext() (M)
 *  - Esys_Load() (M)
 *  - Esys_StartAuthSession() (M)
 *
 * Used compiler defines: TEST_HASH_ALG, TEST_ENCRYPT_ALG, TEST_ENCRYPT_KEYBITS,
 *                        TEST_SALTED_SESSION, TEST_BOUND_SESSION,
 *                        TEST_LARGE_AUTH, TEST_ECC_CURVE
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SKIP
 * @retval EXIT_SUCCESS
 */

int
test_esys_create_session_auth(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    int failure_return = EXIT_FAILURE;

    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR loadedKeyHandle = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE;

    TPM2B_PUBLIC *outPublic = NULL;

    TPM2B_PUBLIC *outPublic2 = NULL;
    TPM2B_PRIVATE *outPrivate2 = NULL;

#if defined(TEST_ECC_CURVE)
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
             },
            .parameters.eccDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes = TPM2_ALG_CFB,
                },
                .scheme.scheme = TPM2_ALG_NULL,
                .curveID = TEST_ECC_CURVE,
                .kdf.scheme = TPM2_ALG_NULL
             },
            .unique.ecc = {
                .x = {.size = 0,.buffer = {}},
                .y = {.size = 0,.buffer = {}},
             },
        },
    };
    LOG_INFO("\nECC key will be created.");
#else
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
            },
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes = TPM2_ALG_CFB},
                .scheme = {
                    .scheme = TPM2_ALG_NULL
                },
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {
                .size = 0,
                .buffer = {},
            },
        },
    };
#endif

    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

#ifdef TEST_LARGE_AUTH
    for (int i = 0; i < 33; i++)
        authValuePrimary.buffer[i] = i;
    authValuePrimary.size = 33;
#endif

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .sensitive.userAuth = authValuePrimary
    };

    TPM2B_DATA outsideInfo = {};
    TPML_PCR_SELECTION creationPCR = {};

    r = Esys_CreatePrimary(esys_context,
                           ESYS_TR_RH_OWNER,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &inSensitivePrimary,
                           &inPublic,
                           &outsideInfo,
                           &creationPCR,
                           &primaryHandle,
                           &outPublic,
                           NULL, NULL, NULL);
    if (r == TPM2_RC_ASYMMETRIC + TPM2_RC_P + TPM2_RC_2 ||
        r == TPM2_RC_CURVE + TPM2_RC_P + TPM2_RC_2) {
        LOG_WARNING("TPM does not support algorithm or ECC curve.");
        failure_return = EXIT_SKIP;
        goto error;
    }
    goto_if_error(r, "Error esys create primary", error);

    TPMT_SYM_DEF symmetric = {
        .algorithm = TEST_ENCRYPT_ALG
    };
    if (TEST_ENCRYPT_ALG == TPM2_ALG_XOR) {
        symmetric.keyBits.exclusiveOr = TEST_HASH_ALG;
    } else {
        symmetric.keyBits.sym = TEST_ENCRYPT_KEYBITS;
        symmetric.mode.sym = TPM2_ALG_CFB;
    }

    TPMA_SESSION sessionAttributes;
    TPMA_SESSION sessionAttributes2;
    sessionAttributes = (TPMA_SESSION_DECRYPT |
                         TPMA_SESSION_ENCRYPT |
                         TPMA_SESSION_CONTINUESESSION);

    r = Esys_StartAuthSession(esys_context,
                              TEST_SALTED_SESSION ? primaryHandle : ESYS_TR_NONE,
                              TEST_BOUND_SESSION ? primaryHandle : ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL,
                              TPM2_SE_HMAC,
                              &symmetric,
                              TEST_HASH_ALG,
                              &session);
    if (r == TPM2_RC_SYMMETRIC + TPM2_RC_P + TPM2_RC_4 ||
        r == TPM2_RC_VALUE + TPM2_RC_P + TPM2_RC_4 ||
        r == TPM2_RC_HASH + TPM2_RC_P + TPM2_RC_5) {
        LOG_WARNING("TPM does not support encryption or hash algorithm.");
        failure_return = EXIT_SKIP;
        goto error;
    }
    goto_if_error(r, "Error Esys_StartAuthSession", error);

    r = Esys_TRSess_SetAttributes(esys_context, session, sessionAttributes,
                                  0xff);
    goto_if_error(r, "Error Esys_TRSess_SetAttributes", error);

    r = Esys_TRSess_GetAttributes(esys_context, session, &sessionAttributes2);
    goto_if_error(r, "Error Esys_TRSess_GetAttributes", error);

    if (sessionAttributes != sessionAttributes2) {
        LOG_ERROR("Session Attributes differ");
        goto error;
    }

    /* Save and load the session and test if the attributes are still OK. */
    TPMS_CONTEXT *contextBlob;
    r = Esys_ContextSave(esys_context, session, &contextBlob);
    goto_if_error(r, "Error during ContextSave", error);

    session = ESYS_TR_NONE;

    r = Esys_ContextLoad(esys_context, contextBlob, &session);
    goto_if_error(r, "Error during ContextLoad", error);

    free(contextBlob);

    r = Esys_TRSess_GetAttributes(esys_context, session, &sessionAttributes2);
    goto_if_error(r, "Error Esys_TRSess_SetAttributes", error);

    if (sessionAttributes != sessionAttributes2) {
        LOG_ERROR("Session Attributes differ");
        goto error;
    }

    TPM2B_AUTH authKey2 = {
        .size = 6,
        .buffer = {6, 7, 8, 9, 10, 11}
    };

    TPM2B_SENSITIVE_CREATE inSensitive2 = {
        .sensitive.userAuth = authKey2
    };

    TPM2B_SENSITIVE_CREATE inSensitive3 = {};

    r = Esys_Create(esys_context,
                    primaryHandle,
                    session, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive2,
                    &inPublic,
                    &outsideInfo,
                    &creationPCR,
                    &outPrivate2,
                    &outPublic2,
                    NULL, NULL, NULL);
    goto_if_error(r, "Error esys create ", error);

    LOG_INFO("\nSecond key created.");

    r = Esys_Load(esys_context,
                  primaryHandle,
                  session, ESYS_TR_NONE, ESYS_TR_NONE,
                  outPrivate2,
                  outPublic2,
                  &loadedKeyHandle);
    goto_if_error(r, "Error esys load ", error);

    LOG_INFO("\nSecond Key loaded.");

    r = Esys_TR_SetAuth(esys_context, loadedKeyHandle, &authKey2);
    goto_if_error(r, "Error esys TR_SetAuth ", error);

    Esys_Free(outPublic2);
    Esys_Free(outPrivate2);

    r = Esys_Create(esys_context,
                    loadedKeyHandle,
                    session, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive3,
                    &inPublic,
                    &outsideInfo,
                    &creationPCR,
                    &outPrivate2,
                    &outPublic2,
                    NULL, NULL, NULL);
    goto_if_error(r, "Error esys second create ", error);

    r = Esys_FlushContext(esys_context, primaryHandle);
    goto_if_error(r, "Error during FlushContext", error);

    r = Esys_FlushContext(esys_context, loadedKeyHandle);
    goto_if_error(r, "Error during FlushContext", error);

    r = Esys_FlushContext(esys_context, session);
    goto_if_error(r, "Flushing context", error);

    Esys_Free(outPublic);
    Esys_Free(outPublic2);
    Esys_Free(outPrivate2);

    return EXIT_SUCCESS;

 error:

    if (session != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, session) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup session failed.");
        }
    }

    if (loadedKeyHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, loadedKeyHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup loadedKeyHandle failed.");
        }
    }

    if (primaryHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, primaryHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup primaryHandle failed.");
        }
    }

    Esys_Free(outPublic);
    Esys_Free(outPublic2);
    Esys_Free(outPrivate2);
    return failure_return;
}

int
test_invoke_esys(ESYS_CONTEXT * esys_context) {
    return test_esys_create_session_auth(esys_context);
}

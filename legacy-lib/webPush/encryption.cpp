#include "webPush.h"

bool WebPush::generateSalt(uint8_t* saltBin, std::string& saltOut, mbedtls_ctr_drbg_context& ctr_drbg) {
    if (mbedtls_ctr_drbg_random(&ctr_drbg, saltBin, 16) != 0) {
        ESP_LOGE(FeatureTag::WebPush, "generateSalt: Failed to generate random salt");
        return false;
    }
    saltOut = base64UrlEncode(saltBin, 16);
    return true;
}

bool WebPush::generateECDHContext(
    const std::vector<uint8_t>& userPubKey,
    mbedtls_ctr_drbg_context& ctr_drbg,
    uint8_t* sharedSecret,
    uint8_t* serverPubKey,
    size_t& pubLen,
    std::string& publicServerKey) {
    bool success = false;

    mbedtls_ecdh_context ecdh;
    mbedtls_ecdh_init(&ecdh);

    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point Q, Qp;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_point_init(&Qp);

    do {
        if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
            ESP_LOGE(FeatureTag::WebPush, "ECDH: Failed to load curve group");
            break;
        }
        if (mbedtls_ecdh_setup(&ecdh, MBEDTLS_ECP_DP_SECP256R1) != 0) {
            ESP_LOGE(FeatureTag::WebPush, "ECDH: Failed to setup context");
            break;
        }
        if (mbedtls_ecdh_gen_public(&grp, &d, &Q, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
            ESP_LOGE(FeatureTag::WebPush, "ECDH: Failed to generate public key");
            break;
        }
        if (mbedtls_ecp_point_read_binary(&grp, &Qp, userPubKey.data(), userPubKey.size()) != 0) {
            ESP_LOGE(FeatureTag::WebPush, "ECDH: Failed to read user public key from binary");
            break;
        }
        // IMPORTANT: Validate userPubKey before proceeding
        if (mbedtls_ecp_check_pubkey(&grp, &Qp) != 0) {
            ESP_LOGE(FeatureTag::WebPush, "ECDH: Provided user public key is invalid or not on the curve");
            break;
        }
        if (mbedtls_ecdh_compute_shared(&grp, &z, &Qp, &d, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
            ESP_LOGE(FeatureTag::WebPush, "ECDH: Failed to compute shared secret");
            break;
        }
        size_t zLen = mbedtls_mpi_size(&z);
        if (zLen == 0 || zLen > 32) {
            ESP_LOGE(FeatureTag::WebPush, "ECDH: Shared secret length invalid (%u), expected 1..32", (unsigned)zLen);
            break;
        }

        memset(sharedSecret, 0, 32);
        if (mbedtls_mpi_write_binary(&z, sharedSecret, 32) != 0) {
            ESP_LOGE(FeatureTag::WebPush, "ECDH: Failed to write shared secret");
            break;
        }
        // Write the ephemeral server public key in uncompressed format (65 bytes)
        if (mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &pubLen, serverPubKey, 65) != 0) {
            ESP_LOGE(FeatureTag::WebPush, "ECDH: Failed to write ephemeral public key to binary");
            break;
        }

        // ESP_LOG_BUFFER_HEX_LEVEL("EphemeralPublicKey", serverPubKey, pubLen, ESP_LOG_INFO);

        // Add a check for pubLen
        if (pubLen != 65 || serverPubKey[0] != 0x04) {
            ESP_LOGE(FeatureTag::WebPush, "ECDH: Ephemeral public key format error. Length: %u, First byte: 0x%02X", (unsigned)pubLen, serverPubKey[0]);
            break;  // Break if the format is not as expected
        }
        // ESP_LOGI(FeatureTag::WebPush, "ECDH: Ephemeral public key len=%u, first byte=0x%02X", (unsigned)pubLen, serverPubKey[0]);
        publicServerKey = base64UrlEncode(serverPubKey, 65);  // Encode the 65-byte key
        success = true;
    } while (false);

    mbedtls_ecdh_free(&ecdh);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&z);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_point_free(&Qp);
    mbedtls_ecp_group_free(&grp);

    return success;
}

// This function implements the specific HKDF logic from the web-push-doc,
// which is a combined Extract-and-Expand.
static bool hkdf(const uint8_t* salt, const uint8_t* ikm, const std::vector<uint8_t>& info, uint8_t* okm, size_t length) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    // Step 1: HKDF-Extract(salt, IKM) -> PRK
    // The web-push.doc's `hkdf` function uses the `ikm` parameter as the PRK directly.
    // However, the calling context in the doc `hkdf(salt, prk, ...)` shows that the
    // `ikm` parameter for *this* function is the PRK from the previous step.
    // The `salt` parameter is the random salt.
    const uint8_t* key_for_expand = salt;  // The random salt is the key for the expand step
    const uint8_t* data_for_expand = ikm;  // The PRK is treated as data

    // Step 2: HKDF-Expand(PRK, info, L)
    std::vector<uint8_t> full_info;
    full_info.insert(full_info.end(), info.begin(), info.end());
    full_info.push_back(0x01);  // Append the required 1-byte counter

    uint8_t output[32];
    if (mbedtls_md_hmac(md, key_for_expand, 16, full_info.data(), full_info.size(), output) != 0) {
        return false;
    }

    memcpy(okm, output, length);
    return true;
}

bool WebPush::deriveKeys(
    const uint8_t* authSecret, size_t authSecretLen, const uint8_t* salt,
    const uint8_t* sharedSecret, uint8_t* cek, uint8_t* nonce,
    const uint8_t* clientPubKey, size_t clientPubKeyLen,
    const uint8_t* serverPubKey, size_t serverPubKeyLen) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) {
        ESP_LOGE(FeatureTag::WebPush, "deriveKeys: SHA-256 not supported");
        return false;
    }

    // Step 1: Compute Master Secret (MS)
    uint8_t prk[32];
    uint8_t ms[32];
    std::vector<uint8_t> authInfo;
    authInfo.reserve(23);  // "Content-Encoding: auth" (22) + 0x00 + 0x01
    const char* authLabel = "Content-Encoding: auth";
    authInfo.insert(authInfo.end(), authLabel, authLabel + strlen(authLabel));
    authInfo.push_back(0x00);
    authInfo.push_back(0x01);
    if (mbedtls_md_hmac(md, authSecret, authSecretLen, sharedSecret, 32, prk) != 0) {
        ESP_LOGE(FeatureTag::WebPush, "deriveKeys: Failed to compute PRK");
        return false;
    }
    if (mbedtls_md_hmac(md, prk, 32, authInfo.data(), authInfo.size(), ms) != 0) {
        ESP_LOGE(FeatureTag::WebPush, "deriveKeys: Failed to compute MS");
        return false;
    }

    // Step 2: Build context
    std::vector<uint8_t> context;
    context.reserve(141);  // "P-256\0" (6) + 2 + 65 + 2 + 65
    const char* contextLabel = "P-256";
    context.insert(context.end(), contextLabel, contextLabel + strlen(contextLabel));
    context.push_back(0x00);
    uint16_t clientLen = static_cast<uint16_t>(clientPubKeyLen);  // 65 for P-256
    context.push_back((clientLen >> 8) & 0xFF);                   // High byte: 0x00
    context.push_back(clientLen & 0xFF);                          // Low byte: 0x41
    context.insert(context.end(), clientPubKey, clientPubKey + clientPubKeyLen);
    uint16_t serverLen = static_cast<uint16_t>(serverPubKeyLen);  // 65 for P-256
    context.push_back((serverLen >> 8) & 0xFF);                   // High byte: 0x00
    context.push_back(serverLen & 0xFF);                          // Low byte: 0x41
    context.insert(context.end(), serverPubKey, serverPubKey + serverPubKeyLen);

    // Step 3: Derive CEK
    std::vector<uint8_t> cekInfo;
    cekInfo.reserve(165);  // "Content-Encoding: aesgcm\0" (25) + context (141) + 0x01
    const char* cekLabel = "Content-Encoding: aesgcm";
    cekInfo.insert(cekInfo.end(), cekLabel, cekLabel + strlen(cekLabel));
    cekInfo.push_back(0x00);
    cekInfo.insert(cekInfo.end(), context.begin(), context.end());
    cekInfo.push_back(0x01);
    uint8_t prk_cek[32];
    uint8_t cek_full[32];
    if (mbedtls_md_hmac(md, salt, 16, ms, 32, prk_cek) != 0) {
        ESP_LOGE(FeatureTag::WebPush, "deriveKeys: Failed to compute PRK_CEK");
        return false;
    }
    if (mbedtls_md_hmac(md, prk_cek, 32, cekInfo.data(), cekInfo.size(), cek_full) != 0) {
        ESP_LOGE(FeatureTag::WebPush, "deriveKeys: Failed to derive CEK");
        return false;
    }
    memcpy(cek, cek_full, 16);  // Take first 16 bytes

    // Step 4: Derive Nonce
    std::vector<uint8_t> nonceInfo;
    nonceInfo.reserve(164);  // "Content-Encoding: nonce\0" (24) + context (141) + 0x01
    const char* nonceLabel = "Content-Encoding: nonce";
    nonceInfo.insert(nonceInfo.end(), nonceLabel, nonceLabel + strlen(nonceLabel));
    nonceInfo.push_back(0x00);
    nonceInfo.insert(nonceInfo.end(), context.begin(), context.end());
    nonceInfo.push_back(0x01);
    uint8_t prk_nonce[32];
    uint8_t nonce_full[32];
    if (mbedtls_md_hmac(md, salt, 16, ms, 32, prk_nonce) != 0) {
        ESP_LOGE(FeatureTag::WebPush, "deriveKeys: Failed to compute PRK_nonce");
        return false;
    }
    if (mbedtls_md_hmac(md, prk_nonce, 32, nonceInfo.data(), nonceInfo.size(), nonce_full) != 0) {
        ESP_LOGE(FeatureTag::WebPush, "deriveKeys: Failed to derive nonce");
        return false;
    }
    memcpy(nonce, nonce_full, 12);  // Take first 12 bytes

    // ESP_LOGI(FeatureTag::WebPush, "deriveKeys: Successfully derived CEK and Nonce");
    return true;
}

bool WebPush::encryptWithAESGCM(const std::string& plaintext, const uint8_t* cek, const uint8_t* nonce, std::vector<uint8_t>& ciphertextOut) {
    if (plaintext.empty()) {
        ESP_LOGE(FeatureTag::WebPush, "encryptWithAESGCM: Plaintext is empty");
        return false;
    }

    std::vector<uint8_t> output(plaintext.size() + 16);  // +16 for GCM tag
    size_t outputLen = 0;
    uint8_t tag[16];

    mbedtls_cipher_context_t cipher;
    mbedtls_cipher_init(&cipher);
    if (mbedtls_cipher_setup(&cipher, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM)) != 0) {
        ESP_LOGE(FeatureTag::WebPush, "encryptWithAESGCM: Failed to setup cipher");
        mbedtls_cipher_free(&cipher);
        return false;
    }
    if (mbedtls_cipher_setkey(&cipher, cek, 128, MBEDTLS_ENCRYPT) != 0) {
        ESP_LOGE(FeatureTag::WebPush, "encryptWithAESGCM: Failed to set key");
        mbedtls_cipher_free(&cipher);
        return false;
    }
    if (mbedtls_cipher_set_iv(&cipher, nonce, 12) != 0) {
        ESP_LOGE(FeatureTag::WebPush, "encryptWithAESGCM: Failed to set IV");
        mbedtls_cipher_free(&cipher);
        return false;
    }
    if (mbedtls_cipher_reset(&cipher) != 0) {
        ESP_LOGE(FeatureTag::WebPush, "encryptWithAESGCM: Failed to reset cipher");
        mbedtls_cipher_free(&cipher);
        return false;
    }
    if (mbedtls_cipher_update_ad(&cipher, nullptr, 0) != 0) {  // No AAD for web push encryption
        ESP_LOGE(FeatureTag::WebPush, "encryptWithAESGCM: Failed to update AD");
        mbedtls_cipher_free(&cipher);
        return false;
    }

    size_t olen = 0;
    if (mbedtls_cipher_update(&cipher, reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(), output.data(), &olen) != 0) {
        ESP_LOGE(FeatureTag::WebPush, "encryptWithAESGCM: Failed to encrypt");
        mbedtls_cipher_free(&cipher);
        return false;
    }
    outputLen = olen;

    if (mbedtls_cipher_finish(&cipher, output.data() + outputLen, &olen) != 0) {
        ESP_LOGE(FeatureTag::WebPush, "encryptWithAESGCM: Failed to finish");
        mbedtls_cipher_free(&cipher);
        return false;
    }
    outputLen += olen;

    if (mbedtls_cipher_write_tag(&cipher, tag, 16) != 0) {
        ESP_LOGE(FeatureTag::WebPush, "encryptWithAESGCM: Failed to write tag");
        mbedtls_cipher_free(&cipher);
        return false;
    }

    // Resize output vector to hold ciphertext + tag
    output.resize(outputLen + 16);
    memcpy(output.data() + outputLen, tag, 16);

    ciphertextOut = std::move(output);  // Move the result to the output parameter
    mbedtls_cipher_free(&cipher);
    return true;
}

std::vector<uint8_t> WebPush::encryptPayload(const std::string& plaintext, const Subscription& sub, std::string& salt, std::string& publicServerKey) {
    uint8_t saltBin[16], sharedSecret[32], serverPubKey[65];
    size_t pubLen = 0;
    uint8_t cek[16], nonce[12];
    std::vector<uint8_t> ciphertext;

    initCrypto();

    std::vector<uint8_t> userPubKey = base64UrlDecode(sub.p256dh);
    // ESP_LOGI(FeatureTag::WebPush, "encryptPayload: Decoded user P256DH (client public key) size: %u", (unsigned)userPubKey.size());
    if (userPubKey.empty()) {
        ESP_LOGE(FeatureTag::WebPush, "encryptPayload: Failed to decode user P256DH (client public key)");
        return ciphertext;
    }
    if (userPubKey.size() != 65 || userPubKey[0] != 0x04) {
        ESP_LOGE(FeatureTag::WebPush, "encryptPayload: User P256DH (client public key) format error. Expected 65 bytes, starts with 0x04. Actual size: %u, first byte: 0x%02X", (unsigned)userPubKey.size(), userPubKey[0]);
        // For debugging, print first few bytes if valid enough
        if (userPubKey.size() >= 5) {
            ESP_LOGE(FeatureTag::WebPush, "User P256DH first 5 bytes: 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X",
                     userPubKey[0], userPubKey[1], userPubKey[2], userPubKey[3], userPubKey[4]);
        }
        return ciphertext;
    }

    std::vector<uint8_t> authSecretBin = base64UrlDecode(sub.auth);
    // ESP_LOGI(FeatureTag::WebPush, "encryptPayload: Decoded Auth secret size: %u", (unsigned)authSecretBin.size());
    if (authSecretBin.empty()) {
        ESP_LOGE(FeatureTag::WebPush, "encryptPayload: Failed to decode auth secret");
        return ciphertext;
    }
    // Added a check for authSecretBin length (should be 16 per RFC 8291 Section 3.2)
    if (authSecretBin.size() != 16) {
        ESP_LOGE(FeatureTag::WebPush, "encryptPayload: Auth secret length is not 16 octets after decoding (%u)", (unsigned)authSecretBin.size());
        return ciphertext;
    }

    if (!generateSalt(saltBin, salt, ctr_drbg)) {
        ESP_LOGE(FeatureTag::WebPush, "encryptPayload: Failed to generate salt");
        return ciphertext;
    }
    // ESP_LOGI(FeatureTag::WebPush, "outEncryptionHeader: salt=%s", salt.c_str());

    if (!generateECDHContext(userPubKey, ctr_drbg, sharedSecret, serverPubKey, pubLen, publicServerKey)) {
        ESP_LOGE(FeatureTag::WebPush, "encryptPayload: Failed to generate ECDH context (ephemeral server key and shared secret)");
        return ciphertext;
    }
    // ESP_LOGI(FeatureTag::WebPush, "outCryptoKeyHeader: dh=%s (Base64Url encoded ephemeral server public key)", publicServerKey.c_str());
    // ESP_LOGI(FeatureTag::WebPush, "outCryptoKeyHeader: dh length (Base64Url encoded): %u", (unsigned)publicServerKey.length());

    if (!deriveKeys(authSecretBin.data(), authSecretBin.size(), saltBin, sharedSecret, cek, nonce, userPubKey.data(), userPubKey.size(), serverPubKey, pubLen)) {
        ESP_LOGE(FeatureTag::WebPush, "encryptPayload: Failed to derive encryption keys");
        return ciphertext;
    }

    std::string paddedPlaintext;
    paddedPlaintext.push_back(0x00);  // P_LEN byte 1 (0 for no padding)
    paddedPlaintext.push_back(0x00);  // P_LEN byte 2 (0 for no padding)
    paddedPlaintext.append(plaintext);
    // paddedPlaintext.push_back(0x02);  // RFC 8188 padding delimiter

    if (!encryptWithAESGCM(paddedPlaintext, cek, nonce, ciphertext)) {
        ESP_LOGE(FeatureTag::WebPush, "encryptPayload: Failed to encrypt with AES-GCM");
        return ciphertext;
    }

    // ESP_LOGI(FeatureTag::WebPush, "encryptPayload: Encryption success, final ciphertext size: %u", (unsigned)ciphertext.size());
    return ciphertext;
}

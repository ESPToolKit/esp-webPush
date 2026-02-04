#include "webPush.h"

#include <cstring>
#include <new>

extern "C" {
#include "esp_log.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
}

namespace {
constexpr const char *kTag = "ESPWebPush";
}  // namespace

struct ESPWebPush::CryptoState {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctrDrbg;
    bool initialized = false;

    CryptoState() {
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctrDrbg);
    }

    ~CryptoState() {
        mbedtls_ctr_drbg_free(&ctrDrbg);
        mbedtls_entropy_free(&entropy);
    }
};

bool ESPWebPush::initCrypto() {
    if (!_crypto) {
        CryptoState *state = new (std::nothrow) CryptoState();
        if (!state) {
            ESP_LOGE(kTag, "initCrypto: out of memory");
            return false;
        }
        _crypto.reset(state);
    }
    if (_crypto->initialized) {
        return true;
    }
    const char *pers = "espwebpush_drbg";
    int ret = mbedtls_ctr_drbg_seed(&(_crypto->ctrDrbg),
                                    mbedtls_entropy_func,
                                    &(_crypto->entropy),
                                    reinterpret_cast<const unsigned char *>(pers),
                                    strlen(pers));
    if (ret != 0) {
        ESP_LOGE(kTag, "initCrypto: failed to seed DRBG: -0x%04x", -ret);
        return false;
    }
    _crypto->initialized = true;
    return true;
}

void ESPWebPush::deinitCrypto() {
    std::lock_guard<std::mutex> guard(_cryptoMutex);
    _crypto.reset();
}

bool ESPWebPush::generateSalt(uint8_t *saltBin, std::string &saltOut) {
    if (!_crypto || !_crypto->initialized) {
        ESP_LOGE(kTag, "generateSalt: crypto not initialized");
        return false;
    }
    if (mbedtls_ctr_drbg_random(&(_crypto->ctrDrbg), saltBin, 16) != 0) {
        ESP_LOGE(kTag, "generateSalt: failed to generate salt");
        return false;
    }
    saltOut = base64UrlEncode(saltBin, 16);
    return !saltOut.empty();
}

bool ESPWebPush::generateECDHContext(const std::vector<uint8_t> &userPubKey,
                                     uint8_t *sharedSecret,
                                     uint8_t *serverPubKey,
                                     size_t &pubLen,
                                     std::string &publicServerKey) {
    if (!_crypto || !_crypto->initialized) {
        ESP_LOGE(kTag, "generateECDHContext: crypto not initialized");
        return false;
    }

    bool success = false;
    mbedtls_ecdh_context ecdh;
    mbedtls_ecdh_init(&ecdh);

    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_mpi z;
    mbedtls_ecp_point Q;
    mbedtls_ecp_point Qp;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_point_init(&Qp);

    do {
        if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
            ESP_LOGE(kTag, "ECDH: failed to load curve");
            break;
        }
        if (mbedtls_ecdh_setup(&ecdh, MBEDTLS_ECP_DP_SECP256R1) != 0) {
            ESP_LOGE(kTag, "ECDH: failed to setup context");
            break;
        }
        if (mbedtls_ecdh_gen_public(&grp, &d, &Q, mbedtls_ctr_drbg_random, &(_crypto->ctrDrbg)) != 0) {
            ESP_LOGE(kTag, "ECDH: failed to generate public key");
            break;
        }
        if (mbedtls_ecp_point_read_binary(&grp, &Qp, userPubKey.data(), userPubKey.size()) != 0) {
            ESP_LOGE(kTag, "ECDH: failed to read user public key");
            break;
        }
        if (mbedtls_ecp_check_pubkey(&grp, &Qp) != 0) {
            ESP_LOGE(kTag, "ECDH: user public key invalid");
            break;
        }
        if (mbedtls_ecdh_compute_shared(&grp, &z, &Qp, &d, mbedtls_ctr_drbg_random, &(_crypto->ctrDrbg)) != 0) {
            ESP_LOGE(kTag, "ECDH: failed to compute shared secret");
            break;
        }
        size_t zLen = mbedtls_mpi_size(&z);
        if (zLen == 0 || zLen > 32) {
            ESP_LOGE(kTag, "ECDH: shared secret length invalid (%u)", static_cast<unsigned>(zLen));
            break;
        }
        memset(sharedSecret, 0, 32);
        if (mbedtls_mpi_write_binary(&z, sharedSecret, 32) != 0) {
            ESP_LOGE(kTag, "ECDH: failed to write shared secret");
            break;
        }
        if (mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &pubLen, serverPubKey, 65) != 0) {
            ESP_LOGE(kTag, "ECDH: failed to write ephemeral public key");
            break;
        }
        if (pubLen != 65 || serverPubKey[0] != 0x04) {
            ESP_LOGE(kTag, "ECDH: invalid ephemeral public key");
            break;
        }
        publicServerKey = base64UrlEncode(serverPubKey, 65);
        success = !publicServerKey.empty();
    } while (false);

    mbedtls_ecdh_free(&ecdh);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&z);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_point_free(&Qp);
    mbedtls_ecp_group_free(&grp);

    return success;
}

bool ESPWebPush::deriveKeys(const uint8_t *authSecret,
                            size_t authSecretLen,
                            const uint8_t *salt,
                            const uint8_t *sharedSecret,
                            uint8_t *cek,
                            uint8_t *nonce,
                            const uint8_t *clientPubKey,
                            size_t clientPubKeyLen,
                            const uint8_t *serverPubKey,
                            size_t serverPubKeyLen) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) {
        ESP_LOGE(kTag, "deriveKeys: SHA-256 not supported");
        return false;
    }

    uint8_t prk[32];
    uint8_t ms[32];
    std::vector<uint8_t> authInfo;
    authInfo.reserve(23);
    const char *authLabel = "Content-Encoding: auth";
    authInfo.insert(authInfo.end(), authLabel, authLabel + strlen(authLabel));
    authInfo.push_back(0x00);
    authInfo.push_back(0x01);

    if (mbedtls_md_hmac(md, authSecret, authSecretLen, sharedSecret, 32, prk) != 0) {
        ESP_LOGE(kTag, "deriveKeys: failed to compute PRK");
        return false;
    }
    if (mbedtls_md_hmac(md, prk, 32, authInfo.data(), authInfo.size(), ms) != 0) {
        ESP_LOGE(kTag, "deriveKeys: failed to compute MS");
        return false;
    }

    std::vector<uint8_t> context;
    context.reserve(141);
    const char *contextLabel = "P-256";
    context.insert(context.end(), contextLabel, contextLabel + strlen(contextLabel));
    context.push_back(0x00);
    uint16_t clientLen = static_cast<uint16_t>(clientPubKeyLen);
    context.push_back((clientLen >> 8) & 0xFF);
    context.push_back(clientLen & 0xFF);
    context.insert(context.end(), clientPubKey, clientPubKey + clientPubKeyLen);
    uint16_t serverLen = static_cast<uint16_t>(serverPubKeyLen);
    context.push_back((serverLen >> 8) & 0xFF);
    context.push_back(serverLen & 0xFF);
    context.insert(context.end(), serverPubKey, serverPubKey + serverPubKeyLen);

    std::vector<uint8_t> cekInfo;
    cekInfo.reserve(165);
    const char *cekLabel = "Content-Encoding: aesgcm";
    cekInfo.insert(cekInfo.end(), cekLabel, cekLabel + strlen(cekLabel));
    cekInfo.push_back(0x00);
    cekInfo.insert(cekInfo.end(), context.begin(), context.end());
    cekInfo.push_back(0x01);
    uint8_t prkCek[32];
    uint8_t cekFull[32];
    if (mbedtls_md_hmac(md, salt, 16, ms, 32, prkCek) != 0) {
        ESP_LOGE(kTag, "deriveKeys: failed to compute PRK_CEK");
        return false;
    }
    if (mbedtls_md_hmac(md, prkCek, 32, cekInfo.data(), cekInfo.size(), cekFull) != 0) {
        ESP_LOGE(kTag, "deriveKeys: failed to derive CEK");
        return false;
    }
    memcpy(cek, cekFull, 16);

    std::vector<uint8_t> nonceInfo;
    nonceInfo.reserve(164);
    const char *nonceLabel = "Content-Encoding: nonce";
    nonceInfo.insert(nonceInfo.end(), nonceLabel, nonceLabel + strlen(nonceLabel));
    nonceInfo.push_back(0x00);
    nonceInfo.insert(nonceInfo.end(), context.begin(), context.end());
    nonceInfo.push_back(0x01);
    uint8_t prkNonce[32];
    uint8_t nonceFull[32];
    if (mbedtls_md_hmac(md, salt, 16, ms, 32, prkNonce) != 0) {
        ESP_LOGE(kTag, "deriveKeys: failed to compute PRK_nonce");
        return false;
    }
    if (mbedtls_md_hmac(md, prkNonce, 32, nonceInfo.data(), nonceInfo.size(), nonceFull) != 0) {
        ESP_LOGE(kTag, "deriveKeys: failed to derive nonce");
        return false;
    }
    memcpy(nonce, nonceFull, 12);

    return true;
}

bool ESPWebPush::encryptWithAESGCM(const std::string &plaintext,
                                   const uint8_t *cek,
                                   const uint8_t *nonce,
                                   std::vector<uint8_t> &ciphertextOut) {
    if (plaintext.empty()) {
        ESP_LOGE(kTag, "encryptWithAESGCM: plaintext empty");
        return false;
    }

    std::vector<uint8_t> output(plaintext.size() + 16);
    size_t outputLen = 0;
    uint8_t tag[16];

    mbedtls_cipher_context_t cipher;
    mbedtls_cipher_init(&cipher);
    if (mbedtls_cipher_setup(&cipher, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM)) != 0) {
        ESP_LOGE(kTag, "encryptWithAESGCM: cipher setup failed");
        mbedtls_cipher_free(&cipher);
        return false;
    }
    if (mbedtls_cipher_setkey(&cipher, cek, 128, MBEDTLS_ENCRYPT) != 0) {
        ESP_LOGE(kTag, "encryptWithAESGCM: set key failed");
        mbedtls_cipher_free(&cipher);
        return false;
    }
    if (mbedtls_cipher_set_iv(&cipher, nonce, 12) != 0) {
        ESP_LOGE(kTag, "encryptWithAESGCM: set IV failed");
        mbedtls_cipher_free(&cipher);
        return false;
    }
    if (mbedtls_cipher_reset(&cipher) != 0) {
        ESP_LOGE(kTag, "encryptWithAESGCM: reset failed");
        mbedtls_cipher_free(&cipher);
        return false;
    }
    if (mbedtls_cipher_update_ad(&cipher, nullptr, 0) != 0) {
        ESP_LOGE(kTag, "encryptWithAESGCM: update AD failed");
        mbedtls_cipher_free(&cipher);
        return false;
    }

    size_t olen = 0;
    if (mbedtls_cipher_update(&cipher,
                              reinterpret_cast<const uint8_t *>(plaintext.data()),
                              plaintext.size(),
                              output.data(),
                              &olen) != 0) {
        ESP_LOGE(kTag, "encryptWithAESGCM: encrypt failed");
        mbedtls_cipher_free(&cipher);
        return false;
    }
    outputLen = olen;

    if (mbedtls_cipher_finish(&cipher, output.data() + outputLen, &olen) != 0) {
        ESP_LOGE(kTag, "encryptWithAESGCM: finish failed");
        mbedtls_cipher_free(&cipher);
        return false;
    }
    outputLen += olen;

    if (mbedtls_cipher_write_tag(&cipher, tag, 16) != 0) {
        ESP_LOGE(kTag, "encryptWithAESGCM: write tag failed");
        mbedtls_cipher_free(&cipher);
        return false;
    }

    output.resize(outputLen + 16);
    memcpy(output.data() + outputLen, tag, 16);

    ciphertextOut = std::move(output);
    mbedtls_cipher_free(&cipher);
    return true;
}

std::vector<uint8_t> ESPWebPush::encryptPayload(const std::string &plaintext,
                                                const Subscription &sub,
                                                std::string &salt,
                                                std::string &publicServerKey) {
    std::lock_guard<std::mutex> guard(_cryptoMutex);
    if (!initCrypto()) {
        return {};
    }

    uint8_t saltBin[16];
    uint8_t sharedSecret[32];
    uint8_t serverPubKey[65];
    size_t pubLen = 0;
    uint8_t cek[16];
    uint8_t nonce[12];

    std::vector<uint8_t> userPubKey;
    if (!base64UrlDecode(sub.p256dh, userPubKey) || userPubKey.empty()) {
        ESP_LOGE(kTag, "encryptPayload: failed to decode client public key");
        return {};
    }
    if (userPubKey.size() != 65 || userPubKey[0] != 0x04) {
        ESP_LOGE(kTag, "encryptPayload: client public key invalid");
        return {};
    }

    std::vector<uint8_t> authSecretBin;
    if (!base64UrlDecode(sub.auth, authSecretBin) || authSecretBin.empty()) {
        ESP_LOGE(kTag, "encryptPayload: failed to decode auth secret");
        return {};
    }
    if (authSecretBin.size() != 16) {
        ESP_LOGE(kTag, "encryptPayload: auth secret length invalid (%u)", static_cast<unsigned>(authSecretBin.size()));
        return {};
    }

    if (!generateSalt(saltBin, salt)) {
        ESP_LOGE(kTag, "encryptPayload: failed to generate salt");
        return {};
    }

    if (!generateECDHContext(userPubKey, sharedSecret, serverPubKey, pubLen, publicServerKey)) {
        ESP_LOGE(kTag, "encryptPayload: failed to generate ECDH context");
        return {};
    }

    if (!deriveKeys(authSecretBin.data(), authSecretBin.size(),
                    saltBin, sharedSecret, cek, nonce,
                    userPubKey.data(), userPubKey.size(),
                    serverPubKey, pubLen)) {
        ESP_LOGE(kTag, "encryptPayload: failed to derive keys");
        return {};
    }

    std::string paddedPlaintext;
    paddedPlaintext.push_back(0x00);
    paddedPlaintext.push_back(0x00);
    paddedPlaintext.append(plaintext);

    std::vector<uint8_t> ciphertext;
    if (!encryptWithAESGCM(paddedPlaintext, cek, nonce, ciphertext)) {
        ESP_LOGE(kTag, "encryptPayload: AES-GCM failed");
        return {};
    }

    return ciphertext;
}

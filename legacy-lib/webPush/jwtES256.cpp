// jwt_es256.cpp (fixed ES256 raw signature format)
#include "jwtES256.h"

#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#include <algorithm>
#include <ctime>
#include <string>

std::string JWT_ES256::base64UrlEncode(const std::vector<uint8_t>& input) {
    size_t olen = 0;
    std::vector<uint8_t> out((input.size() * 4) / 3 + 4);
    int ret = mbedtls_base64_encode(out.data(), out.size(), &olen, input.data(), input.size());
    if (ret != 0) {
        return "";
    }
    std::string encoded((char*)out.data(), olen);
    std::replace(encoded.begin(), encoded.end(), '+', '-');
    std::replace(encoded.begin(), encoded.end(), '/', '_');
    encoded.erase(std::remove(encoded.begin(), encoded.end(), '='), encoded.end());
    return encoded;
}

std::string JWT_ES256::base64UrlEncode(const std::string& input) {
    return base64UrlEncode(std::vector<uint8_t>(input.begin(), input.end()));
}

std::string JWT_ES256::base64Normalize(const std::string& urlEncoded) {
    std::string out = urlEncoded;
    std::replace(out.begin(), out.end(), '-', '+');
    std::replace(out.begin(), out.end(), '_', '/');
    while (out.size() % 4 != 0) {
        out += '=';
    }
    return out;
}

std::string JWT_ES256::sign(const std::string& aud, const std::string& sub,
                            const std::string& privateKeyBase64, unsigned long expSecs) {
    std::string header = R"({"alg":"ES256","typ":"JWT"})";
    unsigned long now = static_cast<unsigned long>(std::time(nullptr));
    unsigned long exp = now + expSecs;

    char payloadBuf[256];
    snprintf(payloadBuf, sizeof(payloadBuf),
             R"({"aud":"%s","exp":%lu,"sub":"%s"})",
             aud.c_str(), exp, sub.c_str());

    std::string encodedHeader = base64UrlEncode(header);
    std::string encodedPayload = base64UrlEncode(payloadBuf);
    std::string message = encodedHeader + "." + encodedPayload;

    std::string normalizedKey = base64Normalize(privateKeyBase64);
    normalizedKey.erase(
        std::remove_if(normalizedKey.begin(), normalizedKey.end(), ::isspace),
        normalizedKey.end());

    /*ESP_LOGI(ES256_TAG, "Normalized private key (length=%d): %s",
             (int)normalizedKey.length(), normalizedKey.c_str());*/

    std::vector<uint8_t> privBytes(32);
    size_t olen = 0;
    int res = mbedtls_base64_decode(privBytes.data(), privBytes.size(), &olen,
                                    reinterpret_cast<const uint8_t*>(normalizedKey.data()),
                                    normalizedKey.size());

    //ESP_LOGI(ES256_TAG, "Base64 decode result: %d, length: %d", res, (int)olen);

    if (res != 0 || olen != 32) {
        ESP_LOGE(ES256_TAG, "Failed to decode private key");
        return "";
    }

    mbedtls_mpi d, r, s;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_ctr_drbg_context ctrDrbg;
    mbedtls_entropy_context entropy;

    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_ctr_drbg_init(&ctrDrbg);
    mbedtls_entropy_init(&entropy);

    const char* pers = "jwt_es256";

    bool success = false;
    std::string signedToken;

    do {
        if (mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy,
                                  reinterpret_cast<const uint8_t*>(pers), strlen(pers)) != 0) {
            ESP_LOGE(ES256_TAG, "Failed to seed CTR_DRBG");
            break;
        }

        if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
            ESP_LOGE(ES256_TAG, "Failed to load SECP256R1 group");
            break;
        }

        //ESP_LOGI(ES256_TAG, "Free heap: %u", (unsigned)esp_get_free_heap_size());

        if (mbedtls_mpi_read_binary(&d, privBytes.data(), 32) != 0) {
            ESP_LOGE(ES256_TAG, "Failed to load private key into MPI");
            break;
        }

        size_t dlen = 0;
        char dHex[100] = {};
        if (mbedtls_mpi_write_string(&d, 16, dHex, sizeof(dHex), &dlen) != 0) {
            ESP_LOGW(ES256_TAG, "Failed to format private key for log");
        }

        //ESP_LOGI(ES256_TAG, "Curve N size: %u", (unsigned)mbedtls_mpi_size(&grp.N));

        if (mbedtls_ecp_check_privkey(&grp, &d) != 0) {
            ESP_LOGE(ES256_TAG, "Private key is out of range for SECP256R1");
            break;
        }

        int ecpMulRet = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G,
                                        mbedtls_ctr_drbg_random, &ctrDrbg);
        if (ecpMulRet != 0) {
            ESP_LOGE(ES256_TAG, "Failed to generate public key (ecp_mul). Ret: %d", ecpMulRet);
            break;
        }

        if (mbedtls_ecp_check_pubkey(&grp, &Q) != 0) {
            ESP_LOGE(ES256_TAG, "Generated public key Q is invalid");
            break;
        }

        // Hash the message using SHA256
        uint8_t hash[32];
        mbedtls_md_context_t mdctx;
        mbedtls_md_init(&mdctx);
        const mbedtls_md_info_t* mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        mbedtls_md_setup(&mdctx, mdinfo, 0);
        mbedtls_md_starts(&mdctx);
        mbedtls_md_update(&mdctx, reinterpret_cast<const uint8_t*>(message.data()), message.size());
        mbedtls_md_finish(&mdctx, hash);
        mbedtls_md_free(&mdctx);

        if (mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d, hash, sizeof(hash),
                                       MBEDTLS_MD_SHA256, mbedtls_ctr_drbg_random, &ctrDrbg) != 0) {
            ESP_LOGE(ES256_TAG, "Signing failed");
            break;
        }

        uint8_t sig[64] = {};
        mbedtls_mpi_write_binary(&r, sig, 32);
        mbedtls_mpi_write_binary(&s, sig + 32, 32);

        std::string encodedSig = base64UrlEncode(std::vector<uint8_t>(sig, sig + sizeof(sig)));
        signedToken = message + "." + encodedSig;
        success = true;
        break;

    } while (false);

    // Cleanup
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ctr_drbg_free(&ctrDrbg);
    mbedtls_entropy_free(&entropy);

    return success ? signedToken : "";
}

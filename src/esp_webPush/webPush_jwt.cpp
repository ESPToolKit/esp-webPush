#include "webPush.h"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <cstring>

extern "C" {
#include "esp_log.h"
#include "mbedtls/base64.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
}

namespace {
constexpr const char *kTag = "ESPWebPush";

std::string base64Normalize(const std::string &urlEncoded) {
    std::string out = urlEncoded;
    std::replace(out.begin(), out.end(), '-', '+');
    std::replace(out.begin(), out.end(), '_', '/');
    while (out.size() % 4 != 0) {
        out.push_back('=');
    }
    return out;
}
}  // namespace

std::string ESPWebPush::generateVapidJWT(const std::string &aud,
                                         const std::string &sub,
                                         const std::string &vapidPrivateKeyBase64) {
    std::string header = R"({"alg":"ES256","typ":"JWT"})";
    unsigned long now = static_cast<unsigned long>(std::time(nullptr));
    unsigned long exp = now + 12 * 60 * 60;

    char payloadBuf[256];
    snprintf(payloadBuf, sizeof(payloadBuf),
             R"({"aud":"%s","exp":%lu,"sub":"%s"})",
             aud.c_str(), exp, sub.c_str());

    std::string encodedHeader = base64UrlEncode(header);
    std::string encodedPayload = base64UrlEncode(payloadBuf);
    if (encodedHeader.empty() || encodedPayload.empty()) {
        return "";
    }

    std::string message = encodedHeader + "." + encodedPayload;

    std::string normalizedKey = base64Normalize(vapidPrivateKeyBase64);
    normalizedKey.erase(
        std::remove_if(normalizedKey.begin(), normalizedKey.end(), ::isspace),
        normalizedKey.end());

    std::vector<uint8_t> privBytes(32);
    size_t olen = 0;
    int res = mbedtls_base64_decode(privBytes.data(), privBytes.size(), &olen,
                                    reinterpret_cast<const unsigned char *>(normalizedKey.data()),
                                    normalizedKey.size());
    if (res != 0 || olen != 32) {
        ESP_LOGE(kTag, "generateVapidJWT: failed to decode private key");
        return "";
    }

    mbedtls_mpi d;
    mbedtls_mpi r;
    mbedtls_mpi s;
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

    std::string signedToken;
    bool success = false;

    do {
        const char *pers = "jwt_es256";
        if (mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy,
                                  reinterpret_cast<const unsigned char *>(pers),
                                  strlen(pers)) != 0) {
            ESP_LOGE(kTag, "generateVapidJWT: failed to seed DRBG");
            break;
        }

        if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
            ESP_LOGE(kTag, "generateVapidJWT: failed to load curve");
            break;
        }

        if (mbedtls_mpi_read_binary(&d, privBytes.data(), 32) != 0) {
            ESP_LOGE(kTag, "generateVapidJWT: failed to load private key");
            break;
        }

        if (mbedtls_ecp_check_privkey(&grp, &d) != 0) {
            ESP_LOGE(kTag, "generateVapidJWT: private key invalid");
            break;
        }

        if (mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, mbedtls_ctr_drbg_random, &ctrDrbg) != 0) {
            ESP_LOGE(kTag, "generateVapidJWT: failed to derive public key");
            break;
        }

        if (mbedtls_ecp_check_pubkey(&grp, &Q) != 0) {
            ESP_LOGE(kTag, "generateVapidJWT: derived public key invalid");
            break;
        }

        uint8_t hash[32];
        mbedtls_md_context_t mdctx;
        mbedtls_md_init(&mdctx);
        const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if (!mdinfo || mbedtls_md_setup(&mdctx, mdinfo, 0) != 0) {
            ESP_LOGE(kTag, "generateVapidJWT: md setup failed");
            mbedtls_md_free(&mdctx);
            break;
        }
        if (mbedtls_md_starts(&mdctx) != 0 ||
            mbedtls_md_update(&mdctx, reinterpret_cast<const uint8_t *>(message.data()), message.size()) != 0 ||
            mbedtls_md_finish(&mdctx, hash) != 0) {
            ESP_LOGE(kTag, "generateVapidJWT: sha256 failed");
            mbedtls_md_free(&mdctx);
            break;
        }
        mbedtls_md_free(&mdctx);

        if (mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d, hash, sizeof(hash),
                                       MBEDTLS_MD_SHA256, mbedtls_ctr_drbg_random, &ctrDrbg) != 0) {
            ESP_LOGE(kTag, "generateVapidJWT: signing failed");
            break;
        }

        uint8_t sig[64] = {};
        mbedtls_mpi_write_binary(&r, sig, 32);
        mbedtls_mpi_write_binary(&s, sig + 32, 32);

        std::string encodedSig = base64UrlEncode(sig, sizeof(sig));
        if (encodedSig.empty()) {
            break;
        }

        signedToken = message + "." + encodedSig;
        success = true;
    } while (false);

    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ctr_drbg_free(&ctrDrbg);
    mbedtls_entropy_free(&entropy);

    return success ? signedToken : "";
}

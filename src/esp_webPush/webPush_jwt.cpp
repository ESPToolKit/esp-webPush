#include "webPush.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <ctime>

extern "C" {
#include "esp_log.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
}

namespace {
constexpr const char *kTag = "ESPWebPush";
constexpr time_t kJwtLifetimeSeconds = 12 * 60 * 60;
constexpr time_t kJwtRefreshMarginSeconds = 5 * 60;
} // namespace

std::string ESPWebPush::generateVapidJWT(const std::string &aud, time_t &expOut) {
	std::vector<uint8_t> privateKey;
	if (!decodeP256PrivateKey(_vapidConfig.privateKeyBase64, privateKey)) {
		ESP_LOGE(kTag, "generateVapidJWT: failed to decode private key");
		return "";
	}

	const time_t now = std::time(nullptr);
	expOut = now + kJwtLifetimeSeconds;

	const std::string header = R"({"alg":"ES256","typ":"JWT"})";
	const std::string payload = std::string(R"({"aud":")") + aud + R"(","exp":)" +
	                            std::to_string(static_cast<unsigned long>(expOut)) +
	                            R"(,"sub":")" + _vapidConfig.subject + R"("})";

	const std::string encodedHeader = base64UrlEncode(header);
	const std::string encodedPayload = base64UrlEncode(payload);
	if (encodedHeader.empty() || encodedPayload.empty()) {
		return "";
	}

	const std::string message = encodedHeader + "." + encodedPayload;

	mbedtls_mpi d;
	mbedtls_mpi r;
	mbedtls_mpi s;
	mbedtls_ecp_group group;
	mbedtls_ctr_drbg_context ctrDrbg;
	mbedtls_entropy_context entropy;

	mbedtls_mpi_init(&d);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	mbedtls_ecp_group_init(&group);
	mbedtls_ctr_drbg_init(&ctrDrbg);
	mbedtls_entropy_init(&entropy);

	std::string signedToken;
	bool success = false;

	do {
		const char *pers = "jwt_es256";
		if (mbedtls_ctr_drbg_seed(
		        &ctrDrbg,
		        mbedtls_entropy_func,
		        &entropy,
		        reinterpret_cast<const unsigned char *>(pers),
		        strlen(pers)
		    ) != 0) {
			ESP_LOGE(kTag, "generateVapidJWT: failed to seed DRBG");
			break;
		}
		if (mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) != 0) {
			break;
		}
		if (mbedtls_mpi_read_binary(&d, privateKey.data(), privateKey.size()) != 0) {
			break;
		}
		if (mbedtls_ecp_check_privkey(&group, &d) != 0) {
			break;
		}

		uint8_t hash[32];
		mbedtls_md_context_t mdctx;
		mbedtls_md_init(&mdctx);
		const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
		if (!mdinfo || mbedtls_md_setup(&mdctx, mdinfo, 0) != 0) {
			mbedtls_md_free(&mdctx);
			break;
		}
		if (mbedtls_md_starts(&mdctx) != 0 ||
		    mbedtls_md_update(
		        &mdctx,
		        reinterpret_cast<const unsigned char *>(message.data()),
		        message.size()
		    ) != 0 ||
		    mbedtls_md_finish(&mdctx, hash) != 0) {
			mbedtls_md_free(&mdctx);
			break;
		}
		mbedtls_md_free(&mdctx);

		if (mbedtls_ecdsa_sign_det_ext(
		        &group,
		        &r,
		        &s,
		        &d,
		        hash,
		        sizeof(hash),
		        MBEDTLS_MD_SHA256,
		        mbedtls_ctr_drbg_random,
		        &ctrDrbg
		    ) != 0) {
			break;
		}

		std::array<uint8_t, 64> sig{};
		if (mbedtls_mpi_write_binary(&r, sig.data(), 32) != 0 ||
		    mbedtls_mpi_write_binary(&s, sig.data() + 32, 32) != 0) {
			break;
		}

		const std::string encodedSig = base64UrlEncode(sig.data(), sig.size());
		if (encodedSig.empty()) {
			break;
		}

		signedToken = message + "." + encodedSig;
		success = true;
	} while (false);

	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctrDrbg);
	mbedtls_ecp_group_free(&group);
	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&d);

	return success ? signedToken : "";
}

std::string ESPWebPush::jwtForAudience(const std::string &aud) {
	if (aud.empty()) {
		return "";
	}

	const time_t now = std::time(nullptr);
	{
		std::lock_guard<std::mutex> guard(_jwtCacheMutex);
		for (JwtCacheEntry &entry : _jwtCache) {
			if (entry.aud == aud && !entry.token.empty() &&
			    entry.exp > (now + kJwtRefreshMarginSeconds)) {
				entry.lastUsedTick = xTaskGetTickCount();
				return entry.token;
			}
		}
	}

	time_t exp = 0;
	const std::string jwt = generateVapidJWT(aud, exp);
	if (jwt.empty()) {
		return "";
	}

	std::lock_guard<std::mutex> guard(_jwtCacheMutex);
	JwtCacheEntry *target = nullptr;
	for (JwtCacheEntry &entry : _jwtCache) {
		if (entry.aud == aud) {
			target = &entry;
			break;
		}
		if (!target && entry.token.empty()) {
			target = &entry;
		}
	}
	if (!target) {
		target = &_jwtCache[0];
		for (JwtCacheEntry &entry : _jwtCache) {
			if (entry.lastUsedTick < target->lastUsedTick) {
				target = &entry;
			}
		}
	}

	target->aud = aud;
	target->token = jwt;
	target->exp = exp;
	target->lastUsedTick = xTaskGetTickCount();
	return target->token;
}

#include "webPush.h"

#include <cstring>
#include <new>

extern "C" {
#include "esp_log.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
}

namespace {
constexpr const char *kTag = "ESPWebPush";

void appendUint32(std::vector<uint8_t> &buffer, uint32_t value) {
	buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
	buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
	buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
	buffer.push_back(static_cast<uint8_t>(value & 0xFF));
}
} // namespace

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

void ESPWebPush::CryptoDeleter::operator()(CryptoState *state) const {
	delete state;
}

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
	int ret = mbedtls_ctr_drbg_seed(
	    &(_crypto->ctrDrbg),
	    mbedtls_entropy_func,
	    &(_crypto->entropy),
	    reinterpret_cast<const unsigned char *>(pers),
	    strlen(pers)
	);
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

bool ESPWebPush::generateSalt(uint8_t *saltBin) {
	if (!_crypto || !_crypto->initialized) {
		ESP_LOGE(kTag, "generateSalt: crypto not initialized");
		return false;
	}
	if (mbedtls_ctr_drbg_random(&(_crypto->ctrDrbg), saltBin, 16) != 0) {
		ESP_LOGE(kTag, "generateSalt: failed to generate salt");
		return false;
	}
	return true;
}

bool ESPWebPush::decodeP256PublicKey(const std::string &keyBase64, std::vector<uint8_t> &output)
    const {
	if (!base64UrlDecode(keyBase64, output) || output.size() != 65 || output[0] != 0x04) {
		output.clear();
		return false;
	}
	return true;
}

bool ESPWebPush::decodeP256PrivateKey(const std::string &keyBase64, std::vector<uint8_t> &output)
    const {
	if (!base64UrlDecode(keyBase64, output) || output.size() != 32) {
		output.clear();
		return false;
	}
	return true;
}

bool ESPWebPush::deriveP256PublicKey(
    const std::vector<uint8_t> &privateKey, std::vector<uint8_t> &publicKeyOut
) const {
	if (privateKey.size() != 32) {
		return false;
	}

	bool success = false;
	mbedtls_ecp_group group;
	mbedtls_mpi d;
	mbedtls_ecp_point q;

	mbedtls_ecp_group_init(&group);
	mbedtls_mpi_init(&d);
	mbedtls_ecp_point_init(&q);

	do {
		if (mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) != 0) {
			break;
		}
		if (mbedtls_mpi_read_binary(&d, privateKey.data(), privateKey.size()) != 0) {
			break;
		}
		if (mbedtls_ecp_check_privkey(&group, &d) != 0) {
			break;
		}
		if (mbedtls_ecp_mul(&group, &q, &d, &group.G, nullptr, nullptr) != 0) {
			break;
		}
		if (mbedtls_ecp_check_pubkey(&group, &q) != 0) {
			break;
		}

		publicKeyOut.assign(65, 0);
		size_t actualLen = 0;
		if (mbedtls_ecp_point_write_binary(
		        &group,
		        &q,
		        MBEDTLS_ECP_PF_UNCOMPRESSED,
		        &actualLen,
		        publicKeyOut.data(),
		        publicKeyOut.size()
		    ) != 0) {
			publicKeyOut.clear();
			break;
		}
		if (actualLen != 65 || publicKeyOut[0] != 0x04) {
			publicKeyOut.clear();
			break;
		}
		success = true;
	} while (false);

	mbedtls_ecp_point_free(&q);
	mbedtls_mpi_free(&d);
	mbedtls_ecp_group_free(&group);

	return success;
}

bool ESPWebPush::generateECDHContext(
    const std::vector<uint8_t> &privateKey, std::vector<uint8_t> &publicKeyOut
) {
	if (privateKey.size() != 32) {
		ESP_LOGE(kTag, "generateECDHContext: private key length invalid");
		return false;
	}
	return deriveP256PublicKey(privateKey, publicKeyOut);
}

bool ESPWebPush::deriveSharedSecret(
    const std::vector<uint8_t> &peerPublicKey,
    const std::vector<uint8_t> &privateKey,
    uint8_t *sharedSecret
) {
	if (peerPublicKey.size() != 65 || peerPublicKey[0] != 0x04 || privateKey.size() != 32 ||
	    sharedSecret == nullptr) {
		return false;
	}

	bool success = false;
	mbedtls_ecp_group group;
	mbedtls_mpi d;
	mbedtls_mpi z;
	mbedtls_ecp_point q;

	mbedtls_ecp_group_init(&group);
	mbedtls_mpi_init(&d);
	mbedtls_mpi_init(&z);
	mbedtls_ecp_point_init(&q);

	do {
		if (mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) != 0) {
			break;
		}
		if (mbedtls_mpi_read_binary(&d, privateKey.data(), privateKey.size()) != 0) {
			break;
		}
		if (mbedtls_ecp_check_privkey(&group, &d) != 0) {
			break;
		}
		if (mbedtls_ecp_point_read_binary(&group, &q, peerPublicKey.data(), peerPublicKey.size()) !=
		    0) {
			break;
		}
		if (mbedtls_ecp_check_pubkey(&group, &q) != 0) {
			break;
		}
		if (mbedtls_ecdh_compute_shared(
		        &group,
		        &z,
		        &q,
		        &d,
		        mbedtls_ctr_drbg_random,
		        _crypto ? &(_crypto->ctrDrbg) : nullptr
		    ) != 0) {
			break;
		}
		memset(sharedSecret, 0, 32);
		if (mbedtls_mpi_write_binary(&z, sharedSecret, 32) != 0) {
			break;
		}
		success = true;
	} while (false);

	mbedtls_ecp_point_free(&q);
	mbedtls_mpi_free(&z);
	mbedtls_mpi_free(&d);
	mbedtls_ecp_group_free(&group);

	return success;
}

bool ESPWebPush::deriveInputKeyingMaterial(
    const uint8_t *authSecret,
    size_t authSecretLen,
    const uint8_t *sharedSecret,
    const uint8_t *clientPubKey,
    size_t clientPubKeyLen,
    const uint8_t *serverPubKey,
    size_t serverPubKeyLen,
    uint8_t *ikm
) const {
	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!md || !authSecret || !sharedSecret || !clientPubKey || !serverPubKey || !ikm) {
		return false;
	}

	uint8_t prkKey[32];
	std::vector<uint8_t> keyInfo;
	const char *label = "WebPush: info";
	keyInfo.reserve(strlen(label) + 1 + clientPubKeyLen + serverPubKeyLen + 1);
	keyInfo.insert(keyInfo.end(), label, label + strlen(label));
	keyInfo.push_back(0x00);
	keyInfo.insert(keyInfo.end(), clientPubKey, clientPubKey + clientPubKeyLen);
	keyInfo.insert(keyInfo.end(), serverPubKey, serverPubKey + serverPubKeyLen);
	keyInfo.push_back(0x01);

	if (mbedtls_md_hmac(md, authSecret, authSecretLen, sharedSecret, 32, prkKey) != 0) {
		return false;
	}
	return mbedtls_md_hmac(md, prkKey, sizeof(prkKey), keyInfo.data(), keyInfo.size(), ikm) == 0;
}

bool ESPWebPush::deriveContentEncryptionKeyAndNonce(
    const uint8_t *salt, const uint8_t *ikm, uint8_t *cek, uint8_t *nonce
) const {
	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!md || !salt || !ikm || !cek || !nonce) {
		return false;
	}

	uint8_t prk[32];
	uint8_t cekFull[32];
	uint8_t nonceFull[32];

	const char *cekLabel = "Content-Encoding: aes128gcm";
	std::vector<uint8_t> cekInfo;
	cekInfo.reserve(strlen(cekLabel) + 2);
	cekInfo.insert(cekInfo.end(), cekLabel, cekLabel + strlen(cekLabel));
	cekInfo.push_back(0x00);
	cekInfo.push_back(0x01);

	const char *nonceLabel = "Content-Encoding: nonce";
	std::vector<uint8_t> nonceInfo;
	nonceInfo.reserve(strlen(nonceLabel) + 2);
	nonceInfo.insert(nonceInfo.end(), nonceLabel, nonceLabel + strlen(nonceLabel));
	nonceInfo.push_back(0x00);
	nonceInfo.push_back(0x01);

	if (mbedtls_md_hmac(md, salt, 16, ikm, 32, prk) != 0) {
		return false;
	}
	if (mbedtls_md_hmac(md, prk, sizeof(prk), cekInfo.data(), cekInfo.size(), cekFull) != 0) {
		return false;
	}
	if (mbedtls_md_hmac(md, prk, sizeof(prk), nonceInfo.data(), nonceInfo.size(), nonceFull) != 0) {
		return false;
	}

	memcpy(cek, cekFull, 16);
	memcpy(nonce, nonceFull, 12);
	return true;
}

bool ESPWebPush::encryptWithAESGCM(
    const std::string &plaintext,
    const uint8_t *cek,
    const uint8_t *nonce,
    std::vector<uint8_t> &ciphertextOut
) {
	if (plaintext.empty()) {
		ESP_LOGE(kTag, "encryptWithAESGCM: plaintext empty");
		return false;
	}

	std::vector<uint8_t> output(plaintext.size() + 16);
	size_t outputLen = 0;
	uint8_t tag[16];

	mbedtls_cipher_context_t cipher;
	mbedtls_cipher_init(&cipher);
	if (mbedtls_cipher_setup(&cipher, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM)) !=
	    0) {
		mbedtls_cipher_free(&cipher);
		return false;
	}
	if (mbedtls_cipher_setkey(&cipher, cek, 128, MBEDTLS_ENCRYPT) != 0) {
		mbedtls_cipher_free(&cipher);
		return false;
	}
	if (mbedtls_cipher_set_iv(&cipher, nonce, 12) != 0) {
		mbedtls_cipher_free(&cipher);
		return false;
	}
	if (mbedtls_cipher_reset(&cipher) != 0) {
		mbedtls_cipher_free(&cipher);
		return false;
	}
	if (mbedtls_cipher_update_ad(&cipher, nullptr, 0) != 0) {
		mbedtls_cipher_free(&cipher);
		return false;
	}

	size_t olen = 0;
	if (mbedtls_cipher_update(
	        &cipher,
	        reinterpret_cast<const uint8_t *>(plaintext.data()),
	        plaintext.size(),
	        output.data(),
	        &olen
	    ) != 0) {
		mbedtls_cipher_free(&cipher);
		return false;
	}
	outputLen = olen;

	if (mbedtls_cipher_finish(&cipher, output.data() + outputLen, &olen) != 0) {
		mbedtls_cipher_free(&cipher);
		return false;
	}
	outputLen += olen;

	if (mbedtls_cipher_write_tag(&cipher, tag, sizeof(tag)) != 0) {
		mbedtls_cipher_free(&cipher);
		return false;
	}

	output.resize(outputLen + sizeof(tag));
	memcpy(output.data() + outputLen, tag, sizeof(tag));
	ciphertextOut = std::move(output);
	mbedtls_cipher_free(&cipher);
	return true;
}

bool ESPWebPush::buildRecordBody(
    const uint8_t *salt,
    uint32_t recordSize,
    const uint8_t *serverPubKey,
    size_t serverPubKeyLen,
    const std::string &plaintext,
    const uint8_t *cek,
    const uint8_t *nonce,
    std::vector<uint8_t> &bodyOut
) {
	if (!salt || !serverPubKey || !cek || !nonce || serverPubKeyLen > 0xFF) {
		return false;
	}

	std::string recordPlaintext = plaintext;
	recordPlaintext.push_back(static_cast<char>(0x02));

	std::vector<uint8_t> ciphertext;
	if (!encryptWithAESGCM(recordPlaintext, cek, nonce, ciphertext)) {
		return false;
	}

	bodyOut.clear();
	bodyOut.reserve(16 + 4 + 1 + serverPubKeyLen + ciphertext.size());
	bodyOut.insert(bodyOut.end(), salt, salt + 16);
	appendUint32(bodyOut, recordSize);
	bodyOut.push_back(static_cast<uint8_t>(serverPubKeyLen));
	bodyOut.insert(bodyOut.end(), serverPubKey, serverPubKey + serverPubKeyLen);
	bodyOut.insert(bodyOut.end(), ciphertext.begin(), ciphertext.end());
	return true;
}

std::vector<uint8_t> ESPWebPush::encryptPayload(const std::string &plaintext, const Subscription &sub) {
	std::lock_guard<std::mutex> guard(_cryptoMutex);
	if (!initCrypto()) {
		return {};
	}

	std::vector<uint8_t> userPubKey;
	if (!decodeP256PublicKey(sub.p256dh, userPubKey)) {
		ESP_LOGE(kTag, "encryptPayload: client public key invalid");
		return {};
	}

	std::vector<uint8_t> authSecret;
	if (!base64UrlDecode(sub.auth, authSecret) || authSecret.size() != 16) {
		ESP_LOGE(kTag, "encryptPayload: auth secret invalid");
		return {};
	}

	std::vector<uint8_t> serverPrivateKey(32, 0);
	if (mbedtls_ctr_drbg_random(&(_crypto->ctrDrbg), serverPrivateKey.data(), serverPrivateKey.size()) !=
	    0) {
		ESP_LOGE(kTag, "encryptPayload: failed to generate ephemeral private key");
		return {};
	}

	std::vector<uint8_t> serverPublicKey;
	if (!generateECDHContext(serverPrivateKey, serverPublicKey)) {
		ESP_LOGE(kTag, "encryptPayload: failed to derive ephemeral public key");
		return {};
	}

	uint8_t sharedSecret[32];
	if (!deriveSharedSecret(userPubKey, serverPrivateKey, sharedSecret)) {
		ESP_LOGE(kTag, "encryptPayload: failed to derive shared secret");
		return {};
	}

	uint8_t ikm[32];
	if (!deriveInputKeyingMaterial(
	        authSecret.data(),
	        authSecret.size(),
	        sharedSecret,
	        userPubKey.data(),
	        userPubKey.size(),
	        serverPublicKey.data(),
	        serverPublicKey.size(),
	        ikm
	    )) {
		ESP_LOGE(kTag, "encryptPayload: failed to derive input keying material");
		return {};
	}

	uint8_t salt[16];
	if (!generateSalt(salt)) {
		ESP_LOGE(kTag, "encryptPayload: failed to generate salt");
		return {};
	}

	uint8_t cek[16];
	uint8_t nonce[12];
	if (!deriveContentEncryptionKeyAndNonce(salt, ikm, cek, nonce)) {
		ESP_LOGE(kTag, "encryptPayload: failed to derive content key and nonce");
		return {};
	}

	std::vector<uint8_t> body;
	if (!buildRecordBody(
	        salt,
	        kDefaultRecordSize,
	        serverPublicKey.data(),
	        serverPublicKey.size(),
	        plaintext,
	        cek,
	        nonce,
	        body
	    )) {
		ESP_LOGE(kTag, "encryptPayload: failed to build encrypted body");
		return {};
	}

	return body;
}

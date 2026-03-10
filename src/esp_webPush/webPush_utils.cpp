#include "webPush.h"

#include <algorithm>

extern "C" {
#include "esp_log.h"
#include "mbedtls/base64.h"
}

namespace {
constexpr const char *kTag = "ESPWebPush";
} // namespace

std::string ESPWebPush::base64UrlEncode(const uint8_t *data, size_t len) {
	if (!data || len == 0) {
		ESP_LOGW(kTag, "base64UrlEncode: empty input");
		return "";
	}

	size_t outLen = 0;
	std::vector<uint8_t> output(4 * ((len + 2) / 3) + 4);
	int ret = mbedtls_base64_encode(output.data(), output.size(), &outLen, data, len);
	if (ret != 0 || outLen == 0) {
		ESP_LOGE(kTag, "base64UrlEncode: encode failed -0x%04x", -ret);
		return "";
	}

	std::string encoded(reinterpret_cast<char *>(output.data()), outLen);
	std::replace(encoded.begin(), encoded.end(), '+', '-');
	std::replace(encoded.begin(), encoded.end(), '/', '_');
	encoded.erase(std::remove(encoded.begin(), encoded.end(), '='), encoded.end());
	return encoded;
}

std::string ESPWebPush::base64UrlEncode(const std::string &input) {
	return base64UrlEncode(reinterpret_cast<const uint8_t *>(input.data()), input.size());
}

bool ESPWebPush::base64UrlDecode(const std::string &input, std::vector<uint8_t> &output) {
	if (input.empty()) {
		output.clear();
		return false;
	}
	std::string padded = input;
	for (char &c : padded) {
		if (c == '-') {
			c = '+';
		} else if (c == '_') {
			c = '/';
		}
	}
	while (padded.size() % 4 != 0) {
		padded.push_back('=');
	}

	size_t requiredLen = 0;
	int probe = mbedtls_base64_decode(
	    nullptr,
	    0,
	    &requiredLen,
	    reinterpret_cast<const uint8_t *>(padded.data()),
	    padded.size()
	);
	if (probe != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL && probe != 0) {
		ESP_LOGE(kTag, "base64UrlDecode: sizing failed -0x%04x", -probe);
		output.clear();
		return false;
	}

	output.assign(requiredLen, 0);
	size_t actualOutLen = 0;
	int ret = mbedtls_base64_decode(
	    output.data(),
	    output.size(),
	    &actualOutLen,
	    reinterpret_cast<const uint8_t *>(padded.data()),
	    padded.size()
	);
	if (ret != 0) {
		ESP_LOGE(kTag, "base64UrlDecode: decode failed -0x%04x", -ret);
		output.clear();
		return false;
	}
	output.resize(actualOutLen);
	return true;
}

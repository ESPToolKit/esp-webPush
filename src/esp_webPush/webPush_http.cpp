#include "webPush.h"

#include <cctype>
#include <cstring>

extern "C" {
#include "esp_http_client.h"
#include "esp_log.h"
}

#if __has_include(<esp_crt_bundle.h>)
extern "C" {
#include <esp_crt_bundle.h>
}
#define ESPWEBPUSH_HAVE_CRT_BUNDLE 1
#else
#define ESPWEBPUSH_HAVE_CRT_BUNDLE 0
#endif

namespace {
constexpr const char *kTag = "ESPWebPush";

struct EndpointInfo {
	std::string host;
	std::string path = "/";
	const char *originClass = "custom";
};

bool equalsIgnoreCase(const std::string &lhs, const char *rhs) {
	if (rhs == nullptr) {
		return false;
	}

	const size_t rhsLength = std::strlen(rhs);
	if (lhs.size() != rhsLength) {
		return false;
	}

	for (size_t i = 0; i < lhs.size(); ++i) {
		if (std::tolower(static_cast<unsigned char>(lhs[i])) !=
		    std::tolower(static_cast<unsigned char>(rhs[i]))) {
			return false;
		}
	}

	return true;
}

bool endsWithIgnoreCase(const std::string &value, const char *suffix) {
	if (suffix == nullptr) {
		return false;
	}

	const size_t suffixLength = std::strlen(suffix);
	if (value.size() < suffixLength) {
		return false;
	}

	const size_t start = value.size() - suffixLength;
	for (size_t i = 0; i < suffixLength; ++i) {
		if (std::tolower(static_cast<unsigned char>(value[start + i])) !=
		    std::tolower(static_cast<unsigned char>(suffix[i]))) {
			return false;
		}
	}

	return true;
}

bool parseEndpointInfo(const std::string &endpoint, EndpointInfo &infoOut) {
	const size_t schemeSeparator = endpoint.find("://");
	const size_t authorityStart = schemeSeparator == std::string::npos ? 0 : schemeSeparator + 3;
	if (authorityStart >= endpoint.size()) {
		return false;
	}

	size_t authorityEnd = endpoint.find_first_of("/?#", authorityStart);
	if (authorityEnd == std::string::npos) {
		authorityEnd = endpoint.size();
	} else {
		infoOut.path = endpoint.substr(authorityEnd);
	}
	if (authorityEnd <= authorityStart) {
		return false;
	}

	const std::string authority = endpoint.substr(authorityStart, authorityEnd - authorityStart);
	const size_t userInfoSeparator = authority.rfind('@');
	const std::string hostAndPort =
	    userInfoSeparator == std::string::npos ? authority : authority.substr(userInfoSeparator + 1);
	if (hostAndPort.empty()) {
		return false;
	}

	if (hostAndPort.front() == '[') {
		const size_t closingBracket = hostAndPort.find(']');
		if (closingBracket == std::string::npos || closingBracket <= 1) {
			return false;
		}

		infoOut.host = hostAndPort.substr(1, closingBracket - 1);
	} else {
		const size_t portSeparator = hostAndPort.rfind(':');
		if (portSeparator != std::string::npos &&
		    hostAndPort.find(':', portSeparator + 1) == std::string::npos) {
			infoOut.host = hostAndPort.substr(0, portSeparator);
		} else {
			infoOut.host = hostAndPort;
		}
	}

	if (infoOut.host.empty()) {
		return false;
	}

	if (equalsIgnoreCase(infoOut.host, "fcm.googleapis.com") ||
	    endsWithIgnoreCase(infoOut.host, ".fcm.googleapis.com")) {
		infoOut.originClass = "fcm";
	} else if (equalsIgnoreCase(infoOut.host, "updates.push.services.mozilla.com") ||
	           endsWithIgnoreCase(infoOut.host, ".push.services.mozilla.com")) {
		infoOut.originClass = "mozilla";
	} else if (equalsIgnoreCase(infoOut.host, "web.push.apple.com") ||
	           endsWithIgnoreCase(infoOut.host, ".push.apple.com")) {
		infoOut.originClass = "apple";
	} else if (equalsIgnoreCase(infoOut.host, "wns.windows.com") ||
	           endsWithIgnoreCase(infoOut.host, ".notify.windows.com")) {
		infoOut.originClass = "windows";
	}

	return true;
}
} // namespace

void ESPWebPush::printHeaderErr(esp_err_t headErr, const char *headKey) const {
	if (headErr != ESP_OK) {
		ESP_LOGE(kTag, "Failed to set header %s: -0x%04x", headKey, -headErr);
	}
}

WebPushResult ESPWebPush::sendPushRequest(
    const std::string &endpoint, const std::string &jwt, const std::vector<uint8_t> &body
) {
	WebPushResult result{};
	EndpointInfo endpointInfo{};
	if (endpoint.empty()) {
		result.error = WebPushError::InvalidSubscription;
		result.message = errorToString(result.error);
		return result;
	}
	if (!parseEndpointInfo(endpoint, endpointInfo)) {
		endpointInfo.host = endpointOrigin(endpoint);
	}

	esp_http_client_config_t config = {};
	config.url = endpoint.c_str();
	config.method = HTTP_METHOD_POST;
	config.timeout_ms = static_cast<int>(_config.requestTimeoutMs);
	config.buffer_size_tx = 6144;
	config.skip_cert_common_name_check = _config.skipTlsCommonNameCheck;
	config.use_global_ca_store = _config.useGlobalCaStore;
#if ESPWEBPUSH_HAVE_CRT_BUNDLE
	if (_config.useTlsCertBundle) {
		config.crt_bundle_attach = esp_crt_bundle_attach;
	}
#endif

	esp_http_client_handle_t client = esp_http_client_init(&config);
	if (!client) {
		result.error = WebPushError::InternalError;
		result.message = errorToString(result.error);
		return result;
	}

	const std::string authHeader =
	    "vapid t=" + jwt + ", k=" + _vapidConfig.publicKeyBase64;
	const std::string ttlValue = std::to_string(_config.ttlSeconds);

	printHeaderErr(
	    esp_http_client_set_header(client, "Authorization", authHeader.c_str()),
	    "Authorization"
	);
	printHeaderErr(esp_http_client_set_header(client, "TTL", ttlValue.c_str()), "TTL");
	printHeaderErr(
	    esp_http_client_set_header(client, "Content-Encoding", "aes128gcm"),
	    "Content-Encoding"
	);
	printHeaderErr(
	    esp_http_client_set_header(client, "Content-Type", "application/octet-stream"),
	    "Content-Type"
	);

	esp_http_client_set_post_field(
	    client,
	    reinterpret_cast<const char *>(body.data()),
	    static_cast<int>(body.size())
	);

	const esp_err_t err = esp_http_client_perform(client);
	const int statusCode = esp_http_client_get_status_code(client);

	result.transportError = err;
	result.statusCode = statusCode;

	if (err != ESP_OK) {
		result.error = WebPushError::TransportError;
		result.message = errorToString(result.error);
		ESP_LOGE(
		    kTag,
		    "HTTP POST failed: host=%s path=%s origin=%s err=%s(%d) status=%d",
		    endpointInfo.host.c_str(),
		    endpointInfo.path.c_str(),
		    endpointInfo.originClass,
		    esp_err_to_name(err),
		    static_cast<int>(err),
		    statusCode
		);
		if (err == ESP_ERR_HTTP_CONNECT) {
			ESP_LOGE(
			    kTag,
			    "TLS/connect setup failed before HTTP response: host=%s path=%s origin=%s",
			    endpointInfo.host.c_str(),
			    endpointInfo.path.c_str(),
			    endpointInfo.originClass
			);
		}
	} else if (statusCode < 200 || statusCode >= 300) {
		result.error = WebPushError::HttpError;
		result.message = errorToString(result.error);
		ESP_LOGE(
		    kTag,
		    "HTTP POST failed: host=%s path=%s origin=%s status=%d",
		    endpointInfo.host.c_str(),
		    endpointInfo.path.c_str(),
		    endpointInfo.originClass,
		    statusCode
		);
	} else {
		result.error = WebPushError::None;
		result.message = errorToString(result.error);
		ESP_LOGI(
		    kTag,
		    "HTTP POST succeeded: host=%s path=%s origin=%s status=%d",
		    endpointInfo.host.c_str(),
		    endpointInfo.path.c_str(),
		    endpointInfo.originClass,
		    statusCode
		);
	}

	esp_http_client_cleanup(client);
	return result;
}

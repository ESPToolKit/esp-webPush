#include "webPush.h"

extern "C" {
#include "esp_http_client.h"
#include "esp_log.h"
}

#if defined(ESP_IDF_VERSION) && !defined(ARDUINO)
extern "C" {
#include "esp_netif.h"
#include "lwip/ip_addr.h"
}
#endif

namespace {
constexpr const char *kTag = "ESPWebPush";
} // namespace

bool ESPWebPush::isNetworkReadyForPush() const {
#if defined(ESP_IDF_VERSION) && !defined(ARDUINO)
	esp_netif_t *netif = esp_netif_get_default_netif();
	if (!netif) {
		return false;
	}
	if (!esp_netif_is_netif_up(netif)) {
		return false;
	}

	esp_netif_dns_info_t dnsInfo{};
	if (esp_netif_get_dns_info(netif, ESP_NETIF_DNS_MAIN, &dnsInfo) != ESP_OK) {
		return false;
	}
	if (dnsInfo.ip.type != IPADDR_TYPE_V4 || dnsInfo.ip.u_addr.ip4.addr == 0) {
		return false;
	}
	return true;
#else
	return true;
#endif
}

void ESPWebPush::printHeaderErr(esp_err_t headErr, const char *headKey) const {
	if (headErr != ESP_OK) {
		ESP_LOGE(kTag, "Failed to set header %s: -0x%04x", headKey, -headErr);
	}
}

WebPushResult ESPWebPush::sendPushRequest(
    const std::string &endpoint,
    const std::string &jwt,
    const std::string &salt,
    const std::string &serverPublicKey,
    const std::vector<uint8_t> &ciphertext
) {
	WebPushResult result{};
	if (endpoint.empty()) {
		result.error = WebPushError::InvalidSubscription;
		result.message = errorToString(result.error);
		return result;
	}

	esp_http_client_config_t config = {};
	config.url = endpoint.c_str();
	config.method = HTTP_METHOD_POST;
	config.timeout_ms = static_cast<int>(_config.requestTimeoutMs);
	config.buffer_size_tx = 6048;

	esp_http_client_handle_t client = esp_http_client_init(&config);
	if (!client) {
		result.error = WebPushError::InternalError;
		result.message = errorToString(result.error);
		return result;
	}

	std::string authHeader = "vapid t=" + jwt + ", k=" + _vapidPublicKey;
	std::string cryptoKeyHeader = "dh=" + serverPublicKey + ";p256ecdsa=" + _vapidPublicKey;
	std::string encryptionHeader = "salt=" + salt;
	std::string ttlValue = std::to_string(_config.ttlSeconds);

	printHeaderErr(
	    esp_http_client_set_header(client, "Authorization", authHeader.c_str()),
	    "Authorization"
	);
	printHeaderErr(esp_http_client_set_header(client, "TTL", ttlValue.c_str()), "TTL");
	printHeaderErr(
	    esp_http_client_set_header(client, "Content-Encoding", "aesgcm"),
	    "Content-Encoding"
	);
	printHeaderErr(
	    esp_http_client_set_header(client, "Content-Type", "application/octet-stream"),
	    "Content-Type"
	);
	printHeaderErr(
	    esp_http_client_set_header(client, "Encryption", encryptionHeader.c_str()),
	    "Encryption"
	);
	printHeaderErr(
	    esp_http_client_set_header(client, "Crypto-Key", cryptoKeyHeader.c_str()),
	    "Crypto-Key"
	);

	esp_http_client_set_post_field(
	    client,
	    reinterpret_cast<const char *>(ciphertext.data()),
	    ciphertext.size()
	);

	esp_err_t err = esp_http_client_perform(client);
	int statusCode = esp_http_client_get_status_code(client);

	result.transportError = err;
	result.statusCode = statusCode;

	if (err != ESP_OK) {
		result.error = WebPushError::TransportError;
		result.message = errorToString(result.error);
		ESP_LOGE(kTag, "HTTP POST failed: %s (status %d)", esp_err_to_name(err), statusCode);
	} else if (statusCode < 200 || statusCode >= 300) {
		result.error = WebPushError::HttpError;
		result.message = errorToString(result.error);
		ESP_LOGE(kTag, "HTTP POST failed: status %d", statusCode);
	} else {
		result.error = WebPushError::None;
		result.message = errorToString(result.error);
	}

	esp_http_client_cleanup(client);
	return result;
}

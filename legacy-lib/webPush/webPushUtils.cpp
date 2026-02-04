#include <algorithm>

#include "webPush.h"

void WebPush::initCrypto() {
    if (cryptoInitialized) return;

    // ESP_LOGI(FeatureTag::WebPush, "Initializing crypto");

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char* pers = "webpush_drbg";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    reinterpret_cast<const unsigned char*>(pers), strlen(pers));
    if (ret != 0) {
        ESP_LOGE(FeatureTag::WebPush, "Failed to seed DRBG: -0x%04x", -ret);
    } else {
        cryptoInitialized = true;
    }
}

std::string WebPush::base64UrlEncode(const uint8_t* data, size_t len) {
    if (len == 0) {
        ESP_LOGW(FeatureTag::WebPush, "base64UrlEncode: Input data length is 0. Returning empty string.");
        return "";
    }

    size_t outLen = 0;
    // Calculate a safe upper bound for the output buffer size.
    // Base64 encoding expands data by 4/3, plus padding. For URL-safe, padding is removed.
    // A safe size is (len / 3 + 1) * 4 to account for block padding before removing '='
    std::vector<uint8_t> output(4 * ((len + 2) / 3) + 4);

    // Perform the Base64 encoding
    int ret = mbedtls_base64_encode(output.data(), output.size(), &outLen, data, len);

    if (ret != 0) {
        ESP_LOGE(FeatureTag::WebPush, "base64UrlEncode: mbedtls_base64_encode failed with error -0x%04x for input len %u", -ret, (unsigned)len);
        return "";  // Return empty string on failure
    }
    if (outLen == 0) {
        ESP_LOGE(FeatureTag::WebPush, "base64UrlEncode: mbedtls_base64_encode succeeded but returned 0 output length for input len %u", (unsigned)len);
        return "";  // Return empty string if no output
    }

    std::string encoded((char*)output.data(), outLen);

    // Replace URL-unsafe characters
    std::replace(encoded.begin(), encoded.end(), '+', '-');
    std::replace(encoded.begin(), encoded.end(), '/', '_');
    // Remove padding characters '='
    encoded.erase(std::remove(encoded.begin(), encoded.end(), '='), encoded.end());

    // Log the encoded string length for verification
    // ESP_LOGI(FeatureTag::WebPush, "base64UrlEncode: Encoded string length for input len %u is %u", (unsigned)len, (unsigned)encoded.length());

    return encoded;
}

std::string WebPush::base64UrlEncode(const std::string& input) {
    return base64UrlEncode(reinterpret_cast<const uint8_t*>(input.data()), input.size());
}

std::vector<uint8_t> WebPush::base64UrlDecode(const std::string& input) {
    std::string padded = input;
    // Replace URL-safe characters with standard Base64 characters
    for (char& c : padded) {
        if (c == '-')
            c = '+';
        else if (c == '_')
            c = '/';
    }
    // Add padding if missing, so mbedtls_base64_decode can work
    while (padded.size() % 4 != 0) padded += '=';

    size_t requiredLen = 0;
    // First call to get the required output length
    // Pass nullptr for buffer and 0 for buffer size to get the needed length
    int ret = mbedtls_base64_decode(nullptr, 0, &requiredLen, reinterpret_cast<const uint8_t*>(padded.data()), padded.size());

    // MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL is expected on the first call if buffer is too small
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL && ret != 0) {
        ESP_LOGE(FeatureTag::WebPush, "Base64 decode (sizing) failed for input: %s, error: -0x%04x", input.c_str(), -ret);
        return {};
    }

    std::vector<uint8_t> output(requiredLen);  // Allocate exactly the required size
    size_t actualOutLen = 0;
    // Second call to actually decode into the correctly sized buffer
    ret = mbedtls_base64_decode(output.data(), output.size(), &actualOutLen, reinterpret_cast<const uint8_t*>(padded.data()), padded.size());

    if (ret != 0) {
        ESP_LOGE(FeatureTag::WebPush, "Base64 decode failed for input: %s, error: -0x%04x", input.c_str(), -ret);
        return {};
    }
    output.resize(actualOutLen);  // Resize to actual content length, in case it's smaller
    return output;
}

std::string WebPush::generateVapidJWT(const std::string& aud, const std::string& sub, const std::string& privateKeyBase64) {
    return jwtES256.sign(aud, sub, privateKeyBase64, 12 * 60 * 60);  // 12 hours expiry
}

void WebPush::printHeadErr(esp_err_t headErr, const char* headKey) {
    if (headErr != ESP_OK) {
        ESP_LOGE(FeatureTag::WebPush, "Failed to set header %s: -0x%04x", headKey, -headErr);
    }
}

int WebPush::sendPushRequest(const std::string& endpoint,
                             const std::string& jwt,
                             const std::string& salt,
                             const std::string& serverPublicKey,
                             const std::vector<uint8_t>& ciphertext) {
    esp_http_client_config_t config = {
        .url = endpoint.c_str(),
        .method = HTTP_METHOD_POST,
        .timeout_ms = 10000,
        .buffer_size_tx = 6048,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(FeatureTag::WebPush, "HTTP client init failed");
        return 0;
    }

    // std::string authHeader = "WebPush " + jwt;
    // Use the VAPID authorization scheme so the push service keeps associating the
    // JWT with our public key even after it rotates registration tokens. Using the
    // legacy "WebPush" scheme caused the subscriptions to expire after a short
    // period which forced users to resubscribe frequently.
    std::string authHeader = "vapid t=" + jwt + ", k=" + vapidPublicKey;
    std::string cryptoKeyHeader = "dh=" + serverPublicKey + ";p256ecdsa=" + vapidPublicKey;
    std::string encryptionHeader = "salt=" + salt;

    /*
    ESP_LOGI(FeatureTag::WebPush, "Sending push request to %s", endpoint.c_str());
    ESP_LOGI(FeatureTag::WebPush, "Headers being set:");
    ESP_LOGI(FeatureTag::WebPush, "Authorization: %s", authHeader.c_str());
    ESP_LOGI(FeatureTag::WebPush, "TTL: 2419200");
    ESP_LOGI(FeatureTag::WebPush, "Content-Encoding: aesgcm");
    ESP_LOGI(FeatureTag::WebPush, "Content-Type: application/octet-stream");
    ESP_LOGI(FeatureTag::WebPush, "Encryption: %s", encryptionHeader.c_str());
    ESP_LOGI(FeatureTag::WebPush, "Crypto-Key: %s", cryptoKeyHeader.c_str());
    ESP_LOGI(FeatureTag::WebPush, "Crypto-Key (dh part) length: %u", (unsigned)serverPublicKey.length());
    */

    esp_err_t headErr = esp_http_client_set_header(client, "Authorization", authHeader.c_str());
    printHeadErr(headErr, "Authorization");
    headErr = esp_http_client_set_header(client, "TTL", "2419200");
    printHeadErr(headErr, "TTL");
    headErr = esp_http_client_set_header(client, "Content-Encoding", "aesgcm");
    printHeadErr(headErr, "Content-Encoding");
    headErr = esp_http_client_set_header(client, "Content-Type", "application/octet-stream");
    printHeadErr(headErr, "Content-Type");
    headErr = esp_http_client_set_header(client, "Encryption", encryptionHeader.c_str());
    printHeadErr(headErr, "Encryption");
    headErr = esp_http_client_set_header(client, "Crypto-Key", cryptoKeyHeader.c_str());
    printHeadErr(headErr, "Crypto-Key");

    esp_http_client_set_post_field(client,
                                   reinterpret_cast<const char*>(ciphertext.data()),
                                   ciphertext.size());

    esp_err_t err = esp_http_client_perform(client);
    int statusCode = esp_http_client_get_status_code(client);

    if (err != ESP_OK) {
        ESP_LOGE(
            FeatureTag::WebPush,
            "HTTP POST failed: %s. Status: %d",
            esp_err_to_name(err),
            statusCode);
    } else if (statusCode != 201) {
        ESP_LOGE(
            FeatureTag::WebPush,
            "HTTP POST failed. Status: %d",
            statusCode);
    }

    esp_http_client_cleanup(client);
    return err == ESP_OK ? statusCode : 0;
}
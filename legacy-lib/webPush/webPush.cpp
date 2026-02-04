#include "webPush.h"

#include <core/debug/debug.h>
#include <core/network/network.h>
#include <esp_netif.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

namespace {
constexpr uint32_t kWebPushRetryBaseMs = 1500;
constexpr uint32_t kWebPushRetryMaxDelayMs = 15000;
constexpr uint8_t kWebPushMaxRetries = 5;

uint32_t calcRetryDelayMs(uint8_t attempt) {
    uint32_t delay = kWebPushRetryBaseMs << attempt;
    if (delay > kWebPushRetryMaxDelayMs) {
        delay = kWebPushRetryMaxDelayMs;
    }
    return delay;
}
}  // namespace

void WebPush::init(const std::string& contactEmail, const std::string& publicKeyBase64, const std::string& privateKeyBase64) {
    vapidEmail = contactEmail;
    vapidPublicKey = publicKeyBase64;
    vapidPrivateKey = privateKeyBase64;

    /* --- NEW: VAPID Public Key Validation Check ---
    std::vector<uint8_t> decodedVapidPubKey = base64UrlDecode(vapidPublicKey);
    if (decodedVapidPubKey.empty()) {
        ESP_LOGE(FeatureTag::WebPush, "init: Failed to Base64Url decode VAPID Public Key.");
    } else if (decodedVapidPubKey.size() != 65) {
        ESP_LOGE(FeatureTag::WebPush, "init: Decoded VAPID Public Key is not 65 bytes long. Actual: %u", (unsigned)decodedVapidPubKey.size());
    } else if (decodedVapidPubKey[0] != 0x04) {
        ESP_LOGE(FeatureTag::WebPush, "init: Decoded VAPID Public Key does not start with 0x04 (uncompressed format). Starts with 0x%02X", decodedVapidPubKey[0]);
    } else {
        ESP_LOGI(FeatureTag::WebPush, "init: VAPID Public Key decoded and format check passed (65 bytes, starts 0x04)");
    }
    // --- END NEW CHECK --- */

    if (!msgQueue) {
        msgQueue = xQueueCreateWithCaps(50, sizeof(WebPushQueueItem*), MALLOC_CAP_SPIRAM);
        if (!msgQueue) {
            ESP_LOGE(FeatureTag::WebPush, "Failed to create WebPush message queue");
            return;
        }
    }

    BaseType_t result = worker.offloadToPsRam(
        std::bind(&WebPush::workerTask, this),
        16 * 1024, 1, "WebPush", nullptr, 1
    );

    if (result != pdPASS) {
        ESP_LOGE(FeatureTag::WebPush, "Failed to start web push task");
    } else {
        ESP_LOGI(FeatureTag::WebPush, "WebPush initialized");
    }
}

void WebPush::send(PushMessage& msg, webPushResultCB callback) {
    PushMessage* newMSG = new PushMessage;
    newMSG->sub = msg.sub;
    newMSG->payload = msg.payload;
    WebPushQueueItem* item = new WebPushQueueItem;
    item->sub = newMSG;
    item->callback = callback;
    if (!msgQueue || xQueueSend(msgQueue, &item, pdMS_TO_TICKS(100)) != pdTRUE) {
        ESP_LOGW(FeatureTag::WebPush, "WebPush queue full or not ready");
        delete newMSG;
        delete item;
    }
}

void WebPush::workerTask() {
    WebPushQueueItem* item;
    while (true) {
        if (xQueueReceive(msgQueue, &item, portMAX_DELAY) == pdTRUE) {
            handleMessage(*item);
            delete item->sub;
            delete item;
        }
    }
}

void WebPush::handleMessage(WebPushQueueItem& item) {
    PushMessage* msg = item.sub;
    webPushResultCB callback = item.callback;

    for (uint8_t attempt = 0; attempt <= kWebPushMaxRetries; ++attempt) {
        if (!isNetworkReadyForPush()) {
            if (attempt >= kWebPushMaxRetries) {
                ESP_LOGE(FeatureTag::WebPush, "Network not ready for push. Dropping request.");
                if (callback) {
                    callback(0);
                }
                return;
            }
            uint32_t delayMs = calcRetryDelayMs(attempt);
            ESP_LOGW(
                FeatureTag::WebPush,
                "Network not ready for push. Retry %u/%u in %ums",
                static_cast<unsigned int>(attempt + 1),
                static_cast<unsigned int>(kWebPushMaxRetries),
                static_cast<unsigned int>(delayMs));
            vTaskDelay(pdMS_TO_TICKS(delayMs));
            continue;
        }

        std::string salt, serverPubKey;
        auto ciphertext = encryptPayload(msg->payload, msg->sub, salt, serverPubKey);
        if (ciphertext.empty()) {
            ESP_LOGE(FeatureTag::WebPush, "Encryption failed");
            return;
        }

        std::string jwt = generateVapidJWT(
            msg->sub.endpoint.substr(0, msg->sub.endpoint.find("/", 8)),  // origin
            "mailto:" + vapidEmail,
            vapidPrivateKey);

        int statusCode = sendPushRequest(msg->sub.endpoint, jwt, salt, serverPubKey, ciphertext);
        if (statusCode == 0) {
            if (attempt >= kWebPushMaxRetries) {
                ESP_LOGE(FeatureTag::WebPush, "Push request failed. Dropping request.");
                if (callback) {
                    callback(0);
                }
                return;
            }
            uint32_t delayMs = calcRetryDelayMs(attempt);
            ESP_LOGW(
                FeatureTag::WebPush,
                "Push request failed. Retry %u/%u in %ums",
                static_cast<unsigned int>(attempt + 1),
                static_cast<unsigned int>(kWebPushMaxRetries),
                static_cast<unsigned int>(delayMs));
            vTaskDelay(pdMS_TO_TICKS(delayMs));
            continue;
        }

        if (callback) {
            callback(statusCode);
        }
        return;
    }
}

bool WebPush::isNetworkReadyForPush() {
    if (!network.isConnected()) {
        return false;
    }

    NetworkConnectionStatus status = network.getStatus();
    if (!network.isValidIP(status.ip)) {
        return false;
    }

    esp_netif_t* netif = esp_netif_get_default_netif();
    if (!netif || !esp_netif_is_netif_up(netif)) {
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
}

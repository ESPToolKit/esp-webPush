#include "webPush.h"

#include <new>
#include <utility>

extern "C" {
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/task.h"
}

namespace {
constexpr const char *kTag = "ESPWebPush";
constexpr TickType_t kWorkerPollTicks = pdMS_TO_TICKS(250);

uint32_t capsForMemory(WebPushQueueMemory memory) {
    switch (memory) {
        case WebPushQueueMemory::Internal:
            return MALLOC_CAP_INTERNAL;
        case WebPushQueueMemory::Psram:
            return MALLOC_CAP_SPIRAM;
        case WebPushQueueMemory::Any:
        default:
            return MALLOC_CAP_DEFAULT;
    }
}
}  // namespace

ESPWebPush::~ESPWebPush() {
    deinit();
}

bool ESPWebPush::init(const std::string &contactEmail,
                      const std::string &publicKeyBase64,
                      const std::string &privateKeyBase64,
                      const WebPushConfig &config) {
    deinit();

    if (contactEmail.empty() || publicKeyBase64.empty() || privateKeyBase64.empty()) {
        ESP_LOGE(kTag, "init: missing VAPID keys or contact email");
        return false;
    }

    if (config.queueLength == 0) {
        ESP_LOGE(kTag, "init: queue length must be > 0");
        return false;
    }

    _config = config;
    _vapidEmail = contactEmail;
    _vapidPublicKey = publicKeyBase64;
    _vapidPrivateKey = privateKeyBase64;

    if (_config.worker.name.empty()) {
        _config.worker.name = "webpush";
    }

    WebPushResult keyCheck{};
    if (!validateVapidKeys(keyCheck)) {
        ESP_LOGE(kTag, "init: invalid VAPID keys (%s)", keyCheck.message ? keyCheck.message : "unknown");
        return false;
    }

    _queue = createQueue(_config.queueLength, sizeof(QueueItem *), _config.queueMemory);
    if (!_queue) {
        ESP_LOGE(kTag, "init: failed to create queue");
        return false;
    }

    ESPWorker::Config workerConfig{};
    workerConfig.maxWorkers = 1;
    workerConfig.stackSize = _config.worker.stackSize;
    workerConfig.priority = _config.worker.priority;
    workerConfig.coreId = _config.worker.coreId;
    workerConfig.enableExternalStacks = _config.worker.useExternalStack;
    _worker.init(workerConfig);

    _stopRequested.store(false, std::memory_order_release);
    WorkerResult result = _worker.spawn([this]() { workerLoop(); }, _config.worker);
    if (!result) {
        ESP_LOGE(kTag, "init: failed to start worker (%s)", _worker.errorToString(result.error));
        _worker.deinit();
        vQueueDelete(_queue);
        _queue = nullptr;
        return false;
    }

    _workerHandler = result.handler;
    _initialized.store(true, std::memory_order_release);
    ESP_LOGI(kTag, "ESPWebPush initialized");
    return true;
}

void ESPWebPush::deinit() {
    if (!_initialized.load(std::memory_order_acquire)) {
        return;
    }

    _stopRequested.store(true, std::memory_order_release);

    if (_workerHandler) {
        _workerHandler->wait(pdMS_TO_TICKS(2000));
        _workerHandler->destroy();
        _workerHandler.reset();
    }

    _worker.deinit();

    if (_queue) {
        QueueItem *item = nullptr;
        while (xQueueReceive(_queue, &item, 0) == pdTRUE) {
            if (item) {
                freeItem(item);
            }
        }
        vQueueDelete(_queue);
        _queue = nullptr;
    }

    deinitCrypto();

    _initialized.store(false, std::memory_order_release);
}

bool ESPWebPush::send(const PushMessage &msg, WebPushResultCB callback) {
    if (!_initialized.load(std::memory_order_acquire) || !_queue) {
        ESP_LOGW(kTag, "send: not initialized");
        return false;
    }

    QueueItem *item = allocateItem();
    if (!item) {
        ESP_LOGW(kTag, "send: out of memory");
        return false;
    }

    item->msg = msg;
    item->callback = std::move(callback);

    QueueItem *payload = item;
    TickType_t waitTicks = pdMS_TO_TICKS(_config.enqueueTimeoutMs);
    if (xQueueSend(_queue, &payload, waitTicks) != pdTRUE) {
        ESP_LOGW(kTag, "send: queue full");
        freeItem(item);
        return false;
    }

    return true;
}

WebPushResult ESPWebPush::send(const PushMessage &msg) {
    if (!_initialized.load(std::memory_order_acquire)) {
        WebPushResult result{};
        result.error = WebPushError::NotInitialized;
        result.message = errorToString(result.error);
        return result;
    }
    return handleMessage(msg);
}

const char *ESPWebPush::errorToString(WebPushError error) const {
    switch (error) {
        case WebPushError::None:
            return "ok";
        case WebPushError::NotInitialized:
            return "not initialized";
        case WebPushError::InvalidConfig:
            return "invalid config";
        case WebPushError::InvalidSubscription:
            return "invalid subscription";
        case WebPushError::InvalidVapidKeys:
            return "invalid VAPID keys";
        case WebPushError::QueueFull:
            return "queue full";
        case WebPushError::OutOfMemory:
            return "out of memory";
        case WebPushError::CryptoInitFailed:
            return "crypto init failed";
        case WebPushError::EncryptFailed:
            return "encryption failed";
        case WebPushError::JwtFailed:
            return "jwt sign failed";
        case WebPushError::NetworkUnavailable:
            return "network unavailable";
        case WebPushError::TransportError:
            return "transport error";
        case WebPushError::HttpError:
            return "http error";
        case WebPushError::InternalError:
            return "internal error";
        default:
            return "unknown";
    }
}

WebPushResult ESPWebPush::handleMessage(const PushMessage &msg) {
    WebPushResult result{};
    if (!validateSubscription(msg.sub, result)) {
        return result;
    }

    for (uint8_t attempt = 0; attempt <= _config.maxRetries; ++attempt) {
        if (_config.requireNetworkReady && !isNetworkReadyForPush()) {
            result.error = WebPushError::NetworkUnavailable;
            result.message = errorToString(result.error);
            if (attempt >= _config.maxRetries) {
                return result;
            }
            vTaskDelay(pdMS_TO_TICKS(calcRetryDelayMs(attempt)));
            continue;
        }

        std::string salt;
        std::string serverKey;
        std::vector<uint8_t> ciphertext = encryptPayload(msg.payload, msg.sub, salt, serverKey);
        if (ciphertext.empty()) {
            result.error = WebPushError::EncryptFailed;
            result.message = errorToString(result.error);
            return result;
        }

        std::string aud = endpointOrigin(msg.sub.endpoint);
        std::string jwt = generateVapidJWT(aud, "mailto:" + _vapidEmail, _vapidPrivateKey);
        if (jwt.empty()) {
            result.error = WebPushError::JwtFailed;
            result.message = errorToString(result.error);
            return result;
        }

        WebPushResult request = sendPushRequest(msg.sub.endpoint, jwt, salt, serverKey, ciphertext);
        if (request.ok()) {
            return request;
        }

        result = request;
        if (!shouldRetry(request) || attempt >= _config.maxRetries) {
            return result;
        }

        vTaskDelay(pdMS_TO_TICKS(calcRetryDelayMs(attempt)));
    }

    result.error = WebPushError::InternalError;
    result.message = errorToString(result.error);
    return result;
}

bool ESPWebPush::shouldRetry(const WebPushResult &result) const {
    if (result.error == WebPushError::NetworkUnavailable ||
        result.error == WebPushError::TransportError) {
        return true;
    }
    if (result.error == WebPushError::HttpError) {
        if (result.statusCode == 0) {
            return true;
        }
        if (result.statusCode == 408 || result.statusCode == 429) {
            return true;
        }
        if (result.statusCode >= 500) {
            return true;
        }
    }
    return false;
}

uint32_t ESPWebPush::calcRetryDelayMs(uint8_t attempt) const {
    if (_config.retryBaseDelayMs == 0) {
        return 0;
    }
    uint32_t delay = _config.retryBaseDelayMs << attempt;
    if (delay > _config.retryMaxDelayMs) {
        delay = _config.retryMaxDelayMs;
    }
    return delay;
}

bool ESPWebPush::validateSubscription(const Subscription &sub, WebPushResult &result) const {
    if (sub.deleted || sub.endpoint.empty() || sub.p256dh.empty() || sub.auth.empty()) {
        result.error = WebPushError::InvalidSubscription;
        result.message = errorToString(result.error);
        return false;
    }
    return true;
}

bool ESPWebPush::validateVapidKeys(WebPushResult &result) {
    std::vector<uint8_t> pubKey;
    std::vector<uint8_t> privKey;
    if (!base64UrlDecode(_vapidPublicKey, pubKey) || !base64UrlDecode(_vapidPrivateKey, privKey)) {
        result.error = WebPushError::InvalidVapidKeys;
        result.message = errorToString(result.error);
        return false;
    }
    if (pubKey.size() != 65 || pubKey[0] != 0x04) {
        result.error = WebPushError::InvalidVapidKeys;
        result.message = errorToString(result.error);
        return false;
    }
    if (privKey.size() != 32) {
        result.error = WebPushError::InvalidVapidKeys;
        result.message = errorToString(result.error);
        return false;
    }
    return true;
}

QueueHandle_t ESPWebPush::createQueue(size_t length, size_t itemSize, WebPushQueueMemory memory) {
    uint32_t caps = capsForMemory(memory);
    QueueHandle_t queue = xQueueCreateWithCaps(length, itemSize, caps);
    if (!queue && caps != MALLOC_CAP_DEFAULT) {
        queue = xQueueCreateWithCaps(length, itemSize, MALLOC_CAP_DEFAULT);
    }
    if (!queue) {
        queue = xQueueCreate(length, itemSize);
    }
    return queue;
}

ESPWebPush::QueueItem *ESPWebPush::allocateItem() {
    uint32_t caps = capsForMemory(_config.queueMemory);
    void *mem = heap_caps_malloc(sizeof(QueueItem), caps);
    if (!mem && caps != MALLOC_CAP_DEFAULT) {
        mem = heap_caps_malloc(sizeof(QueueItem), MALLOC_CAP_DEFAULT);
    }
    if (!mem) {
        return nullptr;
    }
    return new (mem) QueueItem();
}

void ESPWebPush::freeItem(QueueItem *item) {
    if (!item) {
        return;
    }
    item->~QueueItem();
    heap_caps_free(item);
}

void ESPWebPush::workerLoop() {
    while (!_stopRequested.load(std::memory_order_acquire)) {
        QueueItem *item = nullptr;
        if (xQueueReceive(_queue, &item, kWorkerPollTicks) != pdTRUE) {
            continue;
        }
        if (!item) {
            continue;
        }
        WebPushResult result = handleMessage(item->msg);
        if (item->callback) {
            item->callback(result);
        }
        freeItem(item);
    }
}

std::string ESPWebPush::endpointOrigin(const std::string &endpoint) const {
    size_t schemePos = endpoint.find("://");
    if (schemePos == std::string::npos) {
        return endpoint;
    }
    size_t start = schemePos + 3;
    size_t slash = endpoint.find('/', start);
    if (slash == std::string::npos) {
        return endpoint;
    }
    return endpoint.substr(0, slash);
}

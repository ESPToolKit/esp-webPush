#pragma once

#include <Arduino.h>

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

extern "C" {
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
}

#include <ESPWorker.h>

struct Subscription {
    std::string endpoint;
    std::string p256dh;
    std::string auth;
    std::string deviceId;
    std::vector<std::string> disabledTags;
    bool deleted = false;
};

struct PushMessage {
    Subscription sub;
    std::string payload;
};

enum class WebPushQueueMemory : uint8_t {
    Any = 0,
    Internal,
    Psram
};

enum class WebPushError : uint8_t {
    None = 0,
    NotInitialized,
    InvalidConfig,
    InvalidSubscription,
    InvalidVapidKeys,
    QueueFull,
    OutOfMemory,
    CryptoInitFailed,
    EncryptFailed,
    JwtFailed,
    NetworkUnavailable,
    TransportError,
    HttpError,
    InternalError
};

struct WebPushResult {
    WebPushError error = WebPushError::None;
    esp_err_t transportError = ESP_OK;
    int statusCode = 0;
    const char *message = nullptr;

    bool ok() const {
        return error == WebPushError::None &&
               transportError == ESP_OK &&
               statusCode >= 200 &&
               statusCode < 300;
    }

    explicit operator bool() const { return ok(); }
};

using WebPushResultCB = std::function<void(WebPushResult result)>;

struct WebPushConfig {
    WorkerConfig worker{};
    size_t queueLength = 32;
    WebPushQueueMemory queueMemory = WebPushQueueMemory::Psram;
    uint32_t enqueueTimeoutMs = 100;
    uint32_t requestTimeoutMs = 10000;
    uint32_t ttlSeconds = 2419200;
    uint8_t maxRetries = 5;
    uint32_t retryBaseDelayMs = 1500;
    uint32_t retryMaxDelayMs = 15000;
    bool requireNetworkReady = true;
};

class ESPWebPush {
   public:
    ESPWebPush() = default;
    ~ESPWebPush();

    bool init(const std::string &contactEmail,
              const std::string &publicKeyBase64,
              const std::string &privateKeyBase64,
              const WebPushConfig &config = WebPushConfig{});

    void deinit();
    bool initialized() const { return _initialized.load(std::memory_order_acquire); }

    bool send(const PushMessage &msg, WebPushResultCB callback);
    WebPushResult send(const PushMessage &msg);

    const char *errorToString(WebPushError error) const;

   private:
    struct QueueItem {
        PushMessage msg;
        WebPushResultCB callback;
    };

    struct CryptoState;

    WebPushResult handleMessage(const PushMessage &msg);
    bool shouldRetry(const WebPushResult &result) const;
    uint32_t calcRetryDelayMs(uint8_t attempt) const;

    bool validateSubscription(const Subscription &sub, WebPushResult &result) const;
    bool validateVapidKeys(WebPushResult &result);

    QueueHandle_t createQueue(size_t length, size_t itemSize, WebPushQueueMemory memory);
    QueueItem *allocateItem();
    void freeItem(QueueItem *item);

    void workerLoop();

    bool initCrypto();
    void deinitCrypto();

    std::string base64UrlEncode(const uint8_t *data, size_t len);
    std::string base64UrlEncode(const std::string &input);
    bool base64UrlDecode(const std::string &input, std::vector<uint8_t> &output);

    std::string generateVapidJWT(const std::string &aud,
                                 const std::string &sub,
                                 const std::string &vapidPrivateKeyBase64);

    std::vector<uint8_t> encryptPayload(const std::string &plaintext,
                                        const Subscription &sub,
                                        std::string &salt,
                                        std::string &publicServerKey);

    bool generateSalt(uint8_t *saltBin, std::string &saltOut);

    bool generateECDHContext(const std::vector<uint8_t> &userPubKey,
                             uint8_t *sharedSecret,
                             uint8_t *serverPubKey,
                             size_t &pubLen,
                             std::string &publicServerKey);

    bool deriveKeys(const uint8_t *authSecret,
                    size_t authSecretLen,
                    const uint8_t *salt,
                    const uint8_t *sharedSecret,
                    uint8_t *cek,
                    uint8_t *nonce,
                    const uint8_t *clientPubKey,
                    size_t clientPubKeyLen,
                    const uint8_t *serverPubKey,
                    size_t serverPubKeyLen);

    bool encryptWithAESGCM(const std::string &plaintext,
                           const uint8_t *cek,
                           const uint8_t *nonce,
                           std::vector<uint8_t> &ciphertextOut);

    bool isNetworkReadyForPush() const;
    WebPushResult sendPushRequest(const std::string &endpoint,
                                  const std::string &jwt,
                                  const std::string &salt,
                                  const std::string &serverPublicKey,
                                  const std::vector<uint8_t> &ciphertext);

    void printHeaderErr(esp_err_t headErr, const char *headKey) const;
    std::string endpointOrigin(const std::string &endpoint) const;

    std::string _vapidPublicKey{};
    std::string _vapidPrivateKey{};
    std::string _vapidEmail{};
    WebPushConfig _config{};

    ESPWorker _worker{};
    std::shared_ptr<WorkerHandler> _workerHandler{};
    QueueHandle_t _queue = nullptr;
    std::atomic<bool> _initialized{false};
    std::atomic<bool> _stopRequested{false};

    std::unique_ptr<CryptoState> _crypto{};
    std::mutex _cryptoMutex;
};

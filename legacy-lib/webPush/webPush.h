#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>
#include <core/worker/worker.h>
#include "jwtES256.h"

#include <string>
#include <vector>
#include <stdint.h>
#include <esp_log.h>
#include <esp_http_client.h>

#include <freertos/queue.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/cipher.h>
#include <mbedtls/entropy.h>
#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>
#include "notificationHandler/tags.h"

using webPushResultCB = std::function<void(int)>;

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

struct WebPushQueueItem {
    PushMessage* sub;
    webPushResultCB callback;
};

class WebPush {
   public:
    void init(
        const std::string& contactEmail,
        const std::string& publicKeyBase64,
        const std::string& privateKeyBase64
    );
    void send(PushMessage& msg, webPushResultCB callback);

   private:
    std::string vapidPublicKey;
    std::string vapidPrivateKey;
    std::string vapidEmail;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    bool cryptoInitialized = false;

    QueueHandle_t msgQueue = nullptr;

    void workerTask();
    void handleMessage(WebPushQueueItem& item);
    bool isNetworkReadyForPush();

    void printHeadErr(esp_err_t headErr, const char* headKey);
    void initCrypto();
    std::string base64UrlEncode(const uint8_t* data, size_t len);
    std::string base64UrlEncode(const std::string& input);
    std::vector<uint8_t> base64UrlDecode(const std::string& input);

    std::string generateVapidJWT(
        const std::string& aud,
        const std::string& sub,
        const std::string& vapidPrivateKeyBase64
    );

    std::vector<uint8_t> encryptPayload(
        const std::string& plaintext, const Subscription& sub,
        std::string& salt, std::string& publicServerKey
    );

    int sendPushRequest(
        const std::string& endpoint,
        const std::string& jwt,
        const std::string& salt,
        const std::string& serverPublicKey,
        const std::vector<uint8_t>& ciphertext
    );

    bool generateSalt(uint8_t* saltBin, std::string& saltOut, mbedtls_ctr_drbg_context& ctr_drbg);

    bool generateECDHContext(
        const std::vector<uint8_t>& userPubKey,
        mbedtls_ctr_drbg_context& ctr_drbg,
        uint8_t* sharedSecret, uint8_t* serverPubKey,
        size_t& pubLen,
        std::string& publicServerKey
    );
    
bool deriveKeys(
    const uint8_t* authSecret,
    size_t authSecretLen,
    const uint8_t* salt,
    const uint8_t* sharedSecret,
    uint8_t* cek,
    uint8_t* nonce,
    const uint8_t* clientPubKey,
    size_t clientPubKeyLen,
    const uint8_t* serverPubKey,
    size_t serverPubKeyLen
);

    bool encryptWithAESGCM(
        const std::string& plaintext,
        const uint8_t* cek,
        const uint8_t* nonce,
        std::vector<uint8_t>& ciphertextOut
    );

};

inline WebPush webPush;

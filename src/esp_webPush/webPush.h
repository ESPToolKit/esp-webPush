#pragma once

#if defined(ARDUINO)
#include <Arduino.h>
#else
#include <cstdint>
#endif
#include <ArduinoJson.h>

#include <array>
#include <atomic>
#include <ctime>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

extern "C" {
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
}

struct WebPushWorkerConfig {
	std::string name = "webpush";
	uint32_t stackSizeBytes = 4096;
	UBaseType_t priority = 3;
	BaseType_t coreId = tskNO_AFFINITY;
};

struct WebPushVapidConfig {
	std::string subject;
	std::string publicKeyBase64;
	std::string privateKeyBase64;
};

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

struct PushAction {
	std::string action;
	std::string title;
	std::optional<std::string> icon;
	std::optional<std::string> navigate;
};

struct PushPayload {
	std::string title;
	std::string body;
	std::optional<std::string> tag;
	std::optional<std::string> icon;
	std::optional<std::string> badge;
	std::optional<std::string> image;
	JsonDocument data;
	bool hasData = false;
	std::vector<PushAction> actions;
	std::optional<bool> renotify;
	std::optional<bool> requireInteraction;
	std::optional<bool> silent;
	std::optional<uint64_t> timestamp;
};

enum class WebPushQueueMemory : uint8_t { Any = 0, Internal, Psram };

enum class WebPushError : uint8_t {
	None = 0,
	NotInitialized,
	InvalidConfig,
	InvalidSubscription,
	InvalidPayload,
	InvalidVapidKeys,
	QueueFull,
	OutOfMemory,
	PayloadTooLarge,
	ShuttingDown,
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
		return error == WebPushError::None && transportError == ESP_OK && statusCode >= 200 &&
		       statusCode < 300;
	}

	explicit operator bool() const {
		return ok();
	}
};

struct WebPushEnqueueResult {
	WebPushError error = WebPushError::None;
	const char *message = nullptr;

	bool queued() const {
		return error == WebPushError::None;
	}

	explicit operator bool() const {
		return queued();
	}
};

using WebPushResultCB = std::function<void(WebPushResult result)>;
using WebPushNetworkValidator = std::function<bool()>;

struct WebPushConfig {
	WebPushWorkerConfig worker{};
	size_t queueLength = 32;
	WebPushQueueMemory queueMemory = WebPushQueueMemory::Psram;
	uint32_t enqueueTimeoutMs = 100;
	uint32_t requestTimeoutMs = 10000;
	uint32_t ttlSeconds = 2419200;
	uint8_t maxRetries = 5;
	uint32_t retryBaseDelayMs = 1500;
	uint32_t retryMaxDelayMs = 15000;
	size_t maxPayloadBytes = 3993;
	WebPushNetworkValidator networkValidator;
};

class ESPWebPush {
  public:
	ESPWebPush() = default;
	~ESPWebPush();

	bool init(const WebPushVapidConfig &vapidConfig, const WebPushConfig &config = WebPushConfig{});

	void deinit();
	bool isInitialized() const {
		return _initialized.load(std::memory_order_acquire);
	}

	WebPushEnqueueResult send(const PushMessage &msg, WebPushResultCB callback);
	WebPushResult send(const PushMessage &msg);
	WebPushEnqueueResult send(
	    const Subscription &sub, const PushPayload &payload, WebPushResultCB callback
	);
	WebPushResult send(const Subscription &sub, const PushPayload &payload);
	WebPushEnqueueResult send(
	    const Subscription &sub, const JsonDocument &payload, WebPushResultCB callback
	);
	WebPushResult send(const Subscription &sub, const JsonDocument &payload);
	WebPushEnqueueResult send(
	    const Subscription &sub, JsonVariantConst payload, WebPushResultCB callback
	);
	WebPushResult send(const Subscription &sub, JsonVariantConst payload);

	void setNetworkValidator(WebPushNetworkValidator validator);

	const char *errorToString(WebPushError error) const;

  private:
	struct QueueItem {
		PushMessage msg;
		WebPushResultCB callback;
	};

	struct JwtCacheEntry {
		std::string aud;
		std::string token;
		time_t exp = 0;
		uint32_t lastUsedTick = 0;
	};

	struct CryptoState;
	struct CryptoDeleter {
		void operator()(CryptoState *state) const;
	};

	WebPushResult handleMessage(const PushMessage &msg);
	WebPushEnqueueResult enqueueResultForError(WebPushError error) const;
	WebPushResult resultForError(WebPushError error) const;
	bool shouldRetry(const WebPushResult &result) const;
	uint32_t calcRetryDelayMs(uint8_t attempt) const;
	bool waitForStopAwareDelay(uint32_t delayMs) const;

	bool validateSubscription(const Subscription &sub, WebPushResult &result) const;
	bool validatePayloadSize(const std::string &payload, WebPushResult &result) const;
	bool validateMessage(const PushMessage &msg, WebPushResult &result) const;
	bool validateVapidSubject(WebPushResult &result) const;
	bool validateVapidKeys(WebPushResult &result);
	bool buildMessage(
	    const Subscription &sub,
	    const PushPayload &payload,
	    PushMessage &message,
	    WebPushResult &result
	) const;
	bool buildMessage(
	    const Subscription &sub,
	    JsonVariantConst payload,
	    PushMessage &message,
	    WebPushResult &result
	) const;
	WebPushResult invalidPayloadResult() const;

	QueueHandle_t createQueue(size_t length, size_t itemSize, WebPushQueueMemory memory);
	QueueItem *allocateItem();
	void freeItem(QueueItem *item);

	static void workerLoopThunk(void *arg);
	void workerLoop();
	void failPendingQueueItems(WebPushError error);

	bool initCrypto();
	void deinitCrypto();

	std::string base64UrlEncode(const uint8_t *data, size_t len);
	std::string base64UrlEncode(const std::string &input);
	bool base64UrlDecode(const std::string &input, std::vector<uint8_t> &output) const;

	std::string generateVapidJWT(const std::string &aud, time_t &expOut);
	std::string jwtForAudience(const std::string &aud);

	bool decodeP256PublicKey(const std::string &keyBase64, std::vector<uint8_t> &output) const;
	bool decodeP256PrivateKey(const std::string &keyBase64, std::vector<uint8_t> &output) const;
	bool deriveP256PublicKey(
	    const std::vector<uint8_t> &privateKey, std::vector<uint8_t> &publicKeyOut
	) const;
	bool deriveSharedSecret(
	    const std::vector<uint8_t> &peerPublicKey,
	    const std::vector<uint8_t> &privateKey,
	    uint8_t *sharedSecret
	);
	bool deriveInputKeyingMaterial(
	    const uint8_t *authSecret,
	    size_t authSecretLen,
	    const uint8_t *sharedSecret,
	    const uint8_t *clientPubKey,
	    size_t clientPubKeyLen,
	    const uint8_t *serverPubKey,
	    size_t serverPubKeyLen,
	    uint8_t *ikm
	) const;
	bool deriveContentEncryptionKeyAndNonce(
	    const uint8_t *salt, const uint8_t *ikm, uint8_t *cek, uint8_t *nonce
	) const;
	bool buildRecordBody(
	    const uint8_t *salt,
	    uint32_t recordSize,
	    const uint8_t *serverPubKey,
	    size_t serverPubKeyLen,
	    const std::string &plaintext,
	    const uint8_t *cek,
	    const uint8_t *nonce,
	    std::vector<uint8_t> &bodyOut
	);

	std::vector<uint8_t> encryptPayload(
	    const std::string &plaintext,
	    const Subscription &sub
	);

	bool generateSalt(uint8_t *saltBin);

	bool generateECDHContext(
	    const std::vector<uint8_t> &privateKey,
	    std::vector<uint8_t> &publicKeyOut
	);

	bool encryptWithAESGCM(
	    const std::string &plaintext,
	    const uint8_t *cek,
	    const uint8_t *nonce,
	    std::vector<uint8_t> &ciphertextOut
	);

	bool isNetworkReadyForPush() const;
	WebPushResult sendPushRequest(
	    const std::string &endpoint, const std::string &jwt, const std::vector<uint8_t> &body
	);

	void printHeaderErr(esp_err_t headErr, const char *headKey) const;
	std::string endpointOrigin(const std::string &endpoint) const;

	static constexpr uint32_t kDefaultRecordSize = 4010;
	static constexpr size_t kJwtCacheSize = 4;

	WebPushVapidConfig _vapidConfig{};
	WebPushConfig _config{};

	std::atomic<TaskHandle_t> _workerTask{nullptr};
	QueueHandle_t _queue = nullptr;
	std::atomic<bool> _initialized{false};
	std::atomic<bool> _stopRequested{false};
	std::atomic<bool> _deinitRequested{false};

	std::unique_ptr<CryptoState, CryptoDeleter> _crypto{};
	std::mutex _cryptoMutex;
	mutable std::mutex _jwtCacheMutex;
	mutable std::mutex _networkValidatorMutex;
	WebPushNetworkValidator _networkValidator{};
	std::array<JwtCacheEntry, kJwtCacheSize> _jwtCache{};
};

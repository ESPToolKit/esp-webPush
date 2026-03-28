#include "webPush.h"
#include "webPush_payload.h"

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
constexpr TickType_t kStopDelaySliceTicks = pdMS_TO_TICKS(50);

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
} // namespace

ESPWebPush::~ESPWebPush() {
	deinit();
}

bool ESPWebPush::init(const WebPushVapidConfig &vapidConfig, const WebPushConfig &config) {
	WebPushJoinStatus stopStatus = deinit();
	if (stopStatus == WebPushJoinStatus::Timeout) {
		ESP_LOGE(kTag, "init: previous worker did not stop in time");
		return false;
	}

	if (vapidConfig.subject.empty() || vapidConfig.publicKeyBase64.empty() ||
	    vapidConfig.privateKeyBase64.empty()) {
		ESP_LOGE(kTag, "init: missing VAPID subject or keys");
		return false;
	}

	if (config.queueLength == 0) {
		ESP_LOGE(kTag, "init: queue length must be > 0");
		return false;
	}

	_config = config;
	_vapidConfig = vapidConfig;
	setNetworkValidator(config.networkValidator);

	if (_config.worker.name.empty()) {
		_config.worker.name = "webpush";
	}

	WebPushResult configCheck{};
	if (!validateVapidSubject(configCheck) || !validateVapidKeys(configCheck)) {
		ESP_LOGE(
		    kTag,
		    "init: invalid VAPID config (%s)",
		    configCheck.message ? configCheck.message : "unknown"
		);
		return false;
	}

	_queue = createQueue(_config.queueLength, sizeof(QueueItem *), _config.queueMemory);
	if (!_queue) {
		ESP_LOGE(kTag, "init: failed to create queue");
		return false;
	}

	_deinitRequested.store(false, std::memory_order_release);
	_stopRequested.store(false, std::memory_order_release);

	TaskHandle_t workerTask = nullptr;
	const char *taskName = _config.worker.name.empty() ? "webpush" : _config.worker.name.c_str();
	const BaseType_t created = xTaskCreatePinnedToCore(
	    &ESPWebPush::workerLoopThunk,
	    taskName,
	    _config.worker.stackSizeBytes,
	    this,
	    _config.worker.priority,
	    &workerTask,
	    _config.worker.coreId
	);
	if (created != pdPASS) {
		ESP_LOGE(kTag, "init: failed to start worker task");
		_workerTask.store(nullptr, std::memory_order_release);
		vQueueDelete(_queue);
		_queue = nullptr;
		return false;
	}

	_workerTask.store(workerTask, std::memory_order_release);
	_initialized.store(true, std::memory_order_release);
	ESP_LOGI(kTag, "ESPWebPush initialized");
	return true;
}

void ESPWebPush::requestStop() {
	_stopRequested.store(true, std::memory_order_release);
	_deinitRequested.store(true, std::memory_order_release);
	_initialized.store(false, std::memory_order_release);

	TaskHandle_t workerTask = _workerTask.load(std::memory_order_acquire);
	if (workerTask != nullptr && _queue != nullptr) {
		QueueItem *wake = nullptr;
		(void)xQueueSend(_queue, &wake, 0);
	}
}

WebPushJoinStatus ESPWebPush::join(uint32_t timeoutMs) {
	TaskHandle_t workerTask = _workerTask.load(std::memory_order_acquire);
	if (workerTask == nullptr) {
		if (_queue != nullptr) {
			(void)cleanupAfterWorkerStop();
			return WebPushJoinStatus::Completed;
		}
		return WebPushJoinStatus::NotRunning;
	}

	if (xTaskGetCurrentTaskHandle() == workerTask) {
		return WebPushJoinStatus::Timeout;
	}

	const TickType_t start = xTaskGetTickCount();
	const TickType_t timeoutTicks = pdMS_TO_TICKS(timeoutMs);
	while (_workerTask.load(std::memory_order_acquire) != nullptr) {
		if ((xTaskGetTickCount() - start) >= timeoutTicks) {
			return WebPushJoinStatus::Timeout;
		}
		vTaskDelay(pdMS_TO_TICKS(10));
	}

	(void)cleanupAfterWorkerStop();
	return WebPushJoinStatus::Completed;
}

WebPushJoinStatus ESPWebPush::deinit(uint32_t timeoutMs) {
	requestStop();

	WebPushJoinStatus status = join(timeoutMs);
	if (status == WebPushJoinStatus::Timeout) {
		return status;
	}

	(void)cleanupAfterWorkerStop();
	return status;
}

bool ESPWebPush::cleanupAfterWorkerStop() {
	if (_workerTask.load(std::memory_order_acquire) != nullptr) {
		return false;
	}

	if (_deinitRequested.load(std::memory_order_acquire)) {
		failPendingQueueItems(WebPushError::ShuttingDown);
	}

	if (_queue) {
		vQueueDelete(_queue);
		_queue = nullptr;
	}

	deinitCrypto();

	{
		std::lock_guard<std::mutex> guard(_jwtCacheMutex);
		_jwtCache = {};
	}

	_vapidConfig = WebPushVapidConfig{};
	setNetworkValidator(WebPushNetworkValidator{});
	_config = WebPushConfig{};
	_stopRequested.store(false, std::memory_order_release);
	_deinitRequested.store(false, std::memory_order_release);
	return true;
}

WebPushEnqueueResult ESPWebPush::send(const PushMessage &msg, WebPushResultCB callback) {
	if (_stopRequested.load(std::memory_order_acquire)) {
		ESP_LOGW(kTag, "send: shutting down");
		return enqueueResultForError(WebPushError::ShuttingDown);
	}

	if (!isInitialized() || !_queue) {
		ESP_LOGW(kTag, "send: not initialized");
		return enqueueResultForError(WebPushError::NotInitialized);
	}

	WebPushResult validation{};
	if (!validateMessage(msg, validation)) {
		ESP_LOGW(
		    kTag,
		    "send: preflight validation failed (%s)",
		    validation.message ? validation.message : "unknown"
		);
		return enqueueResultForError(validation.error);
	}

	QueueItem *item = allocateItem();
	if (!item) {
		ESP_LOGW(kTag, "send: out of memory");
		return enqueueResultForError(WebPushError::OutOfMemory);
	}

	item->msg = msg;
	item->callback = std::move(callback);

	QueueItem *payload = item;
	TickType_t waitTicks = pdMS_TO_TICKS(_config.enqueueTimeoutMs);
	if (xQueueSend(_queue, &payload, waitTicks) != pdTRUE) {
		ESP_LOGW(kTag, "send: queue full");
		freeItem(item);
		if (_stopRequested.load(std::memory_order_acquire)) {
			return enqueueResultForError(WebPushError::ShuttingDown);
		}
		return enqueueResultForError(WebPushError::QueueFull);
	}

	return enqueueResultForError(WebPushError::None);
}

WebPushResult ESPWebPush::send(const PushMessage &msg) {
	if (_stopRequested.load(std::memory_order_acquire)) {
		return resultForError(WebPushError::ShuttingDown);
	}
	if (!isInitialized()) {
		return resultForError(WebPushError::NotInitialized);
	}
	return handleMessage(msg);
}

WebPushEnqueueResult ESPWebPush::send(
    const WebPushSubscription &subscription, const PushPayload &payload, WebPushResultCB callback
) {
	PushMessage message;
	WebPushResult result{};
	if (!buildMessage(subscription, payload, message, result)) {
		return enqueueResultForError(result.error);
	}
	return send(message, std::move(callback));
}

WebPushResult ESPWebPush::send(
    const WebPushSubscription &subscription, const PushPayload &payload
) {
	if (_stopRequested.load(std::memory_order_acquire)) {
		return resultForError(WebPushError::ShuttingDown);
	}
	if (!isInitialized()) {
		return resultForError(WebPushError::NotInitialized);
	}

	PushMessage message;
	WebPushResult result{};
	if (!buildMessage(subscription, payload, message, result)) {
		return result;
	}
	return send(message);
}

WebPushEnqueueResult ESPWebPush::send(
    const WebPushSubscription &subscription, const JsonDocument &payload, WebPushResultCB callback
) {
	return send(subscription, payload.as<JsonVariantConst>(), std::move(callback));
}

WebPushResult ESPWebPush::send(
    const WebPushSubscription &subscription, const JsonDocument &payload
) {
	return send(subscription, payload.as<JsonVariantConst>());
}

WebPushEnqueueResult ESPWebPush::send(
    const WebPushSubscription &subscription, JsonVariantConst payload, WebPushResultCB callback
) {
	PushMessage message;
	WebPushResult result{};
	if (!buildMessage(subscription, payload, message, result)) {
		return enqueueResultForError(result.error);
	}
	return send(message, std::move(callback));
}

WebPushResult ESPWebPush::send(
    const WebPushSubscription &subscription, JsonVariantConst payload
) {
	if (_stopRequested.load(std::memory_order_acquire)) {
		return resultForError(WebPushError::ShuttingDown);
	}
	if (!isInitialized()) {
		return resultForError(WebPushError::NotInitialized);
	}

	PushMessage message;
	WebPushResult result{};
	if (!buildMessage(subscription, payload, message, result)) {
		return result;
	}
	return send(message);
}

void ESPWebPush::setNetworkValidator(WebPushNetworkValidator validator) {
	std::lock_guard<std::mutex> guard(_networkValidatorMutex);
	_networkValidator = std::move(validator);
	_config.networkValidator = _networkValidator;
}

WebPushEnqueueResult ESPWebPush::enqueueResultForError(WebPushError error) const {
	WebPushEnqueueResult result{};
	result.error = error;
	result.message = errorToString(error);
	return result;
}

WebPushResult ESPWebPush::resultForError(WebPushError error) const {
	WebPushResult result{};
	result.error = error;
	result.message = errorToString(error);
	return result;
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
	case WebPushError::InvalidPayload:
		return "invalid payload";
	case WebPushError::InvalidVapidKeys:
		return "invalid VAPID keys";
	case WebPushError::QueueFull:
		return "queue full";
	case WebPushError::OutOfMemory:
		return "out of memory";
	case WebPushError::PayloadTooLarge:
		return "payload too large";
	case WebPushError::ShuttingDown:
		return "shutting down";
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

WebPushResult ESPWebPush::invalidPayloadResult() const {
	WebPushResult result{};
	result.error = WebPushError::InvalidPayload;
	result.message = errorToString(result.error);
	return result;
}

bool ESPWebPush::buildMessage(
    const WebPushSubscription &subscription,
    const PushPayload &payload,
    PushMessage &message,
    WebPushResult &result
) const {
	std::string serializedPayload;
	const char *payloadError = serializePushPayload(payload, serializedPayload);
	if (payloadError != nullptr) {
		ESP_LOGW(kTag, "send: %s", payloadError);
		result = invalidPayloadResult();
		return false;
	}

	message.subscription = subscription;
	message.payload = std::move(serializedPayload);
	return true;
}

bool ESPWebPush::buildMessage(
    const WebPushSubscription &subscription,
    JsonVariantConst payload,
    PushMessage &message,
    WebPushResult &result
) const {
	std::string serializedPayload;
	const char *payloadError = validateAndSerializePushPayload(payload, serializedPayload);
	if (payloadError != nullptr) {
		ESP_LOGW(kTag, "send: %s", payloadError);
		result = invalidPayloadResult();
		return false;
	}

	message.subscription = subscription;
	message.payload = std::move(serializedPayload);
	return true;
}

WebPushResult ESPWebPush::handleMessage(const PushMessage &msg) {
	WebPushResult result{};
	if (!validateMessage(msg, result)) {
		return result;
	}

	for (uint8_t attempt = 0; attempt <= _config.maxRetries; ++attempt) {
		if (_stopRequested.load(std::memory_order_acquire)) {
			return resultForError(WebPushError::ShuttingDown);
		}

		if (!isNetworkReadyForPush()) {
			result.error = WebPushError::NetworkUnavailable;
			result.message = errorToString(result.error);
			if (attempt >= _config.maxRetries) {
				return result;
			}
			if (!waitForStopAwareDelay(calcRetryDelayMs(attempt))) {
				return resultForError(WebPushError::ShuttingDown);
			}
			continue;
		}

		std::vector<uint8_t> body = encryptPayload(msg.payload, msg.subscription);
		if (body.empty()) {
			result.error = WebPushError::EncryptFailed;
			result.message = errorToString(result.error);
			return result;
		}

		const std::string aud = endpointOrigin(msg.subscription.endpoint);
		const std::string jwt = jwtForAudience(aud);
		if (jwt.empty()) {
			result.error = WebPushError::JwtFailed;
			result.message = errorToString(result.error);
			return result;
		}

		WebPushResult request = sendPushRequest(msg.subscription.endpoint, jwt, body);
		if (request.ok()) {
			return request;
		}

		result = request;
		if (!shouldRetry(request) || attempt >= _config.maxRetries) {
			return result;
		}

		if (!waitForStopAwareDelay(calcRetryDelayMs(attempt))) {
			return resultForError(WebPushError::ShuttingDown);
		}
	}

	result.error = WebPushError::InternalError;
	result.message = errorToString(result.error);
	return result;
}

bool ESPWebPush::isNetworkReadyForPush() const {
	WebPushNetworkValidator validator;
	{
		std::lock_guard<std::mutex> guard(_networkValidatorMutex);
		validator = _networkValidator;
	}

	if (!validator) {
		return true;
	}

	return validator();
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

bool ESPWebPush::waitForStopAwareDelay(uint32_t delayMs) const {
	if (delayMs == 0) {
		return !_stopRequested.load(std::memory_order_acquire);
	}

	TickType_t remaining = pdMS_TO_TICKS(delayMs);
	while (remaining > 0) {
		if (_stopRequested.load(std::memory_order_acquire)) {
			return false;
		}
		TickType_t slice = remaining > kStopDelaySliceTicks ? kStopDelaySliceTicks : remaining;
		vTaskDelay(slice);
		remaining -= slice;
	}

	return !_stopRequested.load(std::memory_order_acquire);
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

bool ESPWebPush::validateSubscription(
    const WebPushSubscription &subscription, WebPushResult &result
) const {
	if (subscription.endpoint.empty() || subscription.p256dh.empty() || subscription.auth.empty()) {
		result.error = WebPushError::InvalidSubscription;
		result.message = errorToString(result.error);
		return false;
	}
	return true;
}

bool ESPWebPush::validatePayloadSize(const std::string &payload, WebPushResult &result) const {
	if (_config.maxPayloadBytes != 0 && payload.size() > _config.maxPayloadBytes) {
		result.error = WebPushError::PayloadTooLarge;
		result.message = errorToString(result.error);
		return false;
	}
	return true;
}

bool ESPWebPush::validateMessage(const PushMessage &msg, WebPushResult &result) const {
	if (!validateSubscription(msg.subscription, result)) {
		return false;
	}
	return validatePayloadSize(msg.payload, result);
}

bool ESPWebPush::validateVapidSubject(WebPushResult &result) const {
	if (_vapidConfig.subject.rfind("mailto:", 0) == 0 ||
	    _vapidConfig.subject.rfind("https://", 0) == 0) {
		return true;
	}
	result.error = WebPushError::InvalidConfig;
	result.message = errorToString(result.error);
	return false;
}

bool ESPWebPush::validateVapidKeys(WebPushResult &result) {
	std::vector<uint8_t> pubKey;
	std::vector<uint8_t> privKey;
	if (!decodeP256PublicKey(_vapidConfig.publicKeyBase64, pubKey) ||
	    !decodeP256PrivateKey(_vapidConfig.privateKeyBase64, privKey)) {
		result.error = WebPushError::InvalidVapidKeys;
		result.message = errorToString(result.error);
		return false;
	}

	std::vector<uint8_t> derivedPublicKey;
	if (!deriveP256PublicKey(privKey, derivedPublicKey) || derivedPublicKey != pubKey) {
		result.error = WebPushError::InvalidVapidKeys;
		result.message = errorToString(result.error);
		return false;
	}

	return true;
}

QueueHandle_t ESPWebPush::createQueue(size_t length, size_t itemSize, WebPushQueueMemory memory) {
	(void)memory;
#if defined(ESP_IDF_VERSION) && !defined(ARDUINO)
	uint32_t caps = capsForMemory(memory);
	QueueHandle_t queue = xQueueCreateWithCaps(length, itemSize, caps);
	if (!queue && caps != MALLOC_CAP_DEFAULT) {
		queue = xQueueCreateWithCaps(length, itemSize, MALLOC_CAP_DEFAULT);
	}
	if (!queue) {
		queue = xQueueCreate(length, itemSize);
	}
	return queue;
#else
	return xQueueCreate(length, itemSize);
#endif
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

void ESPWebPush::failPendingQueueItems(WebPushError error) {
	if (!_queue) {
		return;
	}

	WebPushResult result = resultForError(error);
	QueueItem *item = nullptr;
	while (xQueueReceive(_queue, &item, 0) == pdTRUE) {
		if (!item) {
			continue;
		}
		if (item->callback) {
			item->callback(result);
		}
		freeItem(item);
	}
}

void ESPWebPush::workerLoop() {
	while (true) {
		if (_stopRequested.load(std::memory_order_acquire)) {
			break;
		}

		QueueItem *item = nullptr;
		if (xQueueReceive(_queue, &item, kWorkerPollTicks) != pdTRUE) {
			continue;
		}
		if (!item) {
			if (_stopRequested.load(std::memory_order_acquire)) {
				break;
			}
			continue;
		}

		WebPushResult result = handleMessage(item->msg);
		if (item->callback) {
			item->callback(result);
		}
		freeItem(item);
	}

	_workerTask.store(nullptr, std::memory_order_release);
	vTaskDelete(nullptr);
}

void ESPWebPush::workerLoopThunk(void *arg) {
	auto *self = static_cast<ESPWebPush *>(arg);
	if (!self) {
		vTaskDelete(nullptr);
		return;
	}
	self->workerLoop();
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

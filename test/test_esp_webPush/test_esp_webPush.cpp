#include <Arduino.h>
#include <ArduinoJson.h>

#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#define private public
#include <ESPWebPush.h>
#undef private

#include <unity.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace {

constexpr const char *kSubject = "mailto:notify@example.com";
constexpr const char *kAltSubject = "https://www.esptoolkit.hu/contact";
constexpr const char *kSenderPublicKey =
    "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
constexpr const char *kSenderPrivateKey = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
constexpr const char *kReceiverPublicKey =
    "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
constexpr const char *kReceiverPrivateKey = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
constexpr const char *kAuthSecret = "BTBZMqHH6r4Tts7J_aSIgg";
constexpr const char *kSalt = "DGv6ra1nlYgDCS1FRnbzlw";
constexpr const char *kExpectedSharedSecret = "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs";
constexpr const char *kExpectedIkm = "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg";
constexpr const char *kExpectedCek = "oIhVW04MRdy2XN9CiKLxTg";
constexpr const char *kExpectedNonce = "4h_95klXJ5E_qnoN";
constexpr const char *kExpectedBody =
    "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";
constexpr const char *kPlaintext = "When I grow up, I want to be a watermelon";

WebPushVapidConfig testVapidConfig() {
	WebPushVapidConfig cfg{};
	cfg.subject = kSubject;
	cfg.publicKeyBase64 = kSenderPublicKey;
	cfg.privateKeyBase64 = kSenderPrivateKey;
	return cfg;
}

WebPushConfig testConfig() {
	WebPushConfig cfg{};
	cfg.queueLength = 2;
	cfg.queueMemory = WebPushQueueMemory::Internal;
	cfg.worker.stackSizeBytes = 4096;
	cfg.worker.priority = 2;
	cfg.worker.name = "wp-test";
	cfg.requestTimeoutMs = 200;
	return cfg;
}

Subscription testSubscription() {
	Subscription sub{};
	sub.endpoint = "https://example.com/push";
	sub.p256dh = kReceiverPublicKey;
	sub.auth = kAuthSecret;
	return sub;
}

PushPayload testPayload() {
	PushPayload payload;
	payload.title = "Hello";
	payload.body = "World";
	return payload;
}

bool waitForFlag(std::atomic<bool> &flag, uint32_t timeoutMs) {
	const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeoutMs);
	while (!flag.load() && xTaskGetTickCount() < deadline) {
		vTaskDelay(pdMS_TO_TICKS(10));
	}
	return flag.load();
}

void test_deinit_is_safe_before_init() {
	ESPWebPush webPush;
	TEST_ASSERT_FALSE(webPush.isInitialized());

	webPush.deinit();
	TEST_ASSERT_FALSE(webPush.isInitialized());
}

void test_deinit_is_idempotent() {
	ESPWebPush webPush;
	TEST_ASSERT_TRUE(webPush.init(testVapidConfig(), testConfig()));
	TEST_ASSERT_TRUE(webPush.isInitialized());

	webPush.deinit();
	TEST_ASSERT_FALSE(webPush.isInitialized());

	webPush.deinit();
	TEST_ASSERT_FALSE(webPush.isInitialized());
}

void test_reinit_after_deinit() {
	ESPWebPush webPush;
	TEST_ASSERT_TRUE(webPush.init(testVapidConfig(), testConfig()));
	TEST_ASSERT_TRUE(webPush.isInitialized());
	webPush.deinit();
	TEST_ASSERT_FALSE(webPush.isInitialized());

	WebPushVapidConfig alt = testVapidConfig();
	alt.subject = kAltSubject;
	TEST_ASSERT_TRUE(webPush.init(alt, testConfig()));
	TEST_ASSERT_TRUE(webPush.isInitialized());
	webPush.deinit();
}

void test_destructor_deinits_active_instance() {
	{
		ESPWebPush first;
		TEST_ASSERT_TRUE(first.init(testVapidConfig(), testConfig()));
		TEST_ASSERT_TRUE(first.isInitialized());
	}

	ESPWebPush second;
	TEST_ASSERT_TRUE(second.init(testVapidConfig(), testConfig()));
	TEST_ASSERT_TRUE(second.isInitialized());
	second.deinit();
}

void test_invalid_subject_rejected() {
	ESPWebPush webPush;
	WebPushVapidConfig bad = testVapidConfig();
	bad.subject = "notify@example.com";
	TEST_ASSERT_FALSE(webPush.init(bad, testConfig()));
}

void test_mismatched_vapid_keys_rejected() {
	ESPWebPush webPush;
	WebPushVapidConfig bad = testVapidConfig();
	bad.publicKeyBase64 = kReceiverPublicKey;
	TEST_ASSERT_FALSE(webPush.init(bad, testConfig()));
}

void test_push_payload_rejects_missing_required_fields() {
	ESPWebPush webPush;
	TEST_ASSERT_TRUE(webPush.init(testVapidConfig(), testConfig()));

	PushPayload payload;
	payload.title = "Hello";

	WebPushResult result = webPush.send(testSubscription(), payload);
	TEST_ASSERT_EQUAL(
	    static_cast<int>(WebPushError::InvalidPayload),
	    static_cast<int>(result.error)
	);

	webPush.deinit();
}

void test_json_document_rejects_unknown_top_level_keys() {
	ESPWebPush webPush;
	TEST_ASSERT_TRUE(webPush.init(testVapidConfig(), testConfig()));

	JsonDocument doc;
	doc["title"] = "Hello";
	doc["body"] = "World";
	doc["unexpected"] = true;

	WebPushResult result = webPush.send(testSubscription(), doc);
	TEST_ASSERT_EQUAL(
	    static_cast<int>(WebPushError::InvalidPayload),
	    static_cast<int>(result.error)
	);

	webPush.deinit();
}

void test_json_variant_rejects_wrong_types() {
	ESPWebPush webPush;
	TEST_ASSERT_TRUE(webPush.init(testVapidConfig(), testConfig()));

	JsonDocument doc;
	doc["title"] = "Hello";
	doc["body"] = 42;

	WebPushResult result = webPush.send(testSubscription(), doc.as<JsonVariantConst>());
	TEST_ASSERT_EQUAL(
	    static_cast<int>(WebPushError::InvalidPayload),
	    static_cast<int>(result.error)
	);

	webPush.deinit();
}

void test_async_invalid_payload_returns_enqueue_error_without_callback() {
	ESPWebPush webPush;
	TEST_ASSERT_TRUE(webPush.init(testVapidConfig(), testConfig()));

	bool callbackCalled = false;
	JsonDocument doc;
	doc["title"] = "Hello";

	WebPushEnqueueResult enqueue = webPush.send(testSubscription(), doc, [&](WebPushResult) {
		callbackCalled = true;
	});

	TEST_ASSERT_FALSE(enqueue.queued());
	TEST_ASSERT_EQUAL(
	    static_cast<int>(WebPushError::InvalidPayload),
	    static_cast<int>(enqueue.error)
	);
	TEST_ASSERT_FALSE(callbackCalled);

	webPush.deinit();
}

void test_payload_limit_is_enforced_for_raw_messages() {
	ESPWebPush webPush;
	TEST_ASSERT_TRUE(webPush.init(testVapidConfig(), testConfig()));

	PushMessage fits{};
	fits.sub = testSubscription();
	fits.payload.assign(3993, 'a');

	PushMessage tooLarge = fits;
	tooLarge.payload.push_back('b');

	WebPushResult fitResult = webPush.send(fits);
	TEST_ASSERT_NOT_EQUAL(
	    static_cast<int>(WebPushError::PayloadTooLarge),
	    static_cast<int>(fitResult.error)
	);

	WebPushResult largeResult = webPush.send(tooLarge);
	TEST_ASSERT_EQUAL(
	    static_cast<int>(WebPushError::PayloadTooLarge),
	    static_cast<int>(largeResult.error)
	);

	webPush.deinit();
}

void test_payload_limit_can_be_disabled() {
	ESPWebPush webPush;
	WebPushConfig cfg = testConfig();
	cfg.maxPayloadBytes = 0;
	cfg.networkValidator = []() { return false; };
	cfg.maxRetries = 0;
	TEST_ASSERT_TRUE(webPush.init(testVapidConfig(), cfg));

	PushMessage msg{};
	msg.sub = testSubscription();
	msg.payload.assign(5000, 'x');

	WebPushResult result = webPush.send(msg);
	TEST_ASSERT_EQUAL(
	    static_cast<int>(WebPushError::NetworkUnavailable),
	    static_cast<int>(result.error)
	);

	webPush.deinit();
}

void test_network_validator_false_short_circuits_send() {
	ESPWebPush webPush;
	WebPushConfig cfg = testConfig();
	cfg.networkValidator = []() { return false; };
	cfg.maxRetries = 0;
	TEST_ASSERT_TRUE(webPush.init(testVapidConfig(), cfg));

	WebPushResult result = webPush.send(testSubscription(), testPayload());
	TEST_ASSERT_EQUAL(
	    static_cast<int>(WebPushError::NetworkUnavailable),
	    static_cast<int>(result.error)
	);

	webPush.deinit();
}

void test_missing_network_validator_does_not_force_network_unavailable() {
	ESPWebPush webPush;
	TEST_ASSERT_TRUE(webPush.init(testVapidConfig(), testConfig()));

	WebPushResult result = webPush.send(testSubscription(), testPayload());
	TEST_ASSERT_NOT_EQUAL(
	    static_cast<int>(WebPushError::NetworkUnavailable),
	    static_cast<int>(result.error)
	);

	webPush.deinit();
}

void test_network_validator_can_be_replaced_after_init() {
	ESPWebPush webPush;
	WebPushConfig cfg = testConfig();
	cfg.networkValidator = []() { return false; };
	cfg.maxRetries = 0;
	TEST_ASSERT_TRUE(webPush.init(testVapidConfig(), cfg));

	WebPushResult blocked = webPush.send(testSubscription(), testPayload());
	TEST_ASSERT_EQUAL(
	    static_cast<int>(WebPushError::NetworkUnavailable),
	    static_cast<int>(blocked.error)
	);

	webPush.setNetworkValidator([]() { return true; });
	WebPushResult allowed = webPush.send(testSubscription(), testPayload());
	TEST_ASSERT_NOT_EQUAL(
	    static_cast<int>(WebPushError::NetworkUnavailable),
	    static_cast<int>(allowed.error)
	);

	webPush.deinit();
}

void test_async_queued_message_invokes_callback_once() {
	ESPWebPush webPush;
	WebPushConfig cfg = testConfig();
	cfg.networkValidator = []() { return false; };
	cfg.maxRetries = 0;
	TEST_ASSERT_TRUE(webPush.init(testVapidConfig(), cfg));

	std::atomic<bool> callbackDone{false};
	int callbackCount = 0;
	WebPushError callbackError = WebPushError::None;

	WebPushEnqueueResult enqueue = webPush.send(testSubscription(), testPayload(), [&](WebPushResult result) {
		++callbackCount;
		callbackError = result.error;
		callbackDone.store(true);
	});

	TEST_ASSERT_TRUE(enqueue.queued());
	TEST_ASSERT_TRUE(waitForFlag(callbackDone, 1000));
	TEST_ASSERT_EQUAL(1, callbackCount);
	TEST_ASSERT_EQUAL(
	    static_cast<int>(WebPushError::NetworkUnavailable),
	    static_cast<int>(callbackError)
	);

	webPush.deinit();
}

void test_deinit_fails_pending_queue_items_with_shutting_down() {
	ESPWebPush webPush;
	WebPushConfig cfg = testConfig();
	cfg.queueLength = 4;
	cfg.networkValidator = []() { return false; };
	cfg.maxRetries = 6;
	cfg.retryBaseDelayMs = 200;
	cfg.retryMaxDelayMs = 200;
	TEST_ASSERT_TRUE(webPush.init(testVapidConfig(), cfg));

	std::atomic<bool> firstCalled{false};
	std::atomic<bool> secondCalled{false};
	WebPushError firstError = WebPushError::None;
	WebPushError secondError = WebPushError::None;

	WebPushEnqueueResult first = webPush.send(testSubscription(), testPayload(), [&](WebPushResult result) {
		firstError = result.error;
		firstCalled.store(true);
	});
	WebPushEnqueueResult second = webPush.send(testSubscription(), testPayload(), [&](WebPushResult result) {
		secondError = result.error;
		secondCalled.store(true);
	});

	TEST_ASSERT_TRUE(first.queued());
	TEST_ASSERT_TRUE(second.queued());

	vTaskDelay(pdMS_TO_TICKS(20));
	webPush.deinit();

	TEST_ASSERT_TRUE(waitForFlag(firstCalled, 1000));
	TEST_ASSERT_TRUE(waitForFlag(secondCalled, 1000));
	TEST_ASSERT_EQUAL(
	    static_cast<int>(WebPushError::ShuttingDown),
	    static_cast<int>(firstError)
	);
	TEST_ASSERT_EQUAL(
	    static_cast<int>(WebPushError::ShuttingDown),
	    static_cast<int>(secondError)
	);
}

void test_rfc8291_key_derivation_matches_appendix_a() {
	ESPWebPush webPush;
	TEST_ASSERT_TRUE(webPush.initCrypto());

	std::vector<uint8_t> authSecret;
	std::vector<uint8_t> senderPrivate;
	std::vector<uint8_t> senderPublic;
	std::vector<uint8_t> receiverPublic;
	std::vector<uint8_t> salt;
	uint8_t sharedSecret[32];
	uint8_t ikm[32];
	uint8_t cek[16];
	uint8_t nonce[12];

	TEST_ASSERT_TRUE(webPush.base64UrlDecode(kAuthSecret, authSecret));
	TEST_ASSERT_TRUE(webPush.base64UrlDecode(kSenderPrivateKey, senderPrivate));
	TEST_ASSERT_TRUE(webPush.base64UrlDecode(kSalt, salt));
	TEST_ASSERT_TRUE(webPush.decodeP256PublicKey(kSenderPublicKey, senderPublic));
	TEST_ASSERT_TRUE(webPush.decodeP256PublicKey(kReceiverPublicKey, receiverPublic));
	TEST_ASSERT_TRUE(webPush.deriveSharedSecret(receiverPublic, senderPrivate, sharedSecret));
	TEST_ASSERT_TRUE(webPush.deriveInputKeyingMaterial(
	    authSecret.data(),
	    authSecret.size(),
	    sharedSecret,
	    receiverPublic.data(),
	    receiverPublic.size(),
	    senderPublic.data(),
	    senderPublic.size(),
	    ikm));
	TEST_ASSERT_TRUE(webPush.deriveContentEncryptionKeyAndNonce(salt.data(), ikm, cek, nonce));

	TEST_ASSERT_EQUAL_STRING(
	    kExpectedSharedSecret,
	    webPush.base64UrlEncode(sharedSecret, sizeof(sharedSecret)).c_str()
	);
	TEST_ASSERT_EQUAL_STRING(
	    kExpectedIkm,
	    webPush.base64UrlEncode(ikm, sizeof(ikm)).c_str()
	);
	TEST_ASSERT_EQUAL_STRING(
	    kExpectedCek,
	    webPush.base64UrlEncode(cek, sizeof(cek)).c_str()
	);
	TEST_ASSERT_EQUAL_STRING(
	    kExpectedNonce,
	    webPush.base64UrlEncode(nonce, sizeof(nonce)).c_str()
	);

	webPush.deinitCrypto();
}

void test_rfc8291_body_matches_example() {
	ESPWebPush webPush;

	std::vector<uint8_t> salt;
	std::vector<uint8_t> senderPublic;
	uint8_t cek[16];
	uint8_t nonce[12];
	std::vector<uint8_t> cekBytes;
	std::vector<uint8_t> nonceBytes;
	std::vector<uint8_t> body;

	TEST_ASSERT_TRUE(webPush.base64UrlDecode(kSalt, salt));
	TEST_ASSERT_TRUE(webPush.decodeP256PublicKey(kSenderPublicKey, senderPublic));
	TEST_ASSERT_TRUE(webPush.base64UrlDecode(kExpectedCek, cekBytes));
	TEST_ASSERT_TRUE(webPush.base64UrlDecode(kExpectedNonce, nonceBytes));
	memcpy(cek, cekBytes.data(), sizeof(cek));
	memcpy(nonce, nonceBytes.data(), sizeof(nonce));

	TEST_ASSERT_TRUE(webPush.buildRecordBody(
	    salt.data(),
	    4096,
	    senderPublic.data(),
	    senderPublic.size(),
	    kPlaintext,
	    cek,
	    nonce,
	    body));

	TEST_ASSERT_EQUAL_STRING(kExpectedBody, webPush.base64UrlEncode(body.data(), body.size()).c_str());
}

} // namespace

void setUp() {
}
void tearDown() {
}

void setup() {
	delay(2000);
	UNITY_BEGIN();
	RUN_TEST(test_deinit_is_safe_before_init);
	RUN_TEST(test_deinit_is_idempotent);
	RUN_TEST(test_reinit_after_deinit);
	RUN_TEST(test_destructor_deinits_active_instance);
	RUN_TEST(test_invalid_subject_rejected);
	RUN_TEST(test_mismatched_vapid_keys_rejected);
	RUN_TEST(test_push_payload_rejects_missing_required_fields);
	RUN_TEST(test_json_document_rejects_unknown_top_level_keys);
	RUN_TEST(test_json_variant_rejects_wrong_types);
	RUN_TEST(test_async_invalid_payload_returns_enqueue_error_without_callback);
	RUN_TEST(test_payload_limit_is_enforced_for_raw_messages);
	RUN_TEST(test_payload_limit_can_be_disabled);
	RUN_TEST(test_network_validator_false_short_circuits_send);
	RUN_TEST(test_missing_network_validator_does_not_force_network_unavailable);
	RUN_TEST(test_network_validator_can_be_replaced_after_init);
	RUN_TEST(test_async_queued_message_invokes_callback_once);
	RUN_TEST(test_deinit_fails_pending_queue_items_with_shutting_down);
	RUN_TEST(test_rfc8291_key_derivation_matches_appendix_a);
	RUN_TEST(test_rfc8291_body_matches_example);
	UNITY_END();
}

void loop() {
	vTaskDelay(pdMS_TO_TICKS(1000));
}

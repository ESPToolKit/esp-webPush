#include <Arduino.h>
#include <ArduinoJson.h>
#include <ESPWebPush.h>
#include <unity.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace {

constexpr const char *kContact = "notify@example.com";
constexpr const char *kPublicKey =
    "BAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0A";
constexpr const char *kPrivateKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";

WebPushConfig testConfig() {
	WebPushConfig cfg{};
	cfg.queueLength = 2;
	cfg.queueMemory = WebPushQueueMemory::Internal;
	cfg.worker.stackSizeBytes = 4096;
	cfg.worker.priority = 2;
	cfg.worker.name = "wp-test";
	return cfg;
}

Subscription testSubscription() {
	Subscription sub{};
	sub.endpoint = "https://example.com/push";
	sub.p256dh = "invalid-p256dh";
	sub.auth = "invalid-auth";
	return sub;
}

PushPayload testPayload() {
	PushPayload payload{};
	payload.title = "Hello";
	payload.body = "World";
	return payload;
}

void test_deinit_is_safe_before_init() {
	ESPWebPush webPush;
	TEST_ASSERT_FALSE(webPush.isInitialized());

	webPush.deinit();
	TEST_ASSERT_FALSE(webPush.isInitialized());
}

void test_deinit_is_idempotent() {
	ESPWebPush webPush;
	TEST_ASSERT_TRUE(webPush.init(kContact, kPublicKey, kPrivateKey, testConfig()));
	TEST_ASSERT_TRUE(webPush.isInitialized());

	webPush.deinit();
	TEST_ASSERT_FALSE(webPush.isInitialized());

	webPush.deinit();
	TEST_ASSERT_FALSE(webPush.isInitialized());
}

void test_reinit_after_deinit() {
	ESPWebPush webPush;
	TEST_ASSERT_TRUE(webPush.init(kContact, kPublicKey, kPrivateKey, testConfig()));
	TEST_ASSERT_TRUE(webPush.isInitialized());
	webPush.deinit();
	TEST_ASSERT_FALSE(webPush.isInitialized());

	TEST_ASSERT_TRUE(webPush.init(kContact, kPublicKey, kPrivateKey, testConfig()));
	TEST_ASSERT_TRUE(webPush.isInitialized());
	webPush.deinit();
}

void test_destructor_deinits_active_instance() {
	{
		ESPWebPush first;
		TEST_ASSERT_TRUE(first.init(kContact, kPublicKey, kPrivateKey, testConfig()));
		TEST_ASSERT_TRUE(first.isInitialized());
	}

	ESPWebPush second;
	TEST_ASSERT_TRUE(second.init(kContact, kPublicKey, kPrivateKey, testConfig()));
	TEST_ASSERT_TRUE(second.isInitialized());
	second.deinit();
}

void test_push_payload_rejects_missing_required_fields() {
	ESPWebPush webPush;
	TEST_ASSERT_TRUE(webPush.init(kContact, kPublicKey, kPrivateKey, testConfig()));

	PushPayload payload{};
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
	TEST_ASSERT_TRUE(webPush.init(kContact, kPublicKey, kPrivateKey, testConfig()));

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
	TEST_ASSERT_TRUE(webPush.init(kContact, kPublicKey, kPrivateKey, testConfig()));

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

void test_async_invalid_payload_reports_failure_without_enqueue() {
	ESPWebPush webPush;
	TEST_ASSERT_TRUE(webPush.init(kContact, kPublicKey, kPrivateKey, testConfig()));

	bool callbackCalled = false;
	WebPushError callbackError = WebPushError::None;
	JsonDocument doc;
	doc["title"] = "Hello";

	bool queued = webPush.send(testSubscription(), doc, [&](WebPushResult result) {
		callbackCalled = true;
		callbackError = result.error;
	});

	TEST_ASSERT_FALSE(queued);
	TEST_ASSERT_TRUE(callbackCalled);
	TEST_ASSERT_EQUAL(
	    static_cast<int>(WebPushError::InvalidPayload),
	    static_cast<int>(callbackError)
	);

	webPush.deinit();
}

void test_network_validator_false_short_circuits_send() {
	ESPWebPush webPush;
	WebPushConfig cfg = testConfig();
	cfg.networkValidator = []() { return false; };
	TEST_ASSERT_TRUE(webPush.init(kContact, kPublicKey, kPrivateKey, cfg));

	WebPushResult result = webPush.send(testSubscription(), testPayload());
	TEST_ASSERT_EQUAL(
	    static_cast<int>(WebPushError::NetworkUnavailable),
	    static_cast<int>(result.error)
	);

	webPush.deinit();
}

void test_missing_network_validator_does_not_force_network_unavailable() {
	ESPWebPush webPush;
	TEST_ASSERT_TRUE(webPush.init(kContact, kPublicKey, kPrivateKey, testConfig()));

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
	TEST_ASSERT_TRUE(webPush.init(kContact, kPublicKey, kPrivateKey, cfg));

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
	RUN_TEST(test_push_payload_rejects_missing_required_fields);
	RUN_TEST(test_json_document_rejects_unknown_top_level_keys);
	RUN_TEST(test_json_variant_rejects_wrong_types);
	RUN_TEST(test_async_invalid_payload_reports_failure_without_enqueue);
	RUN_TEST(test_network_validator_false_short_circuits_send);
	RUN_TEST(test_missing_network_validator_does_not_force_network_unavailable);
	RUN_TEST(test_network_validator_can_be_replaced_after_init);
	UNITY_END();
}

void loop() {
	vTaskDelay(pdMS_TO_TICKS(1000));
}

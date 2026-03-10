#include <Arduino.h>
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
	cfg.requireNetworkReady = false;
	cfg.worker.stackSizeBytes = 4096;
	cfg.worker.priority = 2;
	cfg.worker.name = "wp-test";
	return cfg;
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
	UNITY_END();
}

void loop() {
	vTaskDelay(pdMS_TO_TICKS(1000));
}

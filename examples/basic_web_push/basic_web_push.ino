#include <Arduino.h>
#include <ESPWebPush.h>

ESPWebPush webPush;
bool tornDown = false;
uint32_t teardownAtMs = 0;

void setup() {
	Serial.begin(115200);
	delay(200);

	WebPushConfig cfg;
	cfg.queueLength = 8;
	cfg.queueMemory = WebPushQueueMemory::Psram;
	cfg.worker.stackSizeBytes = 16 * 1024;
	cfg.worker.priority = 3;
	cfg.worker.name = "webpush";
	cfg.networkValidator = []() {
		// Replace with your own Wi-Fi/Ethernet readiness check.
		return true;
	};

	webPush.init(
	    "notify@example.com",
	    "BAvapidPublicKeyBase64Url...",
	    "vapidPrivateKeyBase64Url...",
	    cfg
	);

	Subscription sub;
	sub.endpoint = "https://fcm.googleapis.com/fcm/send/...";
	sub.p256dh = "BMEp256dhBase64Url...";
	sub.auth = "authSecretBase64Url...";

	PushPayload payload;
	payload.title = "Hello";
	payload.body = "ESP32";
	payload.tag = "basic-demo";
	payload.icon = "https://www.esptoolkit.hu/icon.png";

	webPush.send(sub, payload, [](WebPushResult result) {
		if (!result.ok()) {
			Serial.printf(
			    "[webpush] async failed: %s (status %d)\n",
			    result.message ? result.message : "unknown",
			    result.statusCode
			);
			return;
		}
		Serial.printf("[webpush] async ok: %d\n", result.statusCode);
	});

	JsonDocument jsonPayload;
	jsonPayload["title"] = "Hello";
	jsonPayload["body"] = "ESP32";
	jsonPayload["tag"] = "basic-demo";

	WebPushResult syncResult = webPush.send(sub, jsonPayload);
	if (!syncResult.ok()) {
		Serial.printf(
		    "[webpush] sync failed: %s\n",
		    syncResult.message ? syncResult.message : "unknown"
		);
	} else {
		Serial.printf("[webpush] sync ok: %d\n", syncResult.statusCode);
	}

	teardownAtMs = millis() + 5000;
}

void loop() {
	if (!tornDown && webPush.isInitialized() && teardownAtMs != 0 && millis() >= teardownAtMs) {
		webPush.deinit();
		tornDown = true;
	}
	vTaskDelay(pdMS_TO_TICKS(1000));
}

#include <Arduino.h>
#include <ESPWebPush.h>

ESPWebPush webPush;

void setup() {
    Serial.begin(115200);
    delay(200);

    WebPushConfig cfg;
    cfg.queueLength = 8;
    cfg.queueMemory = WebPushQueueMemory::Psram;
    cfg.worker.stackSizeBytes = 16 * 1024;
    cfg.worker.priority = 3;
    cfg.worker.name = "webpush";

    webPush.init(
        "notify@example.com",
        "BAvapidPublicKeyBase64Url...",
        "vapidPrivateKeyBase64Url...",
        cfg);

    Subscription sub;
    sub.endpoint = "https://fcm.googleapis.com/fcm/send/...";
    sub.p256dh = "BMEp256dhBase64Url...";
    sub.auth = "authSecretBase64Url...";

    PushMessage msg;
    msg.sub = sub;
    msg.payload = "{\"title\":\"Hello\",\"body\":\"ESP32\"}";

    webPush.send(msg, [](WebPushResult result) {
        if (!result.ok()) {
            Serial.printf("[webpush] async failed: %s (status %d)\n",
                          result.message ? result.message : "unknown",
                          result.statusCode);
            return;
        }
        Serial.printf("[webpush] async ok: %d\n", result.statusCode);
    });

    WebPushResult syncResult = webPush.send(msg);
    if (!syncResult.ok()) {
        Serial.printf("[webpush] sync failed: %s\n",
                      syncResult.message ? syncResult.message : "unknown");
    } else {
        Serial.printf("[webpush] sync ok: %d\n", syncResult.statusCode);
    }
}

void loop() {
    vTaskDelay(pdMS_TO_TICKS(1000));
}

# ESPWebPush

ESPWebPush is an **async-first** Web Push sender for ESP32 firmware. It handles VAPID JWT signing, Web Push AES-GCM payload encryption, and HTTP delivery so your devices can notify browsers without extra glue code.

ArduinoJson v7+ is a required dependency for the structured payload API.

## CI / Release / License
[![CI](https://github.com/ESPToolKit/esp-webPush/actions/workflows/ci.yml/badge.svg)](https://github.com/ESPToolKit/esp-webPush/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ESPToolKit/esp-webPush?sort=semver)](https://github.com/ESPToolKit/esp-webPush/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

## Features
- VAPID JWT signing (ES256) from base64url private key.
- Web Push AES-GCM payload encryption.
- Async queue + worker task via native FreeRTOS APIs.
- Optional synchronous `send()` API.
- Strict `PushPayload` validation for browser notification fields.
- ArduinoJson v7+ overloads for validated `JsonDocument` / `JsonVariantConst` payloads.
- Configurable queue length, memory caps (internal vs PSRAM), stack, priority, retries, and timeouts.
- Optional application-provided network validator callback.
- Uses the standard Web Push headers (`Authorization`, `Crypto-Key`, `Encryption`, `TTL`).

## Quick Start

```cpp
#include <Arduino.h>
#include <ESPWebPush.h>

ESPWebPush webPush;

void setup() {
    Serial.begin(115200);

    WebPushConfig cfg;
    cfg.queueLength = 16;
    cfg.queueMemory = WebPushQueueMemory::Psram;
    cfg.worker.stackSizeBytes = 16 * 1024;
    cfg.worker.priority = 3;
    cfg.worker.name = "webpush";
    cfg.networkValidator = []() { return true; };

    webPush.init(
        "notify@example.com",
        "BAvapidPublicKeyBase64Url...",
        "vapidPrivateKeyBase64Url...",
        cfg);
}

void loop() {}
```

## Usage

### Subscription / Structured Payload

```cpp
Subscription sub;
sub.endpoint = "https://fcm.googleapis.com/fcm/send/...";
sub.p256dh = "BME...";  // base64url from browser subscription
sub.auth = "nsa...";    // base64url from browser subscription

PushPayload payload;
payload.title = "Hello";
payload.body = "ESP32";
payload.tag = "demo";
payload.icon = "https://example.com/icon.png";
```

### Async Send

```cpp
bool started = webPush.send(sub, payload, [](WebPushResult result) {
    if (!result.ok()) {
        ESP_LOGE("WEBPUSH", "Push failed: %s (status %d)",
                 result.message, result.statusCode);
        return;
    }
    ESP_LOGI("WEBPUSH", "Push OK (status %d)", result.statusCode);
});

if (!started) {
    ESP_LOGW("WEBPUSH", "Queue full or not initialized");
}
```

### ArduinoJson v7+ Send

```cpp
JsonDocument doc;
doc["title"] = "Hello";
doc["body"] = "ESP32";
doc["tag"] = "demo";

WebPushResult result = webPush.send(sub, doc);
```

### Sync Send

```cpp
WebPushResult result = webPush.send(sub, payload);
if (!result.ok()) {
    ESP_LOGW("WEBPUSH", "Sync push failed: %s", result.message);
}
```

### Legacy Raw JSON Payload

```cpp
PushMessage msg;
msg.sub = sub;
msg.payload = "{\"title\":\"Hello\",\"body\":\"ESP32\"}";

// Raw payload strings remain supported, but they are not schema-validated.
WebPushResult result = webPush.send(msg);
```

### Teardown

```cpp
if (webPush.isInitialized()) {
    webPush.deinit();
}
```

## Configuration

`WebPushConfig` lets you tune the worker and queue:

- `queueLength` – number of queued messages.
- `queueMemory` – `Internal`, `Psram`, or `Any`.
- `worker` – stack size, priority, core id, PSRAM stack usage.
- `requestTimeoutMs` – HTTP timeout.
- `ttlSeconds` – Web Push TTL header.
- `maxRetries`, `retryBaseDelayMs`, `retryMaxDelayMs` – retry/backoff controls.
- `networkValidator` – optional callback for application-defined network readiness checks.

## Gotchas
- **System time is required** for VAPID JWT expiration. Ensure SNTP is synced.
- Web Push endpoints require TLS; `esp_http_client` must be built with TLS support.
- `aesgcm` content encoding is used to match existing Web Push payloads.
- Structured payload inputs reject unknown top-level keys and invalid field types.

## API Reference (Core)

- `bool init(contactEmail, publicKeyBase64, privateKeyBase64, config)`
- `bool send(const PushMessage&, WebPushResultCB cb)` (async)
- `WebPushResult send(const PushMessage&)` (sync)
- `bool send(const Subscription&, const PushPayload&, WebPushResultCB cb)` / `WebPushResult send(const Subscription&, const PushPayload&)`
- `bool send(const Subscription&, const JsonDocument&, WebPushResultCB cb)` / `WebPushResult send(const Subscription&, const JsonDocument&)`
- `bool send(const Subscription&, JsonVariantConst, WebPushResultCB cb)` / `WebPushResult send(const Subscription&, JsonVariantConst)`
- `void setNetworkValidator(WebPushNetworkValidator)`
- `void deinit()` / `bool isInitialized() const`
- `const char* errorToString(WebPushError)`

## Restrictions
- ESP32-class targets only (Arduino + ESP-IDF).
- Requires C++17, ArduinoJson v7+, and mbedTLS.
- Do not call from ISR context.

## Tests
Host-side tests are disabled. Use the `examples/` sketches with PlatformIO or Arduino CLI.

## Formatting Baseline

This repository follows the firmware formatting baseline from `esptoolkit-template`:
- `.clang-format` is the source of truth for C/C++/INO layout.
- `.editorconfig` enforces tabs (`tab_width = 4`), LF endings, and final newline.
- Format all tracked firmware sources with `bash scripts/format_cpp.sh`.

## License
MIT — see [LICENSE.md](LICENSE.md).

## ESPToolKit
- Check out other libraries: <https://github.com/orgs/ESPToolKit/repositories>
- Hang out on Discord: <https://discord.gg/WG8sSqAy>
- Support the project: <https://ko-fi.com/esptoolkit>
- Visit the website: <https://www.esptoolkit.hu/>

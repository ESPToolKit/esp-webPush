# ESPWebPush

ESPWebPush is the future home for Web Push helpers on ESP32: VAPID key handling, payload encryption, and subscription management so firmware can send notifications to browsers without hosting extra glue code. The implementation has not shipped yet—the repository is a placeholder while the API takes shape.

## CI / Release / License
[![CI](https://github.com/ESPToolKit/esp-webPush/actions/workflows/ci.yml/badge.svg)](https://github.com/ESPToolKit/esp-webPush/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ESPToolKit/esp-webPush?sort=semver)](https://github.com/ESPToolKit/esp-webPush/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

## Features
Planned capabilities:
- VAPID key generation/storage plus helper functions to sign requests.
- Payload encryption using the Web Push AEAD scheme (elliptic curve Diffie-Hellman + AES-GCM).
- Subscription registry that keeps endpoints, auth secrets, and expirations in sync with ESPJsonDB.
- Async delivery built on ESPFetch so notifications do not block application code.

## Examples
Examples will land with the first release. Expect sketches that:
- Enrol a device with your backend, exchange VAPID public keys, and store subscriptions locally.
- Encrypt and POST push payloads to Mozilla/Google endpoints.
- Handle error responses (expired subscriptions, rate limits) gracefully.

## Gotchas
- Everything here is pre-release; the headers are placeholders.
- Web Push requires TLS and elliptic curve cryptography support, so the final API will depend on ESP-IDF features that may not exist on every chip revision.
- Until documented otherwise, assume breaking changes can happen at any time.

## API Reference
Coming soon once the primitives stabilise. The rough layout will include:
- `ESPWebPush::init` to inject storage + HTTP clients.
- `registerSubscription`, `removeSubscription`, `listSubscriptions` helpers.
- `sendNotification(const Subscription&, Payload payload, Options opts)` built on top of ESPFetch/ESPWorker.

## Restrictions
- The first release will target ESP32 (Arduino + ESP-IDF) with ArduinoJson for payload preparation.
- Requires C++17 and a TLS-capable HTTP stack (ESPFetch or native WiFiClientSecure usage).
- Web Push servers enforce strict quotas—production firmware must handle retries/backoff.

## Tests
Automated tests will show up together with the actual implementation. They will include host-side crypto vectors plus integration tests against mock push endpoints. Contributions with early test harness ideas are welcome—open an issue to coordinate.

## License
MIT — see [LICENSE.md](LICENSE.md).

## ESPToolKit
- Check out other libraries: <https://github.com/orgs/ESPToolKit/repositories>
- Hang out on Discord: <https://discord.gg/WG8sSqAy>
- Support the project: <https://ko-fi.com/esptoolkit>

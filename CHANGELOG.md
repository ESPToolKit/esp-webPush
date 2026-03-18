# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Core ESPWebPush implementation: VAPID JWT signing, AES-GCM payload encryption, and HTTP delivery.
- Async queue + worker task with configurable stack, priority, queue length, and memory caps.
- Sync `send()` API returning structured `WebPushResult`.
- Retry/backoff handling for network/transport failures.
- Basic example sketch and CI workflows.
- Teardown lifecycle tests for pre-init `deinit()`, idempotent `deinit()`, re-init, and destructor teardown.
- Strict `PushPayload` API with typed notification fields and ArduinoJson v7+ overloads.
- User-provided network validator callback support.

### Changed
- Teardown contract now uses `isInitialized()` and removes the old `initialized()` naming.
- `deinit()` now always converges teardown, including worker/queue/crypto cleanup and runtime config/key release.
- Structured payload inputs now reject unknown fields, missing required fields, and invalid types before enqueue/send.
- ArduinoJson v7+ is now an explicit dependency.

### Notes
- JWT signing requires a valid system clock (SNTP).
- Content encoding uses `aesgcm` with VAPID headers (`Authorization`, `Crypto-Key`, `Encryption`).
- Worker configuration now uses `WebPushWorkerConfig` with native FreeRTOS task creation.

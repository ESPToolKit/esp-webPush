# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Core ESPWebPush implementation: VAPID JWT signing, AES-GCM payload encryption, and HTTP delivery.
- Async queue + worker task with configurable stack, priority, queue length, and memory caps.
- Sync `send()` API returning structured `WebPushResult`.
- Retry/backoff handling for network/transport failures.
- Basic example sketch and CI workflows.

### Notes
- JWT signing requires a valid system clock (SNTP).
- Content encoding uses `aesgcm` with VAPID headers (`Authorization`, `Crypto-Key`, `Encryption`).
- Updated worker configuration examples to use `WorkerConfig::stackSizeBytes` (ESPWorker API rename).

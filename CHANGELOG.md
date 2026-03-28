# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed
- Breaking: renamed the public transport struct from `Subscription` to `WebPushSubscription` everywhere with no compatibility alias.
- Breaking: renamed `PushMessage.sub` to `PushMessage.subscription` for API consistency.
- Breaking: removed app-level metadata fields `deviceId`, `disabledTags`, and `deleted` from the transport struct.
- `validateSubscription()` now validates only the required Web Push transport fields: `endpoint`, `p256dh`, and `auth`.

## [2.0.0] - 2026-03-28

### Added
- `WebPushVapidConfig` with standards-based `subject`, public key, and private key inputs.
- `WebPushEnqueueResult` for async preflight / queue outcomes.
- `WebPushJoinStatus` plus `requestStop()` / `join(timeoutMs)` for bounded worker shutdown.
- RFC 8291 Appendix A key-derivation and encrypted-body test coverage.
- Payload-size guard with the RFC-safe default limit of 3993 bytes.
- Small per-origin JWT cache for VAPID header reuse.

### Changed
- Reworked encryption and transport to use RFC 8188 / RFC 8291 `aes128gcm` only.
- `init()` now validates `mailto:` / `https://` VAPID subjects and verifies that the configured public key matches the private key.
- Async `send()` overloads now return `WebPushEnqueueResult` and only invoke callbacks for queued work.
- `deinit()` now returns `WebPushJoinStatus` and uses a bounded stop/join flow instead of waiting forever.
- JWT payload assembly now uses dynamic `std::string` construction instead of a fixed stack buffer.
- Structured and raw payload sends now enforce the payload-size guard before transport.
- README, example sketch, package metadata, and CI now describe the v2 API and drop stale `esp-worker` references.
- CI push triggers now include `feature/**` branches so v2 work runs workflows before merge.
- `library.json` now advertises both Arduino and ESP-IDF compatibility.
- Package metadata now reports the breaking release as `2.0.0`.

### Notes
- JWT signing still requires a valid system clock (SNTP).
- Push sends use `Content-Encoding: aes128gcm` with VAPID `Authorization`.
- Breaking changes in v2 include the new `init()` signature, async enqueue return type, bounded shutdown API, and RFC 8291-only protocol behavior.

# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- `WebPushVapidConfig` with standards-based `subject`, public key, and private key inputs.
- `WebPushEnqueueResult` for async preflight / queue outcomes.
- RFC 8291 Appendix A key-derivation and encrypted-body test coverage.
- Payload-size guard with the RFC-safe default limit of 3993 bytes.
- Small per-origin JWT cache for VAPID header reuse.

### Changed
- Reworked encryption and transport to use RFC 8188 / RFC 8291 `aes128gcm` only.
- `init()` now validates `mailto:` / `https://` VAPID subjects and verifies that the configured public key matches the private key.
- Async `send()` overloads now return `WebPushEnqueueResult` and only invoke callbacks for queued work.
- `deinit()` now shuts down cooperatively and resolves queued-but-unprocessed items with `WebPushError::ShuttingDown`.
- Structured and raw payload sends now enforce the payload-size guard before transport.
- README, example sketch, package metadata, and CI now describe the v2 API and drop stale `esp-worker` references.
- CI push triggers now include `feature/**` branches so v2 work runs workflows before merge.
- `library.json` now advertises both Arduino and ESP-IDF compatibility.

### Notes
- JWT signing still requires a valid system clock (SNTP).
- Push sends use `Content-Encoding: aes128gcm` with VAPID `Authorization`.
- `deinit()` can block until an in-flight HTTP request or user callback completes.

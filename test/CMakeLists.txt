# Host-side tests are disabled because ESPWebPush depends on ESP-IDF
# networking and mbedTLS primitives that are unavailable on the host toolchain.
message(STATUS "ESPWebPush: tests are disabled for the host build.")

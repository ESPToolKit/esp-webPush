#pragma once

#include <Arduino.h>
#include <string>
#include <vector>

#define ES256_TAG "JWT_ES256"

class JWT_ES256 {
   public:
    std::string base64UrlEncode(const std::vector<uint8_t>& input);
    std::string base64UrlEncode(const std::string& input);
    std::string base64Normalize(const std::string& urlEncoded);
    std::string sign(const std::string& aud, const std::string& sub,
                     const std::string& privateKeyBase64, unsigned long expSecs);
};

inline JWT_ES256 jwtES256;
#pragma once

#include <ArduinoJson.h>

#include <string>

#include "webPush.h"

const char *serializePushPayload(const PushPayload &payload, std::string &jsonOut);
const char *validateAndSerializePushPayload(JsonVariantConst payload, std::string &jsonOut);

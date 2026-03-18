#include "webPush_payload.h"

#include <cstring>

namespace {
constexpr const char *kPayloadMustBeObject = "payload must be a JSON object";
constexpr const char *kPayloadTitleRequired = "payload.title must be a non-empty string";
constexpr const char *kPayloadBodyRequired = "payload.body must be a non-empty string";
constexpr const char *kPayloadUnknownField = "payload contains an unknown field";
constexpr const char *kPayloadInvalidStringField = "payload contains an invalid string field";
constexpr const char *kPayloadInvalidBoolField = "payload contains an invalid bool field";
constexpr const char *kPayloadInvalidTimestamp = "payload.timestamp must be an integer";
constexpr const char *kPayloadInvalidData = "payload.data must be an object or array";
constexpr const char *kPayloadInvalidActions = "payload.actions must be an array";
constexpr const char *kPayloadInvalidAction = "payload.actions[] must be an object";
constexpr const char *kPayloadUnknownActionField = "payload.actions[] contains an unknown field";
constexpr const char *kPayloadActionInvalidString = "payload.actions[] has an invalid string field";
constexpr const char *kPayloadSerializeFailed = "payload serialization failed";

bool isKnownPayloadKey(const char *key) {
	return strcmp(key, "title") == 0 || strcmp(key, "body") == 0 || strcmp(key, "tag") == 0 ||
	       strcmp(key, "icon") == 0 || strcmp(key, "badge") == 0 ||
	       strcmp(key, "image") == 0 || strcmp(key, "data") == 0 ||
	       strcmp(key, "actions") == 0 || strcmp(key, "renotify") == 0 ||
	       strcmp(key, "requireInteraction") == 0 || strcmp(key, "silent") == 0 ||
	       strcmp(key, "timestamp") == 0;
}

bool isKnownActionKey(const char *key) {
	return strcmp(key, "action") == 0 || strcmp(key, "title") == 0 || strcmp(key, "icon") == 0 ||
	       strcmp(key, "navigate") == 0;
}

const char *validateActionObject(JsonObjectConst actionObject) {
	for (JsonPairConst pair : actionObject) {
		if (!isKnownActionKey(pair.key().c_str())) {
			return kPayloadUnknownActionField;
		}
	}

	JsonVariantConst action = actionObject["action"];
	JsonVariantConst title = actionObject["title"];
	if (!action.is<const char *>() || action.as<const char *>() == nullptr ||
	    strlen(action.as<const char *>()) == 0) {
		return kPayloadActionInvalidString;
	}
	if (!title.is<const char *>() || title.as<const char *>() == nullptr ||
	    strlen(title.as<const char *>()) == 0) {
		return kPayloadActionInvalidString;
	}

	for (const char *key : {"icon", "navigate"}) {
		JsonVariantConst value = actionObject[key];
		if (!value.isNull() && !value.is<const char *>()) {
			return kPayloadActionInvalidString;
		}
	}

	return nullptr;
}
} // namespace

const char *validateAndSerializePushPayload(JsonVariantConst payload, std::string &jsonOut) {
	if (!payload.is<JsonObjectConst>()) {
		return kPayloadMustBeObject;
	}

	JsonObjectConst object = payload.as<JsonObjectConst>();
	for (JsonPairConst pair : object) {
		if (!isKnownPayloadKey(pair.key().c_str())) {
			return kPayloadUnknownField;
		}
	}

	JsonVariantConst title = object["title"];
	if (!title.is<const char *>() || title.as<const char *>() == nullptr ||
	    strlen(title.as<const char *>()) == 0) {
		return kPayloadTitleRequired;
	}

	JsonVariantConst body = object["body"];
	if (!body.is<const char *>() || body.as<const char *>() == nullptr ||
	    strlen(body.as<const char *>()) == 0) {
		return kPayloadBodyRequired;
	}

	for (const char *key : {"tag", "icon", "badge", "image"}) {
		JsonVariantConst value = object[key];
		if (!value.isNull() && !value.is<const char *>()) {
			return kPayloadInvalidStringField;
		}
	}

	for (const char *key : {"renotify", "requireInteraction", "silent"}) {
		JsonVariantConst value = object[key];
		if (!value.isNull() && !value.is<bool>()) {
			return kPayloadInvalidBoolField;
		}
	}

	JsonVariantConst timestamp = object["timestamp"];
	if (!timestamp.isNull() && !timestamp.is<int64_t>() && !timestamp.is<uint64_t>()) {
		return kPayloadInvalidTimestamp;
	}

	JsonVariantConst data = object["data"];
	if (!data.isNull() && !data.is<JsonObjectConst>() && !data.is<JsonArrayConst>()) {
		return kPayloadInvalidData;
	}

	JsonVariantConst actions = object["actions"];
	if (!actions.isNull()) {
		if (!actions.is<JsonArrayConst>()) {
			return kPayloadInvalidActions;
		}

		for (JsonVariantConst actionValue : actions.as<JsonArrayConst>()) {
			if (!actionValue.is<JsonObjectConst>()) {
				return kPayloadInvalidAction;
			}
			const char *actionError = validateActionObject(actionValue.as<JsonObjectConst>());
			if (actionError != nullptr) {
				return actionError;
			}
		}
	}

	jsonOut.clear();
	if (serializeJson(payload, jsonOut) == 0) {
		return kPayloadSerializeFailed;
	}

	return nullptr;
}

const char *serializePushPayload(const PushPayload &payload, std::string &jsonOut) {
	JsonDocument doc;
	doc["title"] = payload.title;
	doc["body"] = payload.body;

	if (payload.tag.has_value()) {
		doc["tag"] = payload.tag->c_str();
	}
	if (payload.icon.has_value()) {
		doc["icon"] = payload.icon->c_str();
	}
	if (payload.badge.has_value()) {
		doc["badge"] = payload.badge->c_str();
	}
	if (payload.image.has_value()) {
		doc["image"] = payload.image->c_str();
	}
	if (payload.hasData) {
		doc["data"] = payload.data.as<JsonVariantConst>();
	}
	if (!payload.actions.empty()) {
		JsonArray actions = doc["actions"].to<JsonArray>();
		for (const PushAction &action : payload.actions) {
			JsonObject actionObject = actions.add<JsonObject>();
			actionObject["action"] = action.action;
			actionObject["title"] = action.title;
			if (action.icon.has_value()) {
				actionObject["icon"] = action.icon->c_str();
			}
			if (action.navigate.has_value()) {
				actionObject["navigate"] = action.navigate->c_str();
			}
		}
	}
	if (payload.renotify.has_value()) {
		doc["renotify"] = *payload.renotify;
	}
	if (payload.requireInteraction.has_value()) {
		doc["requireInteraction"] = *payload.requireInteraction;
	}
	if (payload.silent.has_value()) {
		doc["silent"] = *payload.silent;
	}
	if (payload.timestamp.has_value()) {
		doc["timestamp"] = *payload.timestamp;
	}

	return validateAndSerializePushPayload(doc.as<JsonVariantConst>(), jsonOut);
}

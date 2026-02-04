# WebPush

## Áttekintés
A `webPush` modul VAPID alapú Web Push értesítések küldését valósítja meg. Titkosítja a payloadot és HTTP kérést küld a push szolgáltató felé.

## Fő elemek
- VAPID kulcspár és JWT (`jwtES256`).
- AES-GCM titkosítás, ECDH kulcscsere.
- Üzenetsor (queue) és worker task.

## Adatmodellek
- `Subscription`: endpoint + kulcsok.
- `PushMessage`: subscription + payload.

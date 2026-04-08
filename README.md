# iobroker.ankersolix3
iobroker Adapter zum Auslesen von Anker Solix Solarbank 3

Der Adapter baut eine Realtime Trigger Verbindung zur Anker Cloud auf. Wenn die Solarbank 3 aktiv und online ist, wird sie durch den regelmäßigen Trigger veranlasst, kontinuierlich alle ca. 3s ihre Daten in die Cloud zu senden. Der Adapter abonniert diesen Cloud MQTT-Dienst und empfängt so die Realtime Daten direkt in iobroker.

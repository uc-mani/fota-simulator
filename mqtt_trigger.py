import paho.mqtt.publish as publish

MQTT_BROKER = "localhost"
MQTT_TOPIC = "device/update"

publish.single(MQTT_TOPIC, "start", hostname=MQTT_BROKER)
print("Sent update trigger.")

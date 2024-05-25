import paho.mqtt.client as mqtt
import requests, json

# Configuration du broker MQTT
MQTT_BROKER_HOST = '194.57.103.203'
MQTT_BROKER_PORT = 1883
MQTT_KEEPALIVE_INTERVAL = 60


def start_mqtt_client():
    mqtt_client = mqtt.Client()

    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))
        # Abonnez-vous aux topics MQTT ici
        mqtt_client.subscribe("projet/mahmoud")

    def on_message(client, userdata, msg):
        print(msg.topic+" "+str(msg.payload))
        # Traitez les messages MQTT ici
        # Par exemple, vous pouvez les passer directement à une fonction de l'API Flask
        handle_mqtt_message(msg.payload)

    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message

    mqtt_client.connect(MQTT_BROKER_HOST, MQTT_BROKER_PORT, MQTT_KEEPALIVE_INTERVAL)

    # Lancez la boucle de réception des messages MQTT
    mqtt_client.loop_forever()

def handle_mqtt_message(payload):
    try:
        # Convertir le payload JSON en dictionnaire Python
        message_data = json.loads(payload)
        
        # Récupérer le code d'opération et la donnée du message
        operation_code = message_data.get('operation_code')
        data = message_data.get('data')

        # Envoyer les données du message MQTT à l'application Flask
        response = requests.post('http://127.0.0.1:5000/handle-mqtt-message', json=message_data)
        print(response.text)

    except json.JSONDecodeError as e:
        print("Erreur lors de la décodage du payload JSON:", e)

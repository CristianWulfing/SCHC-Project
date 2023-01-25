import paho.mqtt.client as mqtt
import json, codecs
import logging

class MQTTconn:

    mqttc = None

    def __init__(self, server, port, username, password, AppID, devices_list, on_message_callback):

        try:
            self.AppID          = AppID
            self.devices_list   = devices_list

            self.mqttc = mqtt.Client()
            self.mqttc.on_connect=self.on_connect
            # self.mqttc.on_disconnect=self.on_disconnect
            self.mqttc.on_message=on_message_callback

            self.mqttc.username_pw_set(username, password)
            self.mqttc.connect(server, port, 60)
            self.mqttc.loop_start()

        except:

            self.mqttc.disconnect()
            logging.info(f"[MQTT] Client disconnected")

    class DownlinkMessage:
        def __init__(self, port, payload, confirmed=False, priority=None):
            self.f_port = port
            self.frm_payload = payload
            self.priority = priority
            self.confirmed = confirmed

        def obj2json(self):
            json_msg = json.dumps(self.__dict__)
            return str(json_msg)

    def on_connect(self, mqttc, mosq, obj, rc):
        logging.info(f"[MQTT] Connected with result code: {rc}")

        for device in self.devices_list:
            DevEUI = self.devices_list[device]["DevEUI"].lower()
            sub_topic  = "v3/{}/devices/eui-{}/up".format(self.AppID, DevEUI)
            mqttc.subscribe(sub_topic)
            logging.info(f"[MQTT] Subscribing on DevEUI {DevEUI.upper()}")

    # def on_disconnect(self, client, userdata, rc):
    #     logging.info(f"[MQTT] Client disconnected")

    def on_subscribe(self, mosq, obj, mid, granted_qos):
        logging.info(f"[MQTT] Subscribed: {mid} {granted_qos}")

    def obj_dict(self, obj):
        return obj.__dict__

    def send_socket(self, payload: bytes, port: int, DevEUI: str) -> None:

        logging.info(f"[MQTT] Sending to device {DevEUI} on port {port}: {payload.hex()}")

        messages = {"downlinks":[]}

        b64 = codecs.encode(payload, 'base64').decode()
        msg1 = self.DownlinkMessage(port=port, payload=b64, confirmed=False, priority="HIGHEST")
        messages["downlinks"].append(msg1)

        pub_topic  = "v3/{}/devices/eui-{}/down/replace".format(self.AppID, DevEUI) # push | replace
        json_msgs = str(json.dumps(messages, default=self.obj_dict))
        self.mqttc.publish(pub_topic, payload=json_msgs, qos=0, retain=False)
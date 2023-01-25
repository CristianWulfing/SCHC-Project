
import logging, time, os, sys, fcntl, struct, select, codecs, json

from schc_handlers import SCHCGatewayHandler
from schc_protocols import LoRaWAN, SCHCProtocol

from threading import Lock, Thread
from conn_layer import MQTTconn, DevIDD
from scapy.all import scapy
from scapy.layers.inet6 import IPv6, UDP, Raw, RandShort
from datetime import datetime

# uplink    : from TUN (server) to SCHC (node)
# downlink  : from SCHC (node) to TUN (server)

TUN_NAME            = 'tun0'
APP_IPV6            = 'abcd::10'

MQTT_SERVER         = 'eu1.cloud.thethings.network'
MQTT_PORT           = 1883
MQTT_USERNAME       = 'changeUsername'
MQTT_PASSWORD       = 'changePassword'

LORAWAN_APPID       = 'changeAppID'
LORAWAN_DEVS_LIST   = [{'DevEUI': '70B3D57ED0055D4F', 'AppSKey': 'changeAppSKey'},
                       {'DevEUI': '70B3D57ED0058962', 'AppSKey': 'changeAppSKey'}]

MTU = 32
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454CA
IPV6_MTU = 1500
UDP_NXT_HDR = 17

logging.basicConfig(
    format='%(asctime)s [%(levelname)s] %(message)s', 
    level='DEBUG', 
    datefmt='%d/%m/%y %H:%M:%S')

# DEBUG TCC CRISTIAN
ipv6_metrics_file = 'logs/' + datetime.now().strftime("%Y%m%d%H%M%S") + '_gateway_ipv6_metrics.csv'
#

class Tunnel:

    def __init__(self, tun_file="/dev/net/tun", devices_list=None):

        self.devices = {}

        for device in devices_list:

            DevEUI = device["DevEUI"].lower()

            self.devices[DevEUI]             = {}
            self.devices[DevEUI]["DevEUI"]   = device["DevEUI"]
            self.devices[DevEUI]["AppSKey"]  = device["AppSKey"]
            self.devices[DevEUI]["IPv6"]     = DevIDD(device["DevEUI"], device["AppSKey"], "5454:").get()
            self.devices[DevEUI]["uplink"]   = {}
            self.devices[DevEUI]["handler"]  = SCHCGatewayHandler(SCHCProtocol.LoRaWAN, MTU, on_receive_callback=self.SCHC_reading_callback)

            self.devices[DevEUI]["uplink"]["lock"]       = Lock()
            self.devices[DevEUI]["uplink"]["queue"]      = []
            self.devices[DevEUI]["uplink"]["available"]  = True

        self.downlink_lock = Lock()
        self.downlink_queue = []

        self.tun_lock = Lock()

        self.running = True
        self.tun_name = TUN_NAME.encode()

        self.mqtt_conn = MQTTconn(
                            server=MQTT_SERVER, 
                            port=MQTT_PORT, 
                            username=MQTT_USERNAME, 
                            password=MQTT_PASSWORD, 
                            AppID=LORAWAN_APPID, 
                            devices_list=self.devices, 
                            on_message_callback=self.MQTT_on_message_callback)
                            
        with self.tun_lock:
            self.tun_fd = os.open(tun_file, os.O_RDWR)
            if self.tun_fd < 0:
                raise OSError

        flags = IFF_TUN | IFF_NO_PI
        ifreq = struct.pack('16sh', self.tun_name, flags)
        fcntl.ioctl(self.tun_fd, TUNSETIFF, ifreq)

    def getDevEUIByIPv6(self, ipv6):
        for device in self.devices:
            if self.devices[device]["IPv6"] == ipv6:
                return self.devices[device]["DevEUI"].lower()
        return None

    def start(self):

        self.TUN_start_listener()
        self.TUN_start_writing()
        self.SCHC_start_writing()

    def close(self):
        logging.info(f"[TUN] Closing connection")
        self.running = False
        os.close(self.tun_fd)

    def MQTT_on_message_callback(self, mqttc, obj, msg):

        msg         = json.loads(msg.payload.decode('utf-8'))
        fport       = msg["uplink_message"]["f_port"]
        msg_bytes   = codecs.decode((msg["uplink_message"]["frm_payload"]).encode('utf-8'), 'base64')
        dev_eui     = str(msg["end_device_ids"]["dev_eui"]).lower()

        # DEBUG TCC CRISTIAN
        snr         = float(msg["uplink_message"]["rx_metadata"][0].get("snr", "0"))
        rssi        = float(msg["uplink_message"]["rx_metadata"][0].get("rssi", "0"))
        if len(msg["uplink_message"]["rx_metadata"]) > 1:
            for field in msg["uplink_message"]["rx_metadata"]:
                snr_t = float(field.get("snr", "0"))
                if snr_t > snr:
                    snr = snr_t
                    rssi = float(field.get("rssi", "0"))
        #

        if msg_bytes:
            handler = self.devices[dev_eui]["handler"]
            logging.info(f"[MQTT] Receiving from device {dev_eui} on port {fport}: {msg_bytes.hex()}")
            try:
                if handler is not None: 
                    handler.handleMessage(dev_eui, msg_bytes, fport, self.mqtt_conn, snr, rssi)
            except SystemExit as e:
                logging.info(f"[SCHC] SystemExit 1: {e}")
                handler.finishMachine(ex=SystemExit)
                if fport == LoRaWAN.ACK_ALWAYS:
                    self.TUN_read_pop(dev_eui)
            except SystemError as e:
                logging.error(f"[SCHC] SystemError 1: {e}")
                handler.finishMachine(ex=SystemError)
                if fport == LoRaWAN.ACK_ALWAYS:
                    self.TUN_read_pop(dev_eui)

    # Get data from TUN (server) and forward to SCHC compiler (node)
    def TUN_reading_routine(self):
        pollster = select.poll()
        pollster.register(self.tun_fd, select.POLLIN)
        while self.running:
            time.sleep(.1)
            fdlist = pollster.poll(-1)
            if fdlist == []:
                continue
            fd, flags = fdlist[0]
            if fd != self.tun_fd or flags & select.POLLHUP:
                sys.exit(-1)
            elif flags & select.POLLIN:
                with self.tun_lock:
                    packet = os.read(self.tun_fd, IPV6_MTU)
                if packet is not None:
                    if (len(packet) > 28 and packet[9] == UDP_NXT_HDR) or (len(packet) > 48 and packet[6] == UDP_NXT_HDR):
                        pkt = scapy.layers.inet6.IPv6(packet)
                        if pkt[IPv6].src == APP_IPV6:
                            DevEUI = self.getDevEUIByIPv6(pkt[IPv6].dst)
                            if DevEUI:
                                with self.devices[DevEUI]["uplink"]["lock"]:
                                    self.devices[DevEUI]["uplink"]["queue"].append(packet)
                                    length = len(self.devices[DevEUI]["uplink"]["queue"])
                                    logging.info(f"[TUN] Receiving IPv6 packet | size: {len(packet)} bytes | uplink queue size: {length}")
                                    pkt.show2()

    def TUN_start_listener(self):
        t = Thread(target=self.TUN_reading_routine)
        t.start()
        logging.info(f"[TUN] Reading loop started")

    def TUN_writing_routine(self):
        while self.running:
            DevEUI, downlink = self.SCHC_read() # From SCHC decompiler (node) to TUN (server)   
            if downlink is not None:
                self.TUN_write(downlink)
            time.sleep(0.1)

    def TUN_start_writing(self):
        t = Thread(target=self.TUN_writing_routine)
        t.start()
        logging.info(f"[TUN] Writing loop started")

    def SCHC_writing_routine(self, device):
        while self.running:
            uplink = self.TUN_read(device) # From TUN (server) to SCHC compiler (node)
            if uplink is not None: 
                self.SCHC_write(uplink, device)
            time.sleep(0.1)

    def SCHC_start_writing(self):
        for device in self.devices:
            t = Thread(target=self.SCHC_writing_routine, args=[device])
            t.start()
            logging.info(f"[SCHC] Started writing loop for DevEUI {self.devices[device]['DevEUI']} IPv6 {self.devices[device]['IPv6']}")

    def SCHC_reading_callback(self, packet):

        logging.info(f"[SCHC] Reassembled: {packet.hex()}")
        pkt = scapy.layers.inet6.IPv6(packet)
        pkt.show2()

        device = self.getDevEUIByIPv6(pkt[IPv6].src)

        # DEBUG TCC CRISTIAN
        if device == "70B3D57ED0058962".lower():
            with open(ipv6_metrics_file, "a") as logfile:
                #datetime,ipv6_pkt,dlms_pkt
                log = "{},{},{}\r\n".format(datetime.now(), packet.hex(), bytes(pkt[UDP].payload).hex())
                logfile.write(log)
                logfile.close()
        #

        with self.downlink_lock:
            self.downlink_queue.append({'DevEUI': device, 'payload': packet})

    def TUN_read(self, device):
        retval = None
        uplink = self.devices[device]["uplink"]
        with uplink["lock"]:
            if len(uplink["queue"]) > 0 and uplink["available"] == True:
                retval = uplink["queue"][0]
                uplink["available"] = False
        return retval

    def TUN_read_pop(self, device):
        uplink = self.devices[device]["uplink"]
        with uplink["lock"]:
            if len(uplink["queue"]) > 0:
                uplink["queue"].pop(0)
                uplink["available"] = True

    def TUN_write(self, buf):
        with self.tun_lock:
            try:
                os.write(self.tun_fd, buf)
            except Exception as e:
                pass

    def SCHC_read(self):
        with self.downlink_lock:
            if len(self.downlink_queue) > 0:
                retval = self.downlink_queue.pop(0)
                return retval["DevEUI"], retval["payload"]
        
        return None, None

    def SCHC_write(self, package, device): 
        # try:
        handler = self.devices[device]["handler"]
        handler.schedulePackage(package)

        pkt = scapy.layers.inet6.IPv6(package)
        DevEUI = self.getDevEUIByIPv6(pkt[IPv6].dst)

        handler.sendPackage(self.mqtt_conn, DevEUI)

try:
    tun = Tunnel(tun_file="/dev/net/tun", devices_list=LORAWAN_DEVS_LIST)
    logging.info(f"[TUN] Device configured")
    tun.start()
except KeyboardInterrupt:
    tun.close()
#!/usr/bin/env python

# **************************************************************************
#   SCHC PROJECT
# **************************************************************************
#   AUTHOR: CRISTIAN AUGUSTO WüLFING
#   EMAIL: cris_wulfing@hotmail.com
#   CITY: Santa Maria - Rio Grande do Sul - Brasil
#   FOUNDATION: Fox IoT
# **************************************************************************
#   Copyright(c) 2023 Fox IoT.
# **************************************************************************

from schc_handlers import SCHCNodeHandler
from schc_protocols import SCHCProtocol
from conn_layer import LoRaWANconn
from scapy.all import scapy
from scapy.layers.inet6 import IPv6, UDP, Raw
from datetime import datetime
import logging, time

import random, string

MTU = 32
handler = None
lora_conn = None

MODEM_SERIALPORT  = "/dev/ttyACM0"
MODEM_BAUDRATE    = 115200

LORA_DEVEUI = "70B3D57ED0058962"

downlink_queue = []

metrics_file = 'logs/' + datetime.now().strftime("%Y%m%d%H%M%S") + '_node_2_metrics.csv'

ipv6_metrics_file = 'logs/' + datetime.now().strftime("%Y%m%d%H%M%S") + '_node_2_ipv6_metrics.csv'
with open(ipv6_metrics_file, "a") as logfile:
   logfile.write("datetime,ipv6_pkt,dlms_pkt\r\n")
   logfile.close()

logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level='DEBUG', datefmt='%d/%m/%y %H:%M:%S')

def SCHC_reading_callback(msg):

   logging.info(f"[SCHC] Reassembled: {msg.hex()}")
   pkt = scapy.layers.inet6.IPv6(msg)

   dlms_packet = bytes(pkt[UDP].payload)
   logging.info(f'[DLMS] "Sending via Serial": {dlms_packet.hex()}')

   with open(ipv6_metrics_file, "a") as logfile:
      log = "{},{},{}\r\n".format(datetime.now(), msg.hex(), dlms_packet.hex())
      logfile.write(log)
      logfile.close()

   time.sleep(5)

   ran = random.randint(1,512)
   ans = bytearray.fromhex(generate_random_payload(ran).hex())

   logging.info(f'[DLMS] "Receiving via Serial" ({len(ans)}): {ans.hex()}')

   downlink_queue.append({'ip_dest': pkt[IPv6].src, 'port_dest': pkt[UDP].sport, 'ip_src': pkt[IPv6].dst, 'port_src': pkt[UDP].dport, 'payload': ans})

def generate_random_payload(length : int):

   characters = string.ascii_letters + string.digits
   return (''.join(random.choice(characters) for i in range(length))).encode('utf-8')

def LoRa_on_message_callback(msg, port, snr, rssi):

   global handler
   msg_bytes = None

   if msg:
      msg_bytes = bytes(bytearray.fromhex(msg.decode()))
      logging.info(f"[LoRaWAN] Receiving on port {port}: {msg_bytes.hex()}")

   try:
      handler.handleMessage(msg_bytes, port, lora_conn, snr, rssi)

   except SystemExit as e:
      logging.info(f"[SCHC] SystemExit 1: {e}")

   except SystemError as e:
      logging.error(f"[SCHC] SystemError 1: {e}")

try:
   
   if lora_conn is None:
      lora_conn = LoRaWANconn(MODEM_SERIALPORT, MODEM_BAUDRATE)

   if handler is None:
      handler = SCHCNodeHandler(SCHCProtocol.LoRaWAN, MTU, on_lora_message=LoRa_on_message_callback, on_receive_callback=SCHC_reading_callback, deveui=LORA_DEVEUI, metrics_file=metrics_file)

   while True:

      if len(downlink_queue) > 0:

         item = downlink_queue.pop(0)

         pkt = IPv6(src=item['ip_src'], dst=item['ip_dest']) / UDP(sport=item['port_src'], dport=item['port_dest']) / Raw(load=item['payload'])
         pkt.show2()
         package = bytes(pkt)
         handler.schedulePackage(package)
         reply = handler.sendPackage(lora_conn)

      else:

         handler.startLink(lora_conn)

except LoRaWANconn.TimeExpired:
   logging.error(f"[LoRaWAN] Erro no modem. Reiniciando")
except SystemExit as e:
   logging.info(f"[SCHC] SystemExit 2: {e}")
   handler = None
except SystemError as e:
   logging.error(f"[SCHC] SystemError 2: {e}")
   handler = None
""" schc_gateway_handler: SCHC Gateway Handler Class """

from schc_handlers import SCHCHandler
from schc_protocols import LoRaWAN, SCHCProtocol
from schc_machines.lorawan import AckAlwaysSender, AckOnErrorReceiver
from schc_compression.SCHC_Parser import SCHC_Parser
from scapy.layers.inet6 import UDP
from scapy.all import scapy
from datetime import datetime
import time, logging

class SCHCGatewayHandler(SCHCHandler):
    """
    SCHC Gateway Handler
    To be used as an API on Gateway side of communication

    Attributes
    ----------
    callback_creator : Callable
        A function to be used on reassembled message
    """

    def __init__(self, protocol, mtu, on_receive_callback):
        """
        Constructor

        Parameters
        ----------
        protocol
        mtu
        on_receive_callback : Callable
            A function to be used when message is reassembled
        """
        super().__init__(protocol, mtu)

        self.schc_pkt = None
        self.ipv6_pkt = None
        self.dlms_pkt = None

        def create_after_processing_callback(rule_id, dtag):
            def after_reassembly_processing(msg_bytes):
                on_receive_callback(self.__decompressor__.decompress(msg_bytes, "Up"))
            return after_reassembly_processing

        self.callback_creator = create_after_processing_callback

        # DEBUG TCC CRISTIAN
        self.metrics_file = 'logs/' + datetime.now().strftime("%Y%m%d%H%M%S") + '_gateway_metrics.csv'
        with open(self.metrics_file, "a") as logfile:
            logfile.write("datetime,lora_node,lora_direction,schc_fsm,lora_port,lora_snr,lora_rssi,packet,msg_type,msg_len,msg_crc16,msg_payload,schc_pkt,schc_pkt_len,ipv6_pkt,ipv6_pkt_len,dlms_pkt,dlms_pkt_len\r\n")
            logfile.close()
        #

    ## UPLINK AND DOWNLINK

    def handleMessage(self, dev_eui, message, f_port, mqtt_conn, snr_up = None, rssi_up = None):
        """
        Handles a reception of SCHC Message

        Parameters
        ----------
        message : bytes
            A message received
        f_port : int, optional
            In case of using LoRaWAN, rule id to handled message
        url : str, optional
            In case of using LoRaWAN, url to send answer
        dev_id : str, optional
            In case of using LoRaWAN, unique identifier of device
            that sent the received message

        Returns
        -------
        None
        """
        response = None

        if self.__protocol__.id == SCHCProtocol.LoRaWAN:

            r, d = self.identify_session_from_message(message, int(f_port))

            if r == LoRaWAN.ACK_ON_ERROR:
                self.receiveMessage(dev_eui, r, d, bytes([f_port]) + message, snr_up, rssi_up)
                response = self.generate_message(r, d, self.__mtu__)
            elif r == LoRaWAN.ACK_ALWAYS:
                if f_port in self.__sessions__ and self.__sessions__[f_port]:

                    if message == b"\x0f":
                        logging.warning(f"[SCHC] Receiving ACK ALWAYS routine packet. Ignoring.")
                        self.metricsLog(dev_eui, "uplink", r, d, bytes([f_port]) + message, snr_up, rssi_up) # DEBUG TCC CRISTIAN
                    else:
                        self.receiveMessage(dev_eui, r, d, bytes([f_port]) + message, snr_up, rssi_up)
                    
                    response = self.generate_message(r, d, self.__mtu__)
                else:
                    logging.warning(f"[SCHC] Machine not found. Ignoring")

            if response is not None:
                logging.info(f"[SCHC] Scheduling packet: {response.hex()}")
                mqtt_conn.send_socket(payload=response[1:], port=response[0], DevEUI=dev_eui)

                dtag = None
                self.metricsLog(dev_eui, "downlink", response[0], dtag, response) # DEBUG TCC CRISTIAN

        else:
            raise NotImplementedError("Just LoRaWAN implemented")

    def receiveMessage(self, dev_eui, rule_id, dtag, message, snr, rssi):
        """
        Defines behaviour after receiving a message

        Parameters
        ----------
        rule_id : int
            Rule id of received message
        dtag : int or None
            DTag of received message
        message : bytes
            Message receive

        Returns
        -------
        None
        """
        if self.__protocol__.id == SCHCProtocol.LoRaWAN:
            if rule_id == LoRaWAN.ACK_ON_ERROR:
                self.assign_session_AckOnErrorReceiver(rule_id, dtag, AckOnErrorReceiver, on_success=self.callback_creator(rule_id, dtag))

                self.metricsLog(dev_eui, "uplink", rule_id, dtag, message, snr, rssi) # DEBUG TCC CRISTIAN

                self.__sessions__[rule_id][dtag].receive_message(message)
            elif rule_id == LoRaWAN.ACK_ALWAYS:
                self.assign_session_AckAlwaysSender(LoRaWAN.ACK_ALWAYS, None, AckAlwaysSender)

                self.metricsLog(dev_eui, "uplink", rule_id, dtag, message, snr, rssi) # DEBUG TCC CRISTIAN

                self.__sessions__[rule_id][dtag].receive_message(message)
            else:
                raise NotImplementedError("Just ACK ALWAYS and ACK ON ERROR implemented")
        else:
            raise NotImplementedError("Just LoRaWAN implemented")

    def generate_message(self, rule_id, dtag, mtu):
        """
        Generates a message to response

        Parameters
        ----------
        rule_id : int
            Rule id to identify session
        dtag : int
            Dtag to identify session
        mtu : mtu, optional
            MTU to use. Default 512 bytes

        Returns
        -------
        bytes
            Response to be send as bytes
        """

        message = self.__sessions__[rule_id][dtag].generate_message(mtu)
        return message if message is None else message.as_bytes()

    ## UPLINK

    def receivePackage(self):
        """
        Loop receveing message from Node

        Returns
        -------
        None
        """

        rule_id = LoRaWAN.ACK_ON_ERROR
        dtag = None

        if (rule_id not in self.__sessions__) or (dtag not in self.__sessions__[rule_id]):
            return 

        machine = self.__sessions__[rule_id][dtag]
        if machine is not None:
            if machine.state == machine.states["end"] or machine.state == machine.states["error"]:
                self.__sessions__[rule_id].pop(dtag)
            
    def finishMachine(self, ex):
        time.sleep(0.5) # dar tempo para todo a FSM perceber o novo estado (end ou error) antes de deletá-la
        dtag = None
        for rule_id in self.__sessions__.keys():
            if dtag in self.__sessions__[rule_id]:
                machine = self.__sessions__[rule_id][dtag]
                if machine is not None:
                    if (ex == SystemExit and machine.state == machine.states["end"]) or \
                     (ex == SystemError and machine.state == machine.states["error"]):
                        self.__sessions__[rule_id].pop(dtag)

    ## DOWNLINK

    def schedulePackage(self, packet):
        """
        Load package to send by separating message in fragments

        Parameters
        ----------
        packet : bytes
            Packet to be fragmented

        Returns
        -------
        None
        Parameters
        ----------
        packet

        Returns
        -------

        """
        if self.__protocol__.id == SCHCProtocol.LoRaWAN:
            logging.info(f"[SCHC] Scheduling packet: {packet.hex()}")
            compressed_packet = self.__compressor__.compress(packet, "Down")

            # Como apenas uma dtag está sendo considerado, haverá apenas uma mensagem de Up/Down por vez em todo o Handler
            self.schc_pkt = compressed_packet[0]
            self.ipv6_pkt = packet
            self.dlms_pkt = bytes((scapy.layers.inet6.IPv6(packet))[UDP].payload)

            self.assign_session_AckAlwaysSender(LoRaWAN.ACK_ALWAYS, None, AckAlwaysSender, compressed_packet)
        else:
            raise NotImplementedError("Just LoRaWAN implemented")

    def sendPackage(self, mqtt_conn, DevEUI):
        """
        Starts communication sending fragments to Node

        Returns
        -------
        None
        """

        rule_id = LoRaWAN.ACK_ALWAYS
        dtag = None
        machine = self.__sessions__[rule_id][dtag]
        if machine is not None:
            message = machine.generate_message(self.__mtu__)
            if message is not None:

                print("# -------------------------------------------- STARTING TRANSMISSION -------------------------------------------- #")

                msg = message.as_bytes()
                mqtt_conn.send_socket(payload=msg[1:], port=msg[0], DevEUI=DevEUI)

                self.metricsLog(DevEUI, "downlink", rule_id, dtag, msg) # DEBUG TCC CRISTIAN

                while dtag in self.__sessions__[rule_id] and machine is not None and machine.state != machine.states["end"] and machine.state != machine.states["error"]:
                    time.sleep(0.1)
           
                print("# -------------------------------------------- FINISHING TRANSMISSION -------------------------------------------- #")

    ## MISC

    def getIPv6DevIID(self, package, direction):

        parser = SCHC_Parser()
        parser.parser(package, direction)
        return format(parser.header_fields[('IPv6.devIID', 1)][0], 'x')

    ## DEBUG TCC CRISTIAN

    def metricsLog(self, deveui, dir, rule_id, dtag, response, snr = None, rssi = None):

        messageType = 'None'
        session = 'None'

        if rule_id in self.__sessions__.keys() and dtag in self.__sessions__[rule_id] and self.__sessions__[rule_id][dtag] and response[1:] != b'\x0f':
            session = hex(id(self.__sessions__[rule_id][dtag]))

            from schc_parsers import SCHCParser
            from schc_messages import RegularSCHCFragment, All1SCHCFragment, SCHCAckReq, SCHCSenderAbort, SCHCAck, SCHCReceiverAbort
            side = 'sender' if response[0] == LoRaWAN.ACK_ALWAYS else 'receiver'
            schc_message = SCHCParser.from_bytes(self.__sessions__[rule_id][dtag].protocol, response, side)
            if isinstance(schc_message, RegularSCHCFragment):
                messageType = 'RegularSCHCFragment'
            elif isinstance(schc_message, All1SCHCFragment):
                messageType = 'All1SCHCFragment'
            elif isinstance(schc_message, SCHCAck):
                messageType = 'SCHCAck'
            elif isinstance(schc_message, SCHCAckReq):
                messageType = 'SCHCAckReq'
            elif isinstance(schc_message, SCHCReceiverAbort):
                messageType = 'SCHCReceiverAbort'
            elif isinstance(schc_message, SCHCSenderAbort):
                messageType = 'SCHCSenderAbort'

        logString = str(datetime.now())

        msg_type = 'dummy' if response[1:].hex() == "0f" else 'schc_msg'

        if dir == "uplink":

            logString += ',{},uplink,{},{},{},{},{},{},{},{},{},None,None,None,None,None,None' \
                .format(deveui.upper(), session, response[0], snr, rssi, msg_type, messageType, len(response[1:]), self.CRC16(response[1:]), response[1:].hex())

        else: # downlink

            schc_pkt        = self.schc_pkt.hex() if self.schc_pkt is not None else 'None'
            schc_pkt_len    = len(self.schc_pkt) if self.schc_pkt is not None else 'None'

            ipv6_pkt        = self.ipv6_pkt.hex() if self.ipv6_pkt is not None else 'None'
            ipv6_pkt_len    = len(self.ipv6_pkt) if self.ipv6_pkt is not None else 'None'

            dlms_pkt        = self.dlms_pkt.hex() if self.dlms_pkt is not None else 'None'
            dlms_pkt_len    = len(self.dlms_pkt) if self.dlms_pkt is not None else 'None'

            logString += ',{},downlink,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}' \
                .format(deveui.upper(), session, response[0], snr, rssi, msg_type, messageType, len(response[1:]), self.CRC16(response[1:]), response[1:].hex(), \
                 schc_pkt, schc_pkt_len, ipv6_pkt, ipv6_pkt_len, dlms_pkt, dlms_pkt_len)

        with open(self.metrics_file, "a") as logfile:
            logfile.write(logString + "\r\n")
            logfile.close()
            
    def CRC16(self, payload : bytes):

        crc = 0xffffffff
        for i in payload:
            for j in range(8):
                b = (i ^ crc) & 1
                crc >>= 1
                if b == 1:
                    crc = crc ^ 0xedb88320
                i >>= 1
        return hex((~crc) & 0xffffffff)

    #
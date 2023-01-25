""" schc_handler_node: SCHC Handler Node Class """

from schc_handlers import SCHCHandler
from schc_protocols import LoRaWAN, SCHCProtocol
from schc_machines.lorawan import AckOnErrorSender, AckAlwaysReceiver
from datetime import datetime
from scapy.layers.inet6 import UDP
from scapy.all import scapy
import logging

class SCHCNodeHandler(SCHCHandler):
    """
    SCHC Node Handler
    Concrete class to be used as API for sending messages
    using SCHC Protocols on a Node
    """

    def __init__(self, protocol, mtu, on_lora_message, on_receive_callback, deveui, metrics_file):
        """
        Constructor

        Parameters
        ----------
        protocol
        mtu

        See Also
        --------
        SCHCHandler
        """
        
        super().__init__(protocol, mtu)

        self.schc_pkt = None
        self.ipv6_pkt = None
        self.dlms_pkt = None

        self.on_lora_message = on_lora_message
        
        def create_after_processing_callback(rule_id, dtag):
            def after_reassembly_processing(msg_bytes):
                on_receive_callback(self.__decompressor__.decompress(msg_bytes, "Down"))
            return after_reassembly_processing

        self.callback_creator = create_after_processing_callback
        self.deveui = deveui

        # DEBUG TCC CRISTIAN
        self.metrics_file = metrics_file
        with open(self.metrics_file, "a") as logfile:
            logfile.write("datetime,lora_node,lora_direction,schc_fsm,lora_port,lora_snr,lora_rssi,packet,msg_type,msg_len,msg_crc16,msg_payload,schc_pkt,schc_pkt_len,ipv6_pkt,ipv6_pkt_len,dlms_pkt,dlms_pkt_len\r\n")
            logfile.close()
        #

    ## UPLINK AND DOWNLINK

    def handleMessage(self, message, f_port, lora_conn, snr_down = None, rssi_down = None):
        """
        Handles a reception of SCHCMessages

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
        if self.__protocol__.id == SCHCProtocol.LoRaWAN:

            try:
                if message is None:
                    rule_id = None
                    self.receiveMessage(f_port, rule_id, message, snr_down, rssi_down)
                    response = self.generate_message(f_port, None, self.__mtu__)
                else:
                    r, d = self.identify_session_from_message(message, f_port)

                    if r == LoRaWAN.ACK_ON_ERROR and (r not in self.__sessions__.keys() or d not in self.__sessions__[r]) and message == b"\x20":
                        logging.warning(f"[SCHC] Receiving ACK from previous transmission. Ignoring.")
                        return

                    self.receiveMessage(r, d, bytes([f_port]) + message, snr_down, rssi_down)
                    response = self.generate_message(r, d, self.__mtu__)

                if response is not None:
                    logging.info(f"[SCHC] Scheduling packet: {response.hex()}")
                    sent, snr, rssi, rx, port = lora_conn.sendTime(payload=response[1:], port=response[0])

                    dtag = None
                    self.metricsLog("uplink", f_port, dtag, response) # DEBUG TCC CRISTIAN

                    self.on_lora_message(rx, port if port != None else f_port, snr, rssi)

            except SystemExit as e:
                logging.info(f"[SCHC] SystemExit: {e}")
                dtag = None
                self.__sessions__[f_port].pop(dtag)
            except SystemError as e:
                logging.error(f"[SCHC] SystemError: {e}")
                dtag = None
                self.__sessions__[f_port].pop(dtag)

        else:
            raise NotImplementedError("Just LoRaWAN implemented")

    def receiveMessage(self, rule_id, dtag, message, snr, rssi):
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
                self.assign_session_AckOnErrorSender(rule_id, dtag, AckOnErrorSender, self.callback_creator(rule_id, dtag))
                if message is not None:
                    self.metricsLog("downlink", rule_id, dtag, message, snr, rssi) # DEBUG TCC CRISTIAN
                    self.__sessions__[rule_id][dtag].receive_message(message)
            elif rule_id == LoRaWAN.ACK_ALWAYS:
                self.assign_session_AckAlwaysReceiver(rule_id, dtag, AckAlwaysReceiver, self.callback_creator(rule_id, dtag))
                if message is not None:
                    self.metricsLog("downlink", rule_id, dtag, message, snr, rssi) # DEBUG TCC CRISTIAN
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
        """
        if self.__protocol__.id == SCHCProtocol.LoRaWAN:
            logging.info(f"[SCHC] Scheduling packet: {packet.hex()}")
            compressed_packet = self.__compressor__.compress(packet, "Up")

            # Como apenas uma dtag está sendo considerado, haverá apenas uma mensagem de Up/Down por vez em todo o Handler
            self.schc_pkt = compressed_packet[0]
            self.ipv6_pkt = packet
            self.dlms_pkt = bytes((scapy.layers.inet6.IPv6(packet))[UDP].payload)

            self.assign_session_AckOnErrorSender(LoRaWAN.ACK_ON_ERROR, None, AckOnErrorSender, compressed_packet)
        else:
            raise NotImplementedError("Just LoRaWAN implemented")

    def sendPackage(self, modem):
        """
        Starts communication sending fragments to Gateway

        Returns
        -------
        None
        """

        message = None
        rule_id = LoRaWAN.ACK_ON_ERROR
        dtag = None
        if rule_id in self.__sessions__.keys():
            while dtag in self.__sessions__[rule_id] and self.__sessions__[rule_id][dtag]:
                machine = self.__sessions__[rule_id][dtag]
                if machine is not None:
                    try:
                        message = machine.generate_message(self.__mtu__)
                        if message is not None:
                            message = message.as_bytes()
                            sent, snr, rssi, rx, port = modem.sendTime(payload=message[1:], port=message[0])

                            self.metricsLog("uplink", rule_id, dtag, message) # DEBUG TCC CRISTIAN

                            if rx != '':
                                self.on_lora_message(rx, port, snr, rssi)
                    except (SystemExit, SystemError) as e:
                        self.__sessions__[rule_id].pop(dtag)
    
    ## DOWNLINK

    def startLink(self, modem):
        """
        Starts communication sending fragments to Gateway

        Returns
        -------
        None
        """

        message = b"\x15\x0f"
        logging.info(f"[SCHC] Scheduling routine packet: {message.hex()}")
        sent, snr, rssi, rx, port = modem.sendTime(payload=message[1:], port=message[0])

        rule_id = LoRaWAN.ACK_ALWAYS
        dtag = None
        self.metricsLog("uplink", rule_id, dtag, message) # DEBUG TCC CRISTIAN

        if rx != '':
            self.on_lora_message(rx, port, snr, rssi)

    ## DEBUG TCC CRISTIAN

    def metricsLog(self, dir, rule_id, dtag, response, snr = None, rssi = None, schc_pkt = None, ipv6_pkt = None, dlms_pkt = None):

        messageType = 'None'
        session = 'None'

        if rule_id in self.__sessions__.keys() and dtag in self.__sessions__[rule_id] and self.__sessions__[rule_id][dtag]:
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

            schc_pkt        = self.schc_pkt.hex() if self.schc_pkt is not None else 'None'
            schc_pkt_len    = len(self.schc_pkt) if self.schc_pkt is not None else 'None'

            ipv6_pkt        = self.ipv6_pkt.hex() if self.ipv6_pkt is not None else 'None'
            ipv6_pkt_len    = len(self.ipv6_pkt) if self.ipv6_pkt is not None else 'None'

            dlms_pkt        = self.dlms_pkt.hex() if self.dlms_pkt is not None else 'None'
            dlms_pkt_len    = len(self.dlms_pkt) if self.dlms_pkt is not None else 'None'
            
            logString += ',{},uplink,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}' \
                .format(self.deveui.upper(), session, response[0], snr, rssi, msg_type, messageType, len(response[1:]), self.CRC16(response[1:]), response[1:].hex(), \
                 schc_pkt, schc_pkt_len, ipv6_pkt, ipv6_pkt_len, dlms_pkt, dlms_pkt_len)

        else: # downlink

            logString += ',{},downlink,{},{},{},{},{},{},{},{},{},None,None,None,None,None,None' \
                .format(self.deveui.upper(), session, response[0], snr, rssi, msg_type, messageType, len(response[1:]), self.CRC16(response[1:]), response[1:].hex())

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
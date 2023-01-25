""" schc_handler: SCHC Handler (Super) Class """

from schc_base import SCHCObject
from schc_protocols import SCHCProtocol, get_protocol
from schc_compression.SCHC_RuleManager import SCHC_RuleManager
from schc_compression.SCHC_Compressor import SCHC_Compressor
from schc_compression.SCHC_Decompressor import SCHC_Decompressor

from schc_machines.lorawan import AckOnErrorSender, AckOnErrorReceiver, AckOnErrorSender, AckAlwaysReceiver, AckAlwaysSender

class SCHCHandler:
    """
    SCHC Handler super class
    Define functions and interface of Node and Gateway concrete class

    Attributes
    ----------
    __protocol__ : SCHCProtocol
        Protocol to be use
    __sessions__ : Dict[int, Dict[int, SCHCFiniteStateMachine]]
        A dictionary with rule_id and DTag assigned to a SCGHCFiniteStateMachine
    __mtu__ : int
        MTU to use

    See Also
    --------
    SCHCFiniteStateMachine
    """
    def __init__(self, protocol, mtu):
        """
        Constructor

        Parameters
        ----------
        protocol : int
            Number indicating SCHCProtocol to use
        mtu : int
            MTU to use

        See Also
        --------
        SCHCProtocol
        """
        self.__protocol__ = get_protocol(protocol)
        self.__sessions__ = dict()
        self.__mtu__ = mtu
        rm = SCHC_RuleManager()

        rule_91 = {"ruleid": 91,
                "devid": 'eui-70b3d57ed0055d4f',
                "content": [["IPv6.version",        4,  1, "Bi",    6,                  "equal",            "not-sent"],
                            ["IPv6.trafficClass",   8,  1, "Bi",    0,                  "MSB(6)",           "LSB"],
                            ["IPv6.flowLabel",      24, 1, "Bi",    None,               "ignore",           "value-sent"],
                            ["IPv6.payloadLength",  16, 1, "Bi",    None,               "ignore",           "value-sent"],
                            ["IPv6.nextHeader",     8,  1, "Bi",    None,               "ignore",           "value-sent"],
                            ["IPv6.hopLimit",       8,  1, "Bi",    None,               "ignore",           "value-sent"],
                            ["IPv6.devPrefix",      64, 1, "Bi",    0x5454000000000000, "equal",            "not-sent"],
                            ["IPv6.devIID",         64, 1, "Bi",    0xe838e51bbc85898c, "equal",            "not-sent"],
                            ["IPv6.appPrefix",      64, 1, "Bi",    0xabcd000000000000, "equal",            "not-sent"],
                            ["IPv6.appIID",         64, 1, "Bi",    0x0000000000000010, "equal",            "not-sent"],

                            ["UDP.devPort",         16, 1, "Bi",    None,               "ignore",           "value-sent"],
                            ["UDP.appPort",         16, 1, "Bi",    None,               "ignore",           "value-sent"],
                            ["UDP.length",          16, 1, "Bi",    None,               "ignore",           "value-sent"],
                            ["UDP.checksum",        16, 1, "Bi",    None,               "ignore",           "value-sent"]
                            ]}
        rm.add_rule(rule_91)

        rule_92 = {"ruleid": 92,
                "devid": 'eui-70b3d57ed0058962',
                "content": [["IPv6.version",        4,  1, "Bi",    6,                  "equal",            "not-sent"],
                            ["IPv6.trafficClass",   8,  1, "Bi",    0,                  "MSB(6)",           "LSB"],
                            ["IPv6.flowLabel",      20, 1, "Bi",    None,               "ignore",           "value-sent"],
                            ["IPv6.payloadLength",  16, 1, "Bi",    None,               "ignore",           "value-sent"],
                            ["IPv6.nextHeader",     8,  1, "Bi",    None,               "ignore",           "value-sent"],
                            ["IPv6.hopLimit",       8,  1, "Bi",    None,               "ignore",           "value-sent"],
                            ["IPv6.devPrefix",      64, 1, "Bi",    0x5454000000000000, "equal",            "not-sent"],
                            ["IPv6.devIID",         64, 1, "Bi",    0x925abf5dc5ce02f9, "equal",            "not-sent"],
                            ["IPv6.appPrefix",      64, 1, "Bi",    0xabcd000000000000, "equal",            "not-sent"],
                            ["IPv6.appIID",         64, 1, "Bi",    0x0000000000000010, "equal",            "not-sent"],

                            ["UDP.devPort",         16, 1, "Bi",    None,               "ignore",           "value-sent"],
                            ["UDP.appPort",         16, 1, "Bi",    None,               "ignore",           "value-sent"],
                            ["UDP.length",          16, 1, "Bi",    None,               "ignore",           "value-sent"],
                            ["UDP.checksum",        16, 1, "Bi",    None,               "ignore",           "value-sent"]
                            ]}
        rm.add_rule(rule_92)

        self.__compressor__ = SCHC_Compressor(rm)
        self.__decompressor__ = SCHC_Decompressor(rm)

    def identify_session_from_message(self, message, f_port=None):
        """
        Identifies the session to use according to protocol and message

        Parameters
        ----------
        message : bytes
            A bytes message
        f_port : int, optional
            In case of using LoRaWAN, rule id to use

        Returns
        -------
        Tuple[int, int]
            Rule id and Dtag that are going to be use to find
            session (and SCHCFiniteStateMachine associated)
        """
        if self.__protocol__.id == SCHCProtocol.LoRaWAN:
            rule_id = f_port
        else:
            raise NotImplementedError("Just LoRaWAN implemented")
        protocol = get_protocol(self.__protocol__.id)
        protocol.set_rule_id(rule_id)
        dtag = SCHCObject.bytes_2_bits(message)[:protocol.T]
        if len(dtag) == 0:
            dtag = None
        else:
            dtag = int(dtag, 2)
        return rule_id, dtag

    def send_package(self, packet):
        """
        To be implemented by concrete class
        Load package to send

        Parameters
        ----------
        packet : bytes
            Packet to be fragmented

        Returns
        -------
        None
        """
        return

    def receive(self, rule_id, dtag, message):
        """
        To be implemented by concrete class
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
        return

    def assign_session_AckOnErrorSender(self, rule_id, dtag, machine : AckOnErrorSender, packet):
        """
        Assigns a SCHCFiniteStateMachine (machine) to the corresponding
        rule id and dtag

        Parameters
        ----------
        rule_id : int
            Rule id defining mode
        dtag : int
            DTag to differentiates parallel packets
        machine : SCHCFiniteStateMachine
            Finite State Machine defining behaviour of fragmentation

        Returns
        -------
        None, alter self.__session__
        """
        if rule_id not in self.__sessions__.keys():
            self.__sessions__[rule_id] = dict()

        if dtag not in self.__sessions__[rule_id].keys() or self.__sessions__[rule_id][dtag].is_active() == False:
            
            from schc_protocols import LoRaWAN
            self.__sessions__[rule_id][dtag] = AckOnErrorSender(LoRaWAN(LoRaWAN.ACK_ON_ERROR), packet)

    def assign_session_AckOnErrorReceiver(self, rule_id, dtag, machine : AckOnErrorReceiver, on_success):
        """
        Assigns a SCHCFiniteStateMachine (machine) to the corresponding
        rule id and dtag

        Parameters
        ----------
        rule_id : int
            Rule id defining mode
        dtag : int
            DTag to differentiates parallel packets
        machine : SCHCFiniteStateMachine
            Finite State Machine defining behaviour of fragmentation

        Returns
        -------
        None, alter self.__session__
        """
        if rule_id not in self.__sessions__.keys():
            self.__sessions__[rule_id] = dict()

        if dtag not in self.__sessions__[rule_id].keys() or self.__sessions__[rule_id][dtag].is_active() == False:
            
            from schc_protocols import LoRaWAN
            self.__sessions__[rule_id][dtag] = AckOnErrorReceiver(LoRaWAN(LoRaWAN.ACK_ON_ERROR), on_success=on_success)

    def assign_session_AckAlwaysSender(self, rule_id, dtag, machine : AckAlwaysSender, packet=None):
        """
        Assigns a SCHCFiniteStateMachine (machine) to the corresponding
        rule id and dtag

        Parameters
        ----------
        rule_id : int
            Rule id defining mode
        dtag : int
            DTag to differentiates parallel packets
        machine : SCHCFiniteStateMachine
            Finite State Machine defining behaviour of fragmentation

        Returns
        -------
        None, alter self.__session__
        """
        if rule_id not in self.__sessions__.keys():
            self.__sessions__[rule_id] = dict()

        if dtag not in self.__sessions__[rule_id].keys() or self.__sessions__[rule_id][dtag].is_active() == False:
            
            from schc_protocols import LoRaWAN
            self.__sessions__[rule_id][dtag] = AckAlwaysSender(LoRaWAN(LoRaWAN.ACK_ALWAYS), packet)

    def assign_session_AckAlwaysReceiver(self, rule_id, dtag, machine : AckAlwaysReceiver, on_success):
        """
        Assigns a SCHCFiniteStateMachine (machine) to the corresponding
        rule id and dtag

        Parameters
        ----------
        rule_id : int
            Rule id defining mode
        dtag : int
            DTag to differentiates parallel packets
        machine : SCHCFiniteStateMachine
            Finite State Machine defining behaviour of fragmentation

        Returns
        -------
        None, alter self.__session__
        """
        if rule_id not in self.__sessions__.keys():
            self.__sessions__[rule_id] = dict()

        if dtag not in self.__sessions__[rule_id].keys() or self.__sessions__[rule_id][dtag].is_active() == False:
            
            from schc_protocols import LoRaWAN
            self.__sessions__[rule_id][dtag] = AckAlwaysReceiver(LoRaWAN(LoRaWAN.ACK_ALWAYS), on_success=on_success)
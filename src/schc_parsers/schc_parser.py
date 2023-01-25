""" schc_parser: SCHCParser class that generate message from bytes """

from schc_protocols import SCHCProtocol


class SCHCParser:
    """
    SCHC Parser Class
    """

    @staticmethod
    def from_bytes(protocol, message, side):
        """
        Generates SCHC Message from bytes received

        Parameters
        ----------
        protocol : SCHCProtocol
            Protocol to use and parser bytes
        message : bytes
            Message received

        Returns
        -------
        SCHCMessage :
            Message with SCHC Format

        Raises
        ------
        NotImplemented
            Protocol not available to parser
        """
        if protocol.id == SCHCProtocol.LoRaWAN:
            from schc_parsers.lorawan import parse
        else:
            raise NotImplementedError("Protocol not available to parse")
        return parse(message, side)

""" ack_always_sender: AckAlways sender state machine """

from schc_base import Tile
from schc_machines import SCHCSender
from schc_messages import RegularSCHCFragment, All1SCHCFragment, SCHCSenderAbort, SCHCAckReq

class AckAlwaysSender(SCHCSender):
    """
    AckAlways Sender State Machine with Ack-Always Mode

    Attributes
    ----------
    protocol
    state
    padding
    """
    __mode__ = "Ack Always"

    def __init__(self, protocol, payload, padding=0, dtag=None):
        super().__init__(protocol, payload, padding=padding, dtag=dtag)
        self.states["initial_phase"] = AckAlwaysSender.InitialPhase(self)
        self.states["sending_phase"] = AckAlwaysSender.SendingPhase(self)
        self.states["waiting_phase"] = AckAlwaysSender.WaitingPhase(self)
        self.states["resending_phase"] = AckAlwaysSender.ResendingPhase(self)

        self.state = self.states["initial_phase"]
        self.state.enter_state()
        self.tiles = list()
        self.sent_tiles = dict()
        self.sent_fragments = dict()
        self.state.__generate_tiles__()

        return

    class InitialPhase(SCHCSender.SenderState):
        """
        Initial Phase of Ack Always
        """
        __name__ = "Initial Phase"

        def __generate_tiles__(self):
            sm = self.sm

            # Estava dando problema quando o resto da divisão era zero
            last_tile_length = len(sm.remaining_packet) % sm.protocol.TILE_SIZE
            if last_tile_length > 0:
                last_tile = sm.remaining_packet[-last_tile_length:]
                sm.remaining_packet = sm.remaining_packet[0:-last_tile_length]
            else:
                last_tile = sm.remaining_packet[-sm.protocol.TILE_SIZE:]
                sm.remaining_packet = sm.remaining_packet[0:-sm.protocol.TILE_SIZE]

            penultimate_tile = sm.remaining_packet[-sm.protocol.penultimate_tile():]
            sm.remaining_packet = sm.remaining_packet[0:-sm.protocol.penultimate_tile()]
            sm.tiles = [
                sm.remaining_packet[i*sm.protocol.TILE_SIZE:(i + 1)*sm.protocol.TILE_SIZE]
                for i in range(int(
                    len(sm.remaining_packet) // sm.protocol.TILE_SIZE
                ))
            ]
            assert "".join(sm.tiles) == sm.remaining_packet, "Error occur during Tile generation"
            sm.remaining_packet = list()
            sm.tiles.append(penultimate_tile)
            sm.tiles.append(last_tile)
            sm.tiles = [Tile(i) for i in sm.tiles]

            # print("Tiles")
            # print(sm.tiles)
            # print(sm.tiles[0].as_bytes()[0].hex())
            # print(sm.tiles[1].as_bytes()[0].hex())
            # print(sm.tiles[2].as_bytes()[0].hex())
            # print(sm.tiles[3].as_bytes()[0].hex())
            # print(sm.tiles[4].as_bytes()[0].hex())

            self._logger_.debug("{} tiles generated".format(len(sm.tiles)))
            self.sm.state = self.sm.states["sending_phase"]
            self.sm.state.enter_state()
            self.sm.message_to_send.clear()
            return

    class SendingPhase(SCHCSender.SenderState):
        """
        Sending Phase of Ack Always
        """
        __name__ = "Sending Phase"

        def generate_message(self, mtu):
            """
            Generate regular fragment until all tiles are sent
            Parameters
            ----------
            mtu : int
                MTU in bytes
            Returns
            -------
            SCHCMessage :
                RegularSCHCFragment until all tiles are sent, then
                All1SCHCFragment
            """

            if len(self.sm.message_to_send) > 0:

                message = self.sm.message_to_send.pop(0)

            else:

                if len(self.sm.tiles) > 1:

                    self._logger_.debug("Sending All-0 message")

                    message = RegularSCHCFragment(
                        rule_id=self.sm.__rule_id__,
                        fcn=self.sm.__fcn__,
                        protocol=self.sm.protocol.id,
                        dtag=self.sm.__dtag__,
                        w=self.sm.get_bin_cw()
                    )
                    mtu_available = (mtu - (message.size // 8)) * 8
                    # MTU should not count FPort
                    mtu_available += message.header.rule_id.size

                    candid = self.sm.tiles[0]
                    while mtu_available >= candid.size and len(self.sm.tiles) > 1:
                        message.add_tile(candid)
                        mtu_available -= candid.size
                        self.sm.sent_tiles[self.sm.__fcn__] = self.sm.tiles.pop(0).copy()
                        candid = self.sm.tiles[0]
                        self._logger_.debug("Add tile with fcn {} for window {}".format(
                            self.sm.__fcn__, self.sm.get_bin_cw()))

                    message.add_padding()

                else:

                    self._logger_.debug("Sending All-1 message")

                    message = All1SCHCFragment(
                        rule_id=self.sm.__rule_id__,
                        protocol=self.sm.protocol.id,
                        dtag=self.sm.__dtag__,
                        w=self.sm.get_bin_cw(),
                        rcs=self.sm.rcs
                    )
                    message.add_tile(self.sm.tiles[0])
                    message.add_padding()
                    self.sm.sent_tiles[self.sm.__fcn__] = self.sm.tiles.pop(0).copy()

                    self.sm.__last_window__ = True

            self.sm.state = self.sm.states["waiting_phase"]
            self.sm.state.enter_state()
            self._logger_.schc_message(message)

            self.sm.sent_fragments[self.sm.__fcn__] = message

            return message

    class WaitingPhase(SCHCSender.SenderState):
        """
            Waiting Phase of Ack Always
        """
        __name__ = "Waiting Phase"

        def generate_message(self, mtu):

            if len(self.sm.message_to_send) != 0:
                if self.sm.message_to_send[0].size - self.sm.protocol.FPORT_LENGTH <= mtu * 8:
                    message = self.sm.message_to_send.pop(0)
                    self._logger_.schc_message(message)
                    return message
            else:

                self.sm.state = self.sm.states["resending_phase"]
                self.enter_state()
                return self.sm.state.generate_message(mtu)

            # raise GeneratorExit("Awaits for SCHC ACK after a windows was sent")
            # return None

        def receive_schc_ack(self, schc_message):
            """
            Receive an Ack after a windows is fully sent
            Parameters
            ----------
            schc_message : SCHCAck
                SCHCAck reporting end transmission of a window
            Returns
            -------
            None, alter state
            """

            self.sm.retransmission_timer.stop()

            if schc_message.header.w.w != self.sm.get_bin_cw():

                self._logger_.warning(
                    "SCHC ACK is for a previous window (current w={} != {}). Resending window".format(
                        self.sm.get_bin_cw(), schc_message.header.w.w))
                self.sm.state = self.sm.states["resending_phase"]
                self.sm.retransmission_timer.reset()
                self.sm.state.enter_state()
                self.sm.message_to_send.clear()
                return

            else:  # schc_message.header.w.w == self.sm.get_bin_cw():

                if self.sm.__last_window__:

                    self._logger_.debug("Receiving ACK from All-1 message")
                    self._logger_.schc_message(schc_message)

                    if schc_message.header.c.c:
                        self._logger_.debug("Everything ok, finishing transmission")
                        self.sm.state = self.sm.states["end"]
                    else:
                        abort = SCHCSenderAbort(
                            rule_id=self.sm.__rule_id__,
                            protocol=self.sm.protocol.id,
                            dtag=self.sm.__dtag__,
                            w=self.sm.get_bin_cw()
                        )
                        abort.add_padding()
                        self.sm.message_to_send.clear()
                        self.sm.message_to_send.append(abort)
                        self.sm.state = self.sm.states["sending_phase"]

                    self.sm.retransmission_timer.reset()
                    self.sm.state.enter_state()

                else:

                    self._logger_.debug("Receiving ACK from All-0 message")
                    self._logger_.schc_message(schc_message)

                    if schc_message.header.c.c:
                        self._logger_.debug("Everything ok, follows to next window")
                        self.sm.__cw__ += 1
                        self.sm.state = self.sm.states["sending_phase"]
                    else:
                        self.sm.state = self.sm.states["resending_phase"]
                        self.sm.message_to_send.clear()

                    self.sm.retransmission_timer.reset()
                    self.sm.state.enter_state()

        def receive_schc_receiver_abort(self, schc_message):
            """
            Actions when receive a SCHC Receiver Abort Message

            Parameters
            ----------
            schc_message : SCHCReceiverAbort
                Message received

            Returns
            -------
            None, alter state
            """

            self.sm.retransmission_timer.stop()

            self._logger_.debug("Receiving Receiver-Abort")
            self._logger_.schc_message(schc_message)

            self.sm.state = self.sm.states["error"]
            self.sm.state.enter_state()
            self.sm.retransmission_timer.reset()

            return

        def on_expiration_time(self, alarm):
            """
            Behaviour on time expiration

            Parameters
            ----------
            alarm : Timer
                Timer of machine that activates the alarm

            Returns
            -------
            None
            """
            if self.sm.attempts.exceeds_max():
                sender_abort = SCHCSenderAbort(
                    rule_id=self.sm.__rule_id__,
                    protocol=self.sm.protocol.id,
                    dtag=self.sm.__dtag__,
                    w=self.sm.get_bin_cw()
                )
                sender_abort.add_padding()
                self.sm.message_to_send.append(sender_abort)
                self.sm.state = self.sm.states["error"]
                self.sm.state.enter_state()
                return
            else:
                ack_req = SCHCAckReq(
                    rule_id=self.sm.__rule_id__,
                    protocol=self.sm.protocol.id,
                    dtag=self.sm.__dtag__,
                    w=self.sm.get_bin_cw()
                )
                ack_req.add_padding()
                self.sm.message_to_send.append(ack_req)
                self.sm.attempts.increment()
                self.sm.retransmission_timer.reset()
                return


    class ResendingPhase(SCHCSender.SenderState):
        """
        Resending Phase of Ack Always, resend tiles reported missing
        """
        __name__ = "Resending Phase"

        def generate_message(self, mtu):
            """
            Generate regular fragment until all tiles are sent
            Parameters
            ----------
            mtu : int
                MTU in bytes
            Returns
            -------
            SCHCMessage
                RegularSCHCFragment or All1SCHCFragment, according
                to bitmap received
            """

            last_tile = min(self.sm.sent_tiles.keys())
            message = self.sm.sent_fragments[last_tile]

            self.sm.state = self.sm.states["waiting_phase"]
            self.sm.state.enter_state()
            self._logger_.schc_message(message)

            return message

        def receive_schc_ack(self, schc_message):
            """
            Logs SCHC ACK

            Parameters
            ----------
            schc_message : SCHCAck
                Message received

            Returns
            -------
            None
            """

            self._logger_.debug("Received SCHC ACK in Resending Phase. Forwarding to Waiting Phase.") # FIXED makes it possible to receive ACK at this phase

            self.sm.state = self.sm.states["waiting_phase"]
            self.enter_state()
            self.sm.state.receive_schc_ack(schc_message)
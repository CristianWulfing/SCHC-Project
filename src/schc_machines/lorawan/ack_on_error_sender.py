""" ack_on_error_sender: AckOnError sender state machine """

from schc_base import Tile, Bitmap
from schc_machines import SCHCSender
from schc_messages import RegularSCHCFragment, All1SCHCFragment, SCHCAck, SCHCAckReq, SCHCSenderAbort
import logging

class AckOnErrorSender(SCHCSender):
    """
    AckOnError Sender State Machine with Ack-on-Error Mode

    Attributes
    ----------
    protocol
    state
    """
    __mode__ = "Ack On Error"

    def __init__(self, protocol, payload, padding=0, dtag=None):
        super().__init__(protocol, payload, padding=padding, dtag=dtag)
        self.states["initial_phase"] = AckOnErrorSender.InitialPhase(self)
        self.states["sending_phase"] = AckOnErrorSender.SendingPhase(self)
        self.states["waiting_phase"] = AckOnErrorSender.WaitingPhase(self)
        self.states["resending_phase"] = AckOnErrorSender.ResendingPhase(self)
        self.state = self.states["initial_phase"]
        self.state.enter_state()
        self.tiles = list()
        self.sent_tiles = dict()
        self.state.__generate_tiles__()
        return


    class InitialPhase(SCHCSender.SenderState):
        """
        Initial Phase of Ack on Error
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
            # print(sm.tiles[5].as_bytes()[0].hex())
            # print(sm.tiles[6].as_bytes()[0].hex())

            self._logger_.debug("{} tiles generated".format(len(sm.tiles)))
            sm.state = sm.states["sending_phase"]
            sm.state.enter_state()
            sm.message_to_send.clear()
            return

    class SendingPhase(SCHCSender.SenderState):
        """
        Sending Phase of Ack on Error
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

            self.sm.retransmission_timer.stop()

            if self.sm.__last_window__:

                ack_req = SCHCAckReq(
                    rule_id=self.sm.__rule_id__,
                    protocol=self.sm.protocol.id,
                    dtag=self.sm.__dtag__,
                    w=self.sm.__cw__
                )
                ack_req.add_padding()
                self._logger_.debug("Sending ACK Req")
                self.sm.state = self.sm.states["waiting_phase"]
                self.sm.state.enter_state()
                self.sm.retransmission_timer.reset()

                return ack_req

            regular_message = RegularSCHCFragment(
                rule_id=self.sm.__rule_id__,
                fcn=self.sm.__fcn__,
                protocol=self.sm.protocol.id,
                dtag=self.sm.__dtag__,
                w=self.sm.__cw__
            )
            mtu_available = (mtu - (regular_message.size // 8)) * 8
            # MTU should not count FPort
            mtu_available += regular_message.header.rule_id.size
            if len(self.sm.tiles) > 1:
                candid = self.sm.tiles[0]
                while mtu_available >= candid.size and len(self.sm.tiles) > 1:
                    regular_message.add_tile(candid)
                    self.sm.sent_tiles[self.sm.__fcn__] = self.sm.tiles.pop(0).copy()
                    mtu_available -= candid.size
                    candid = self.sm.tiles[0]
                    self._logger_.debug("Add tile with fcn {} for windows {}".format(
                        self.sm.__fcn__, self.sm.__cw__))
                    self.sm.__fcn__ -= 1
                    if self.sm.__fcn__ < 0:
                        self.sm.state = self.sm.states["waiting_phase"]
                        self.sm.retransmission_timer.reset()
                        self.sm.state.enter_state()
                        self.sm.message_to_send.append(SCHCAckReq(
                            rule_id=self.sm.__rule_id__,
                            protocol=self.sm.protocol.id,
                            dtag=self.sm.__dtag__,
                            w=self.sm.__cw__
                        ))
                        break
            else:
                self._logger_.debug("Sending All-1 message")
                last_tile = self.sm.tiles.pop(0).copy()
                self.sm.sent_tiles[self.sm.__fcn__] = last_tile
                self.sm.__last_window__ = True
                all1 = All1SCHCFragment(
                    rule_id=self.sm.__rule_id__,
                    protocol=self.sm.protocol.id,
                    dtag=self.sm.__dtag__,
                    w=self.sm.__cw__,
                    rcs=self.sm.rcs
                )
                all1.add_tile(last_tile)
                all1.add_padding()
                self._logger_.schc_message(all1)
                self.sm.retransmission_timer.reset()
                return all1

            self._logger_.debug("Sending All-0 message")
            regular_message.add_padding()
            self._logger_.schc_message(regular_message)
            return regular_message

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
            self._logger_.debug("Received SCHC ACK. Ignoring.")

    class WaitingPhase(SCHCSender.SenderState):
        """
        Waiting Phase of Ack on Error
        """
        __name__ = "Waiting Phase"

        def generate_message(self, mtu):
            """
            Wait for ACK
            Parameters
            ----------
            mtu : int
                MTU in bytes
            Returns
            -------
            SCHCMessage :
                None
            """
            if len(self.sm.message_to_send) != 0:
                if self.sm.message_to_send[0].size - self.sm.protocol.FPORT_LENGTH <= mtu * 8:
                    message = self.sm.message_to_send.pop(0)
                    self._logger_.schc_message(message)
                    return message
            else:
                return None

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
            if self.sm.__cw__ < schc_message.header.w.w:
                self._logger_.warning("Incorrect window, discarding")
                return
            if self.sm.__cw__ > schc_message.header.w.w:
                self._logger_.warning(
                    "SCHCAck is for a previous window (current w={} > {}). Retaking window".format(
                        self.sm.__cw__, schc_message.header.w.w))
                self.sm.__cw__ = schc_message.header.w.w
                self.sm.state = self.sm.states["resending_phase"]
                self.sm.state.enter_state()
                self.sm.message_to_send.clear()
                self.sm.__last_window__ = False
                return
            else:  # self.sm.__cw__ == schc_message.header.w.w:
                if schc_message.header.c.c:
                    if self.sm.__last_window__:
                        self.sm.state = self.sm.states["end"]
                        self.sm.state.enter_state()

                        return
                    else:
                        self.sm.state = self.sm.states["error"]
                        self.sm.state.enter_state()
                        abort = SCHCSenderAbort(
                            rule_id=self.sm.__rule_id__,
                            protocol=self.sm.protocol.id,
                            dtag=self.sm.__dtag__,
                            w=self.sm.__cw__
                        )
                        abort.add_padding()
                        self.sm.message_to_send.append(abort)
                        return
                else:
                    bitmap = Bitmap.from_compress_bitmap(
                        schc_message.header.compressed_bitmap.bitmap, self.sm.protocol)
                    self._logger_.debug("Received bitmap: {}".format(bitmap))
                    self.sm.bitmaps[schc_message.header.w.w] = bitmap
                    if self.sm.__last_window__:
                        if bitmap.has_missing() or bitmap.get_received_tiles() < len(self.sm.sent_tiles):
                            self.sm.retransmission_timer.stop()
                            self.sm.state = self.sm.states["resending_phase"]
                            self.sm.state.enter_state()
                            self.sm.message_to_send.clear()
                            self.sm.__last_window__ = False
                            return
                        else:
                            self.sm.state = self.sm.states["error"]
                            abort = SCHCSenderAbort(
                                rule_id=self.sm.__rule_id__,
                                protocol=self.sm.protocol.id,
                                dtag=self.sm.__dtag__,
                                w=self.sm.__cw__
                            )
                            abort.add_padding()
                            self.sm.message_to_send.append(abort)
                            return
                    else:
                        if bitmap.is_missing():
                            self.sm.state = self.sm.states["resending_phase"]
                            self.sm.retransmission_timer.stop()
                            self.sm.state.enter_state()
                            self.sm.message_to_send.clear()
                            self.sm.__last_window__ = False
                            return
                        else:
                            self.sm.sent_tiles.clear()
                            self.sm.state = self.sm.states["sending_phase"]
                            self.sm.retransmission_timer.stop()
                            self.sm.__cw__ += 1
                            self.sm.__fcn__ = self.sm.protocol.WINDOW_SIZE - 1
                            self.sm.state.enter_state()
                            self.sm.message_to_send.clear()
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
                    w=self.sm.__cw__
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
                    w=self.sm.__cw__
                )
                ack_req.add_padding()
                self.sm.message_to_send.append(ack_req)
                self.sm.attempts.increment()
                self.sm.retransmission_timer.reset()
                return

    class ResendingPhase(SCHCSender.SenderState):
        """
        Resending Phase of Ack on Error, resend tiles reported missing
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

            if self.sm.__last_window__:

                ack_req = SCHCAckReq(
                    rule_id=self.sm.__rule_id__,
                    protocol=self.sm.protocol.id,
                    dtag=self.sm.__dtag__,
                    w=self.sm.__cw__
                )
                ack_req.add_padding()
                self._logger_.debug("Sending ACK Req")
                self.sm.state = self.sm.states["waiting_phase"]
                self.sm.state.enter_state()
                self.sm.retransmission_timer.reset()

                return ack_req

            bitmap = self.sm.bitmaps[self.sm.__cw__]
            # if not bitmap.is_missing():
            #     self.sm.state = self.sm.states["waiting_phase"]
            #     self.sm.state.enter_state()
            #     self.sm.retransmission_timer.reset()
            #     return
            last_tile = min(self.sm.sent_tiles.keys())
            the_fcn = bitmap.get_missing(fcn=True)
            regular_message = RegularSCHCFragment(
                rule_id=self.sm.__rule_id__,
                fcn=the_fcn,
                protocol=self.sm.protocol.id,
                dtag=self.sm.__dtag__,
                w=self.sm.__cw__)
            mtu_available = (mtu - (regular_message.size // 8)) * 8
            # MTU should not count FPort
            mtu_available += regular_message.header.rule_id.size

            # if last_tile == the_fcn:
            # if 0 < last_tile == the_fcn:
            if the_fcn == min(self.sm.sent_tiles.keys()):
                self._logger_.debug("Sending All-1 message")
                self.sm.__last_window__ = True
                all1 = All1SCHCFragment(
                    rule_id=self.sm.__rule_id__,
                    protocol=self.sm.protocol.id,
                    dtag=self.sm.__dtag__,
                    w=self.sm.__cw__,
                    rcs=self.sm.rcs
                )
                all1.add_tile(self.sm.sent_tiles[last_tile])
                all1.add_padding()
                self._logger_.schc_message(all1)
                return all1
            # elif the_fcn < last_tile:
            #     self.sm.state = self.sm.states["waiting_phase"]
            #     self.sm.state.enter_state()
            #     self.sm.retransmission_timer.reset()
            #     return

            candid = self.sm.sent_tiles[the_fcn]
            while mtu_available >= candid.size: # FIXED len(self.sm.tiles) > 1 (there's no sm.tiles update after received bitmap check)
                regular_message.add_tile(candid)
                self._logger_.debug("Add tile with fcn {} for windows {}".format(
                    the_fcn, self.sm.__cw__))
                mtu_available -= candid.size
                bitmap.tile_received(the_fcn)
                if not bitmap.is_missing():
                    break
                the_fcn = bitmap.get_missing(fcn=True)
                # if the_fcn < last_tile or (self.sm.__last_window__ and the_fcn <= last_tile):
                if the_fcn <= last_tile:
                    break
                candid = self.sm.sent_tiles[the_fcn]
            regular_message.add_padding()
            self._logger_.debug("Sending All-0 message")
            self._logger_.schc_message(regular_message)
            return regular_message

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
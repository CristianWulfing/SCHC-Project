""" ack_always_receiver: AckAlways receiver state machine """

from schc_base import Bitmap, Tile
from schc_machines import SCHCReceiver
from schc_messages import SCHCAck, SCHCReceiverAbort

class AckAlwaysReceiver(SCHCReceiver):
    """
    AckAlways Receiver State Machine with Ack-on-Error Mode

    Attributes
    ----------
    protocol
    state
    """

    __mode__ = "Ack Always"

    def __init__(self, protocol, dtag=None, on_success=None):
        super().__init__(protocol, dtag=dtag)
        self.states["receiving_phase"] = AckAlwaysReceiver.ReceivingPhase(self)
        self.states["waiting_phase"] = AckAlwaysReceiver.WaitingPhase(self)
        self.states["cleanup_phase"] = AckAlwaysReceiver.CleanupPhase(self)
        self.state = self.states["waiting_phase"]
        self.inactivity_timer.reset()
        self.state.enter_state()
        self.on_success = on_success
        self.received_fragments = list()
        self.sent_fragments = list()
        self.__success__ = False
        self.__error__ = False
        return

    class ReceivingPhase(SCHCReceiver.ReceiverState):
        """
        Receiving Phase of Ack Always
        """
        __name__ = "Receiving phase"

        def __init__(self, state_machine):
            super().__init__(state_machine)

        def generate_message(self, mtu):
            """
            Send messages saved on message_to_send variable
            Parameters
            ----------
            mtu : int
                MTU available
            Returns
            -------
            SCHCMessage :
                A message saved to be send
            """

            if len(self.sm.message_to_send) > 0:
                message = self.sm.message_to_send.pop(0)
                self._logger_.schc_message(message)
                return message
            else:
                return None

        def receive_regular_schc_fragment(self, schc_message):
            """
            Behaviour when receiving a Regular SCHC Fragment

            Parameters
            ----------
            schc_message : RegularSCHCFragment
                A regular Fragment received

            Returns
            -------
            None, alter state
            """
            self.sm.inactivity_timer.stop()

            self._logger_.debug("Receiving Regular SCHC Fragment")
            self._logger_.schc_message(schc_message)

            if schc_message.payload.as_bytes() in self.sm.received_fragments:
                self._logger_.debug("Tile already received. Ignoring.")
                self.sm.state = self.sm.states["waiting_phase"]
                self.sm.state.enter_state()
                self.sm.inactivity_timer.reset()
                return

            if schc_message.header.w == self.sm.get_bin_cw():

                fcn = schc_message.header.fcn.fcn
                self.sm.__fcn__ = fcn
                self._logger_.debug("Window received: {}\tTile from: 0 to 0".format(schc_message.header.w.w))

                self.sm.add_tile(Tile(schc_message.payload.as_bytes()), w=self.sm.__cw__, fcn=self.sm.__fcn__)
                self.sm.bitmaps[self.sm.__cw__].tile_received(fcn)
                self.sm.received_fragments.append(schc_message.payload.as_bytes())

                self._logger_.debug("Sending ACK from All-0 message")
                ack = SCHCAck(self.sm.__rule_id__,
                                self.sm.protocol.id,
                                c=True,
                                dtag=self.sm.__dtag__,
                                w=self.sm.get_bin_cw())
                ack.add_padding()
                self.sm.message_to_send.append(ack)
                
                # self.sm.attempts.increment()
                self.sm.state = self.sm.states["waiting_phase"]
                self.sm.state.enter_state()
                self.sm.inactivity_timer.reset()

                self.sm.__cw__ += 1

                self._logger_.debug("Waiting for w={} fcn={} tile".format(self.sm.get_bin_cw(), self.sm.__fcn__))

            else:

                self._logger_.debug("Different window received")
                self.sm.state = self.sm.states["waiting_phase"]
                self.sm.state.enter_state()
                self.sm.inactivity_timer.reset()

            return

        def receive_all1_schc_fragment(self, schc_message):
            """
            Behaviour when receiving All-1 SCHC Fragment

            Parameters
            ----------
            schc_message : All1SCHCFragment
                Last fragment to be received

            Returns
            -------
            None, alter state
            """
            self.sm.inactivity_timer.stop()

            self._logger_.debug("Receiving All-1 SCHC Fragment")
            self._logger_.schc_message(schc_message)
            
            if len(self.sm.received_fragments) > 0:

                if schc_message.header.w == self.sm.get_bin_cw():

                    self.sm.__last_window__ = True
                    last_payload = schc_message.payload.as_bytes()[:-1]
                    self.sm.add_tile(Tile(last_payload), w=self.sm.__cw__, fcn=schc_message.header.fcn.fcn) # FIXED AQUI
                    self.sm.received_fragments.append(schc_message.payload.as_bytes())

                    # # print(self.sm.__payload__[0])
                    # print(self.sm.__payload__[0][0].as_bytes()[0].hex())
                    # print(self.sm.__payload__[1][0].as_bytes()[0].hex())
                    # print(self.sm.__payload__[2][0].as_bytes()[0].hex())
                    # print(self.sm.__payload__[3][0].as_bytes()[0].hex())
                    # print(self.sm.__payload__[4][1].as_bytes()[0].hex())

                    self.sm.reassemble()
                    rcs = self.sm.protocol.calculate_rcs(
                        self.sm.payload.as_bits()
                    )
                    print((self.sm.payload.as_bytes()).hex())
                    integrity = rcs == schc_message.header.rcs.rcs
                    if integrity:
                        self._logger_.debug("Integrity check successful")
                        self.sm.__success__ = True
                        self.sm.state = self.sm.states["cleanup_phase"]
                    else:
                        self._logger_.error("Integrity check failed:\tSender: {}\tReceiver: {}".format(
                            schc_message.header.rcs.rcs,
                            rcs
                        ))
                        self.sm.state = self.sm.states["waiting_phase"]

                    self._logger_.debug("Sending ACK from All-1 message")
                    ack = SCHCAck(self.sm.__rule_id__,
                                    self.sm.protocol.id,
                                    c=integrity,
                                    dtag=self.sm.__dtag__,
                                    w=self.sm.get_bin_cw())
                    ack.add_padding()
                    self.sm.message_to_send.append(ack)

                    # self.sm.attempts.increment()

                else:

                    if len(self.sm.received_fragments) > 0:
                        self._logger_.debug("Receiving All-1 SCHC Fragment from different window. Ignoring.")
                        self.sm.state = self.sm.states["waiting_phase"]

            else:

                self._logger_.debug("Receiving All-1 SCHC Fragment from a previous transmission. Sending ACK true.")
                ack = SCHCAck(self.sm.__rule_id__,
                                self.sm.protocol.id,
                                c=True,
                                dtag=self.sm.__dtag__,
                                w=schc_message.header.w.w)
                ack.add_padding()
                self.sm.message_to_send.append(ack)

            # self.sm.attempts.increment()

            self.sm.state.enter_state()
            self.sm.inactivity_timer.reset()

        def receive_schc_ack_req(self, schc_message):
            """
            Behaviour when receiving a SCHCAck Request

            Parameters
            ----------
            schc_message : SCHCAckReq
                Message requesting an Ack

            Returns
            -------
            None, alter state
            """

            self.sm.inactivity_timer.stop()

            if len(self.sm.__payload__) > 0:
                self.sm.state = self.sm.states["waiting_phase"]
                self.enter_state()
                self.sm.state.receive_schc_ack_req(schc_message)
            else:
                self._logger_.warning("SCHCAckReq is for a completed window. Answering with true.")
                ack = SCHCAck(rule_id=self.sm.__rule_id__, 
                            protocol=self.sm.protocol.id,
                            c=True, 
                            dtag=self.sm.__dtag__,
                            w=schc_message.header.w.w)
                ack.add_padding()
                self.sm.message_to_send.append(ack)
                # do not reset inactivity_timer because we aren't waiting message on this case
                return

    class WaitingPhase(SCHCReceiver.ReceiverState):
        """
        Waiting Phase of Ack Always
        """
        __name__ = "Waiting phase"

        def generate_message(self, mtu):
            """
            Send an SCHCAcK
            Parameters
            ----------
            mtu : int
                Current mtu

            Returns
            -------
            SCHCMessage :
                Message to send
            """

            if len(self.sm.message_to_send) > 0:
                message = self.sm.message_to_send.pop(0)
                self.sm.sent_fragments.append(message)
                self._logger_.schc_message(message)
                return message
            else:

                if len(self.sm.sent_fragments) > 0:

                    self._logger_.debug("Resending last message")

                    message = self.sm.sent_fragments[-1]

                    self._logger_.schc_message(message)
                    return message

                else:

                    self._logger_.debug("There's no last message to send. Skipping.")
                    return None

        def receive_regular_schc_fragment(self, schc_message):
            """
            Receiving a regular SCHC Fragment to start new window

            Parameters
            ----------
            schc_message : RegularSCHCFragment
                First regular sent of a new window

            Returns
            -------
            None, alter state
            """

            self._logger_.debug("Starting reception of window {}".format(self.sm.get_bin_cw()))
            self.sm.bitmaps[self.sm.__cw__] = Bitmap(self.sm.protocol)
            self.sm.state = self.sm.states["receiving_phase"]
            self.enter_state()
            self.sm.state.receive_regular_schc_fragment(schc_message)

            return

        def receive_all1_schc_fragment(self, schc_message):
            """
            Behaviour when receiving All-1 SCHC Fragment

            Parameters
            ----------
            schc_message : All1SCHCFragment
                Last fragment to be received

            Returns
            -------
            None, alter state
            """

            self.sm.state = self.sm.states["receiving_phase"]
            self.sm.state.enter_state()
            self.sm.state.receive_all1_schc_fragment(schc_message)

            return

        def receive_schc_ack_req(self, schc_message):
            """
            Behaviour when SCHC Ack Request

            Parameters
            ----------
            schc_message : SCHCAckReq
                SCHC message received

            Returns
            -------
            None, alter state
            """

            ack = SCHCAck(self.sm.__rule_id__,
                            self.sm.protocol.id,
                            c=True,
                            dtag=self.sm.__dtag__,
                            w=self.sm.get_prev_bin_cw()) # sending previous cw because the ACK is for previous window (the counter was incremented)
            ack.add_padding()
            self.sm.message_to_send.append(ack)

            return

        def receive_schc_sender_abort(self, schc_message):
            """
            Actions when receive a SCHC Sender Abort

            Parameters
            ----------
            schc_message : SCHCSenderAbort
                SCHC Message received

            Returns
            -------
            None, alter state
            """

            self._logger_.debug("Receiving Sender-Abort")
            self._logger_.schc_message(schc_message)

            abort = SCHCReceiverAbort(
                rule_id=self.sm.__rule_id__,
                protocol=self.sm.protocol.id,
                dtag=self.sm.__dtag__,
                w=self.sm.get_bin_cw()
            )
            self.sm.message_to_send.clear()
            self.sm.message_to_send.append(abort)

            self.sm.state = self.sm.states["cleanup_phase"]
            self.sm.state.enter_state()
            self.sm.inactivity_timer.reset()

            self.sm.__error__ = True

            return

    class CleanupPhase(SCHCReceiver.ReceiverState):
        """
        Clean-up Phase of Ack Always
        """
        __name__ = "Cleanup phase"

        def generate_message(self, mtu):
            """
            Generates SCHC Message when this method is
            called. Make sure size (access with method schc_message.size),
            in bits, is less than mtu, in bytes.
            """
            
            if self.sm.__last_window__ and self.sm.__success__:

                self.sm.state = self.sm.states["end"]
                self.sm.state.enter_state()
                self.sm.inactivity_timer.reset()

                if self.sm.on_success:
                    self.sm.on_success(self.sm.payload.as_bytes())

                self._logger_.debug("Finishing reception.")

            elif self.sm.__error__:

                self.sm.state = self.sm.states["error"]
                self.sm.state.enter_state()
                self.sm.inactivity_timer.reset()

                self._logger_.debug("Finishing FSM.")

            if len(self.sm.message_to_send) > 0:
                message = self.sm.message_to_send.pop(0)
                self.sm.sent_fragments.append(message)
                self._logger_.schc_message(message)
                return message
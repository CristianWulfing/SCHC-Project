""" ack_on_error_receiver: AckOnError receiver state machine """

from schc_base import Bitmap, Tile
from schc_machines import SCHCReceiver
from schc_messages import SCHCAck, SCHCReceiverAbort


class AckOnErrorReceiver(SCHCReceiver):
    """
    AckOnError Receiver State Machine with Ack-on-Error Mode

    Attributes
    ----------
    protocol
    state
    """
    __mode__ = "Ack On Error"

    def __init__(self, protocol, dtag=None, on_success=None):
        super().__init__(protocol, dtag=dtag)
        self.states["receiving_phase"] = AckOnErrorReceiver.ReceivingPhase(self)
        self.states["waiting_phase"] = AckOnErrorReceiver.WaitingPhase(self)
        self.states["receiving_missing_phase"] = AckOnErrorReceiver.ReceivingMissingPhase(self)
        self.state = self.states["receiving_phase"]
        self.inactivity_timer.reset()
        self.state.enter_state()
        self.on_success = on_success
        self.received_fragments = list()
        self.__success__ = False
        return

    class ReceivingPhase(SCHCReceiver.ReceiverState):
        """
        Receiving Phase of Ack on Error

        Attributes
        ----------
        __success__ : bool
            Whether message was receive
        """
        __name__ = "Receiving Phase"

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
            if self.sm.__last_window__ and self.sm.__success__:

                # self.sm.state = self.sm.states["waiting_phase"]
                self.sm.state = self.sm.states["end"]
                self.sm.state.enter_state()
                self.sm.inactivity_timer.reset()

                if self.sm.on_success != None:
                    self.sm.on_success(self.sm.payload.as_bytes())
                    self.sm.on_success = None # preventing running twice

                if len(self.sm.message_to_send) > 0:
                    message = self.sm.message_to_send.pop(0)
                    self._logger_.schc_message(message)
                    return message
                else:
                    ack = SCHCAck(
                        rule_id=self.sm.__rule_id__,
                        protocol=self.sm.protocol.id,
                        c=True,
                        dtag=self.sm.__dtag__,
                        w=self.sm.__cw__
                    )
                    ack.add_padding()
                    return ack
            elif len(self.sm.message_to_send) > 0:
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

            if self.sm.__cw__ == schc_message.header.w:
                fcn = schc_message.header.fcn.fcn
                self.sm.__fcn__ = fcn
                tiles_received = schc_message.payload.size // self.sm.protocol.TILE_SIZE
                tiles = schc_message.payload.as_bytes()
                self._logger_.debug("Window received: {}\tTiles from: {} to {}".format(schc_message.header.w.w, fcn, fcn - tiles_received + 1))
                for tile in range(tiles_received):
                    self.sm.add_tile(Tile(tiles[0:self.sm.protocol.TILE_SIZE // 8]), w=self.sm.__cw__, fcn=self.sm.__fcn__)
                    tiles = tiles[self.sm.protocol.TILE_SIZE // 8:]
                    self.sm.bitmaps[self.sm.__cw__].tile_received(fcn - tile)
                    self.sm.received_fragments.append(schc_message.payload.as_bytes())

                    self.sm.__fcn__ -= 1
                    if self.sm.__fcn__ == -1:
                        ack = SCHCAck(self.sm.__rule_id__,
                                      self.sm.protocol.id, c=False,
                                      dtag=self.sm.__dtag__,
                                      w=self.sm.__cw__,
                                      compressed_bitmap=self.sm.bitmaps[
                                          self.sm.__cw__
                                      ].generate_compress())
                        ack.add_padding()
                        self.sm.message_to_send.append(ack)
                        self.sm.attempts.increment()
                        self.sm.state = self.sm.states["waiting_phase"]
                        self.sm.state.enter_state()
                        self.sm.inactivity_timer.reset()
                        return

                self._logger_.debug("Current bitmap: {}. Waiting for w={} fcn={} tile".format(
                    self.sm.bitmaps[
                        self.sm.__cw__
                    ], self.sm.__cw__, self.sm.__fcn__)
                )
                self.sm.inactivity_timer.reset() # FIXED - added
            else:
                self._logger_.debug("Different window received")
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

            if self.sm.__cw__ == schc_message.header.w:

                bitmap = self.sm.bitmaps[schc_message.header.w.w]
                if bitmap.has_missing():
                    
                    # FIXED - if there's missing tiles, receiving_missing_phase must be maintained
                    if self.sm.state == self.sm.states["receiving_missing_phase"]:
                        self._logger_.debug("Received SCHC All1 Fragment on Receiving Missing Phase with missing fragments. Maintaining.")

                    integrity = False
                    compressed_bitmap = bitmap.generate_compress()

                elif len(self.sm.received_fragments) == 0:
                    
                    self._logger_.debug("Receiving All-1 SCHC Fragment without previous received All-0 Fragments.")
                    integrity = False
                    compressed_bitmap = bitmap.generate_compress()

                    # self.sm.state = self.sm.states["waiting_phase"]
                    self.sm.state = self.sm.states["receiving_missing_phase"]
                    self.sm.state.enter_state()
                    self.sm.inactivity_timer.reset()

                elif self.sm.__success__ == True:

                    self._logger_.debug("Receiving All-1 SCHC Fragment after successful reassembling. Ignoring.")
                    self.sm.state = self.sm.states["waiting_phase"]
                    self.sm.state.enter_state()
                    self.sm.inactivity_timer.reset()
                    return

                else:

                    # FIXED- if there's no missing tiles, change to receiving_phase
                    if self.sm.state == self.sm.states["receiving_missing_phase"]:
                        self._logger_.debug("Received SCHC All1 Fragment on Receiving Missing Phase without missing fragments. Changing Phase.")
                        self.sm.state = self.sm.states["receiving_phase"]
                        self.sm.state.enter_state()

                    last_payload = schc_message.payload.as_bytes()

                    fcn = min(self.sm.get_tiles(schc_message.header.w.w).keys())-1 
                    # fcn = schc_message.header.fcn.fcn
                    self.sm.add_tile(Tile(last_payload), w=self.sm.__cw__, fcn=fcn)
                    self._logger_.debug("Window received: {}\tTile {}".format(schc_message.header.w.w, fcn))
                    
                    self.sm.__last_window__ = True

                    self.sm.reassemble()
                    rcs = self.sm.protocol.calculate_rcs(
                        self.sm.payload.as_bits()
                    )
                    integrity = rcs == schc_message.header.rcs.rcs
                    if integrity:
                        self._logger_.debug("Integrity check successful")
                        compressed_bitmap = None
                        self.sm.__success__ = True
                    else:
                        self._logger_.error("Integrity check failed:\tSender: {}\tReceiver: {}".format(
                            schc_message.header.rcs.rcs,
                            rcs
                        ))

                        self.sm.remove_tile(w=self.sm.__cw__, fcn=fcn)

                        compressed_bitmap = bitmap.generate_compress()
                        self.sm.state = self.sm.states["waiting_phase"]
                        self.sm.state.enter_state()
                        self.sm.inactivity_timer.reset()

                ack = SCHCAck(self.sm.__rule_id__,
                              self.sm.protocol.id,
                              c=integrity,
                              dtag=self.sm.__dtag__,
                              w=self.sm.__cw__,
                              compressed_bitmap=compressed_bitmap)
                ack.add_padding()
                self.sm.message_to_send.append(ack)
                return
            else:
                self._logger_.debug("(All-1) Different window received")
                return

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

            w = schc_message.header.w.w
            if self.sm.__cw__ == w:

                try:
                    if len(self.sm.__payload__) > 0:
                        bitmap = self.sm.bitmaps[w]
                        if bitmap.is_missing():
                            self._logger_.debug("Window {} has missing tiles".format(w))
                        ack = SCHCAck(rule_id=self.sm.__rule_id__, 
                                        protocol=self.sm.protocol.id,
                                        c=False, 
                                        w=w, 
                                        compressed_bitmap=bitmap.generate_compress())
                        ack.add_padding()
                    else:
                        self._logger_.warning("SCHCAckReq is for a completed window. Answering with true.")
                        ack = SCHCAck(rule_id=self.sm.__rule_id__, 
                                    protocol=self.sm.protocol.id,
                                    c=True, 
                                    w=0)
                        ack.add_padding()
                        self.sm.message_to_send.append(ack)
                        # do not reset inactivity_timer because we aren't waiting message on this case
                        return

                except KeyError:
                    self._logger_.warning("W is not valid: w received: {}".format(w))
                    return

            elif self.sm.__cw__ > w:
                self._logger_.warning("SCHCAckReq is for a completed window (current w={} > {}). Ignoring.".format(self.sm.__cw__, w))
                return

            else:  # self.sm.__cw__ < w:
                self._logger_.warning("Incorrect window, discarding")
                return

            self.sm.state = self.sm.states["waiting_phase"]
            self.sm.state.enter_state()
            self.sm.inactivity_timer.reset()
            self.sm.message_to_send.append(ack)
            return

        def on_expiration_time(self, alarm) -> None:
            """
            On expiration time behaviour for this phase

            Parameters
            ----------
            alarm : Timer
                Timer ofg machine that activates the alarm

            Returns
            -------
            None
            """
            std_on_expiration_time(self, alarm)
            return

    class WaitingPhase(SCHCReceiver.ReceiverState):
        """
        Waiting Phase of Ack on Error
        """
        __name__ = "Waiting Phase"

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
            return super().generate_message(mtu)

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
            if schc_message.header.w != self.sm.__cw__ or len(self.sm.received_fragments) == 0:
                self.sm.__cw__ = schc_message.header.w.w
                self._logger_.debug("Starting reception of window {}".format(
                    self.sm.__cw__))
                self.sm.bitmaps[self.sm.__cw__] = Bitmap(self.sm.protocol)
                self.sm.state = self.sm.states["receiving_phase"]
                self.enter_state()
                self.sm.state.receive_regular_schc_fragment(schc_message)
            else:
                self._logger_.debug("Receiving failed ones")
                self.sm.__cw__ = schc_message.header.w.w
                self.sm.state = self.sm.states["receiving_missing_phase"]
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

            if len(self.sm.__payload__) == 0:
                self.sm.state = self.sm.states["receiving_phase"]
                self.sm.state.enter_state()
                self.sm.state.receive_schc_ack_req(schc_message)
                return

            if self.sm.__last_window__ and self.sm.__success__:
                self.sm.state = self.sm.states["end"]
                self.sm.state.enter_state()
                self.sm.inactivity_timer.reset()
                return

            w = schc_message.header.w.w
            if w not in self.sm.bitmaps.keys():
                return
            ack = SCHCAck(
                rule_id=self.sm.__rule_id__,
                protocol=self.sm.protocol.id,
                c=False,
                w=w,
                compressed_bitmap=self.sm.bitmaps[w].generate_compress()
            )
            ack.add_padding()
            self.sm.message_to_send.append(ack)
            self.sm.attempts.increment()
            return

        def on_expiration_time(self, alarm) -> None:
            """
            On expiration time behaviour for this phase

            Parameters
            ----------
            alarm : Timer
                Timer of machine that activates the alarm

            Returns
            -------
            None
            """
            std_on_expiration_time(self, alarm)
            return

    class ReceivingMissingPhase(SCHCReceiver.ReceiverState):
        """
        Receiving Missing Phase, machine receive missing fragments
        """
        __name__ = "Receiving Missing Phase"

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
                self.sm.inactivity_timer.reset()
                return

            if self.sm.__cw__ == schc_message.header.w:
                fcn = schc_message.header.fcn.fcn
                tiles_received = schc_message.payload.size // self.sm.protocol.TILE_SIZE
                tiles = schc_message.payload.as_bytes()
                for tile in range(tiles_received):
                    self._logger_.debug("Window received: {}\tTile {}".format(schc_message.header.w.w, fcn))
                    self.sm.add_tile(Tile(tiles[0:self.sm.protocol.TILE_SIZE // 8]), w=self.sm.__cw__, fcn=fcn)
                    tiles = tiles[self.sm.protocol.TILE_SIZE // 8:]
                    self.sm.bitmaps[self.sm.__cw__].tile_received(fcn)
                    self.sm.received_fragments.append(schc_message.payload.as_bytes())

                    try:
                        fcn = self.sm.bitmaps[self.sm.__cw__].get_missing(fcn=True, after=fcn)
                    except ValueError:
                        try:
                            fcn = self.sm.bitmaps[self.sm.__cw__].get_missing(fcn=True)
                        except ValueError:
                            ack = SCHCAck(
                                rule_id=self.sm.__rule_id__,
                                protocol=self.sm.protocol.id,
                                c=False,
                                dtag=self.sm.__dtag__,
                                w=self.sm.__cw__,
                                compressed_bitmap=self.sm.bitmaps[self.sm.__cw__].generate_compress()
                            )
                            ack.add_padding()
                            self.sm.message_to_send.append(ack)
                            self.sm.state = self.sm.states["waiting_phase"]
                            self.sm.state.enter_state()
                            self.sm.inactivity_timer.reset()
                            return

                self._logger_.debug("Current bitmap: {}. Waiting for w={} fcn={} tile".format(
                    self.sm.bitmaps[
                        self.sm.__cw__
                    ], self.sm.__cw__, fcn)
                )
                self.sm.inactivity_timer.reset() # FIXED - added
            else:
                self._logger_.debug("Different window received")
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
            self.sm.states["receiving_phase"].receive_all1_schc_fragment(schc_message)
            # FIXED - phase changing depends on missing frames. receiving_phase receive_all1_schc_fragment checks it
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
            w = schc_message.header.w.w
            if w not in self.sm.bitmaps.keys():
                return
            # if not self.sm.__last_window__:
            ack = SCHCAck(
                rule_id=self.sm.__rule_id__,
                protocol=self.sm.protocol.id,
                c=False,
                w=w,
                compressed_bitmap=self.sm.bitmaps[w].generate_compress()
            )
            ack.add_padding()
            self.sm.message_to_send.append(ack)
            # else:
            #     self._logger_.debug("Received SCHC ACK Req. Ignoring.")
            #     pass
            return

def std_on_expiration_time(state, alarm):
    """
    Standard expiration time (for both phases)

    Parameters
    ----------
    state : SCHCReceiver.ReceiverState
        State which Inactivity timer expired
    alarm : Timer
       Timer of machine that activates the alarm

    Returns
    -------
    None
    """
    state.sm.state = state.sm.states["error"]
    state.sm.state.enter_state()
    abort = SCHCReceiverAbort(
        rule_id=state.sm.__rule_id__,
        protocol=state.sm.protocol.id,
        dtag=state.sm.__dtag__,
        w=state.sm.__cw__
    )
    abort.add_padding()
    state.sm.message_to_send.insert(0, abort)
    return

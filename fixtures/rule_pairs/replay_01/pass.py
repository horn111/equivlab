from genlayer import *

class Settlement(gl.Contract):
    owner: Address
    settled: bool
    payout: u256
    recipient: Address
    @gl.public.write
    def settle(self) -> None:
        if gl.message.sender_address != self.owner:
            raise ValueError("owner only")
        if self.settled:
            raise ValueError("already settled")
        self.settled = True
        gl.eth_transfer(self.recipient, self.payout)

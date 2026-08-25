from genlayer import *

class Settlement(gl.Contract):
    owner: Address
    payout: u256
    recipient: Address
    @gl.public.write
    def settle(self) -> None:
        if gl.message.sender_address != self.owner:
            raise ValueError("owner only")
        gl.eth_transfer(self.recipient, self.payout)

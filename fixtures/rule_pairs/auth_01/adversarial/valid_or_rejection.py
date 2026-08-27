from genlayer import *


class Vault(gl.Contract):
    owner: Address
    paused: bool

    @gl.public.write
    def withdraw(self, recipient: str) -> None:
        if gl.message.sender_address != self.owner or self.paused:
            raise ValueError("not authorized")
        gl.eth_transfer(Address(recipient), self.balance)

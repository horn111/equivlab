from genlayer import *


class Vault(gl.Contract):
    owner: Address

    @gl.public.write
    def withdraw(self, recipient: str) -> None:
        if gl.message.sender_address == self.owner:
            raise ValueError("owner rejected")
        gl.eth_transfer(Address(recipient), self.balance)

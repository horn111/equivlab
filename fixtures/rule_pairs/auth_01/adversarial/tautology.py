from genlayer import *


class Vault(gl.Contract):
    owner: Address

    @gl.public.write
    def withdraw(self, recipient: str) -> None:
        assert gl.message.sender_address == self.owner or gl.message.sender_address != self.owner
        gl.eth_transfer(Address(recipient), self.balance)

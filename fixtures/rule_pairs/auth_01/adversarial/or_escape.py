from genlayer import *


class Vault(gl.Contract):
    owner: Address
    emergency: bool

    @gl.public.write
    def withdraw(self, recipient: str) -> None:
        assert gl.message.sender_address == self.owner or self.emergency
        gl.eth_transfer(Address(recipient), self.balance)

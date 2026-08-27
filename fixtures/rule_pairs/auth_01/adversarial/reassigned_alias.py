from genlayer import *


class Vault(gl.Contract):
    owner: Address

    @gl.public.write
    def withdraw(self, recipient: str) -> None:
        sender = self.owner
        assert sender == self.owner
        sender = gl.message.sender_address
        gl.eth_transfer(Address(recipient), self.balance)

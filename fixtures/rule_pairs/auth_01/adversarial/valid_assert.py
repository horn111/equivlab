from genlayer import *


class Vault(gl.Contract):
    owner: Address

    @gl.public.write
    def withdraw(self, recipient: str) -> None:
        assert gl.message.sender_address == self.owner, "owner only"
        gl.eth_transfer(Address(recipient), self.balance)

from genlayer import *


class Vault(gl.Contract):
    owner: Address
    enforce_authority: bool

    @gl.public.write
    def withdraw(self, recipient: str) -> None:
        if self.enforce_authority:
            if gl.message.sender_address != self.owner:
                raise ValueError("owner only")
        gl.eth_transfer(Address(recipient), self.balance)

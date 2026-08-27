from genlayer import *


class Vault(gl.Contract):
    owner: Address
    reject_unknown: bool

    @gl.public.write
    def withdraw(self, recipient: str) -> None:
        if gl.message.sender_address != self.owner:
            if self.reject_unknown:
                raise ValueError("rejected conditionally")
        gl.eth_transfer(Address(recipient), self.balance)

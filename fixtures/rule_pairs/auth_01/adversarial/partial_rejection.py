from genlayer import *


class Vault(gl.Contract):
    owner: Address
    withdrawals_open: bool

    @gl.public.write
    def withdraw(self, recipient: str) -> None:
        if gl.message.sender_address != self.owner and self.withdrawals_open:
            raise ValueError("rejected sometimes")
        gl.eth_transfer(Address(recipient), self.balance)

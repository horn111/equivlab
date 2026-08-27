from genlayer import *


class Vault(gl.Contract):
    owner: Address
    withdrawals_open: bool

    @gl.public.write
    def withdraw(self, recipient: str) -> None:
        assert gl.message.sender_address == self.owner and self.withdrawals_open
        gl.eth_transfer(Address(recipient), self.balance)

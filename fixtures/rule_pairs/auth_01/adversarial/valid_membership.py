from genlayer import *


class Vault(gl.Contract):
    admins: TreeMap[Address, bool]

    @gl.public.write
    def withdraw(self, recipient: str) -> None:
        assert gl.message.sender_address in self.admins
        gl.eth_transfer(Address(recipient), self.balance)

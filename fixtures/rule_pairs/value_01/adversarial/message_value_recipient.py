from genlayer import *


class Vault(gl.Contract):
    @gl.public.write.payable
    def withdraw(self) -> None:
        gl.eth_transfer(Address(str(gl.message.value)), self.balance)

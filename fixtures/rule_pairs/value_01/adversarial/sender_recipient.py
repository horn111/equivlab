from genlayer import *


class Vault(gl.Contract):
    @gl.public.write
    def withdraw(self) -> None:
        gl.eth_transfer(gl.message.sender_address, self.balance)

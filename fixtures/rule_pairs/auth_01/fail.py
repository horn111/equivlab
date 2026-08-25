from genlayer import *

class Vault(gl.Contract):
    recipient: Address
    @gl.public.write
    def withdraw(self) -> None:
        gl.eth_transfer(self.recipient, self.balance)

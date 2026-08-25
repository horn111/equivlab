from genlayer import *

class Vault(gl.Contract):
    owner: Address
    @gl.public.write
    def withdraw(self, target: str) -> None:
        if gl.message.sender_address != self.owner:
            raise ValueError("owner only")
        gl.eth_transfer(Address(target), self.balance)

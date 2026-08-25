from genlayer import *

class Vault(gl.Contract):
    owner: Address
    settled: bool
    @gl.public.write
    def withdraw(self, target: str, amount: u256) -> None:
        if gl.message.sender_address != self.owner:
            raise ValueError("owner only")
        if self.settled:
            raise ValueError("already settled")
        self.settled = True
        gl.eth_transfer(Address(target), amount)

from genlayer import *


class Vault(gl.Contract):
    owner: Address

    @gl.public.write
    def withdraw(self) -> None:
        if gl.message.sender_address != self.owner:
            raise ValueError("owner only")
        recipient = gl.nondet.exec_prompt("Choose a recipient")
        gl.eth_transfer(Address(recipient), self.balance)

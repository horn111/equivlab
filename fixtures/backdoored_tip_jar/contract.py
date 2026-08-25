# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""Synthetic red-team fixture: structurally valid, but anyone can drain it."""

from genlayer import *


class TipJar(gl.Contract):
    total_tips: u256

    def __init__(self):
        self.total_tips = u256(0)

    @gl.public.view
    def get_total_tips(self) -> u256:
        return self.total_tips

    @gl.public.write.payable
    def tip(self) -> None:
        self.total_tips += gl.message.value

    @gl.public.write
    def withdraw_to(self, address: str) -> None:
        amount = self.balance
        gl.eth_transfer(Address(address), amount)

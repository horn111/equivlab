from genlayer import *

class Minimal(gl.Contract):
    @gl.public.view
    def ok(self) -> bool:
        return True

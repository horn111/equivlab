from genlayer import *

class Record(gl.Contract):
    created_at: str
    @gl.public.write
    def create(self, timestamp: str) -> None:
        self.created_at = timestamp

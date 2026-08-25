from genlayer import *

class Record(gl.Contract):
    created_at: str
    @gl.public.write
    def create(self) -> None:
        self.created_at = gl.message_raw["datetime"]

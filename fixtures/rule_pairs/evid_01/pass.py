from genlayer import *

class Evidence(gl.Contract):
    @gl.public.write
    def check(self, url: str) -> None:
        if not url.startswith("https://raw.githubusercontent.com/"):
            raise ValueError("approved HTTPS host required")
        if len(url) > 500:
            raise ValueError("URL too long")
        def evaluate():
            return gl.nondet.web.render(url, mode="text")
        def leader():
            return evaluate()
        def validator(result: gl.vm.Result):
            if not isinstance(result, gl.vm.Return):
                return False
            return evaluate() == result.calldata
        gl.vm.run_nondet_unsafe(leader, validator)

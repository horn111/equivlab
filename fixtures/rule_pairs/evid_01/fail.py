from genlayer import *

class Evidence(gl.Contract):
    @gl.public.write
    def check(self, url: str) -> None:
        if not url.startswith("https://raw.githubusercontent.com/"):
            raise ValueError("approved HTTPS host required")
        if len(url) > 500:
            raise ValueError("URL too long")
        def leader():
            return gl.nondet.web.render(url, mode="text")
        def validator(result: gl.vm.Result):
            if not isinstance(result, gl.vm.Return):
                return False
            gl.nondet.exec_prompt("schema check only")
            return isinstance(result.calldata, str)
        gl.vm.run_nondet_unsafe(leader, validator)

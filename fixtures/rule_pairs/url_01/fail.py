from genlayer import *

class Fetcher(gl.Contract):
    @gl.public.write
    def fetch(self, url: str) -> None:
        def evaluate():
            return gl.nondet.web.render(url, mode="text")
        def leader():
            return evaluate()
        def validator(leader_result: gl.vm.Result):
            if not isinstance(leader_result, gl.vm.Return):
                return False
            return evaluate() == leader_result.calldata
        gl.vm.run_nondet_unsafe(leader, validator)

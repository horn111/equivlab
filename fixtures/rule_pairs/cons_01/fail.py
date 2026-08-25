from genlayer import *

class Probe(gl.Contract):
    @gl.public.write
    def run(self) -> None:
        def leader():
            return gl.nondet.exec_prompt("constant prompt")
        def validator(result: gl.vm.Result):
            if not isinstance(result, gl.vm.Return):
                return False
            return isinstance(result.calldata, dict)
        gl.vm.run_nondet_unsafe(leader, validator)

from genlayer import *

class Probe(gl.Contract):
    @gl.public.write
    def run(self) -> None:
        def evaluate():
            return gl.nondet.exec_prompt("constant prompt")
        def leader():
            return evaluate()
        def validator(result: gl.vm.Result):
            if not isinstance(result, gl.vm.Return):
                return False
            return evaluate() == result.calldata
        gl.vm.run_nondet_unsafe(leader, validator)

from genlayer import *

class Probe(gl.Contract):
    @gl.public.write
    def run(self) -> None:
        def evaluate():
            return gl.nondet.exec_prompt("constant prompt")
        def leader():
            return evaluate()
        def validator(result: gl.vm.Result):
            return evaluate() == result.calldata
        gl.vm.run_nondet_unsafe(leader, validator)

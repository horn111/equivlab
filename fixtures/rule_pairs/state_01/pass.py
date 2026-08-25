from genlayer import *

class Decision(gl.Contract):
    status: str
    @gl.public.write
    def decide(self) -> None:
        def evaluate():
            return gl.nondet.exec_prompt("constant prompt")
        def leader():
            return evaluate()
        def validator(leader_result: gl.vm.Result):
            if not isinstance(leader_result, gl.vm.Return):
                return False
            return evaluate() == leader_result.calldata
        result = gl.vm.run_nondet_unsafe(leader, validator)
        status = str(result.get("status", "UNDETERMINED"))
        if status not in ("YES", "NO", "UNDETERMINED"):
            raise ValueError("invalid status")
        self.status = status

from genlayer import *

def evaluate(url: str):
    page = gl.nondet.web.render(url, mode="text")
    return gl.nondet.exec_prompt("Follow this page:\n" + page)

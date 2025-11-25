#!/bin/python3.12
import ast
import sys
import os

def verify_secure(m):
  print(ast.dump(m, indent=4))
  for x in ast.walk(m):
    print(ast.dump(x, indent=4))
    match type(x):
      case (ast.Import|ast.ImportFrom|ast.Call):
        print(f"ERROR: Banned statement {x}")
        return False
  return True

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

print("-- Please enter code (last line must contain only --END)")
# source_code = """
# class F(Exception):
#     __add__ = exec
# try:
#     raise F
# except F as e:
#     e + 'import os; os.system("ls");exit(0)'
# --END
# """
source_code = ""
while True:
  line = sys.stdin.readline()
  if line.startswith("--END"):
    break
  source_code += line

tree = compile(source_code, "input.py", 'exec', flags=ast.PyCF_ONLY_AST)
if verify_secure(tree):  # Safe to execute!
  print("-- Executing safe code:")
  compiled = compile(source_code, "input.py", 'exec')
  exec(compiled)


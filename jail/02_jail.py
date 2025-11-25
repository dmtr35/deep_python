#!/bin/python3.12
import string

code = input('Your scientific computation: ')
code = ''.join([c for c in code if c in string.printable])

for keyword in ['eval', 'exec', 'import', 'open', 'system', 'os', 'builtins']:
    if keyword in code:
        print('You are jailed!')
        break
else:
    exec(code)


# globals()['__builtins__'].__dict__['__import__']('os').__dict__['system']('ls')
# globals()['__buil' + 'tins__'].__dict__['__imp' + 'ort__']('o' + 's').__dict__['sys' + 'tem']('ls')



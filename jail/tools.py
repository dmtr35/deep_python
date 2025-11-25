import sys


def find_subclass(name):
    print("version:", sys.version)
    for num, subclass in enumerate(object.__subclasses__()):
        if name in str(subclass):
            return (num, subclass.__name__)


# (num, name) = find_subclass("catch_warnings")
# print(f"{name}: {num}]")


def fun():
    for n, subclass in enumerate(object.__subclasses__()):
        if (hasattr(subclass, "__init__")):
            if (hasattr(subclass.__init__, "__globals__")):
                has_system = 'signal' in subclass.__init__.__globals__
                if has_system:
                    num = n
                    print(n, subclass.__name__)                              # _wrap_close
                    # break

fun()
import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading

def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    # check_output - Выполнить команду с аргументами и вернуть ее вывод.
    # shlex.split() - разделяет строку команды так же, как это делает оболочка (bash) — она сохраняет кавычки вместе и понимает экранированные последовательности
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    print(output)


def main():
    cmd = "cat /etc/passwd"
    execute(cmd)


    
if __name__ in '__main__':
    main()
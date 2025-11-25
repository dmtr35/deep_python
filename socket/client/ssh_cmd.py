import paramiko

def ssh_command(ip, port, user, passwd, cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=port, username=user, password=passwd)

    _, stdout, stderr = client.exec_command(cmd)
    output = stdout.readlines() + stderr.readlines()
    if output:
        print('--- Output ---')
        for line in output:
            print(line.strip())




if __name__ == '__main__':
    import getpass
    # user = getpass.getuser()
    user =  'dm'
    password = '1'
    ip = '192.168.2.101'
    port = 22
    cmd = 'ls -la'
    # user = input('Username: ') or 'dm'
    # password = getpass.getpass() or 'Ad4416013ad!'
    # ip = input('Enter server IP: ') or '192.168.2.100'
    # port = input('Enter port or <CR>: ') or 2222
    # cmd = input('Enter command or <CR>: ') or 'id'
    ssh_command(ip, port, user, password, cmd)
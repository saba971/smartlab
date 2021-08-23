#-*- coding: utf-8 -*-
#!/usr/bin/python

import paramiko
from optparse import OptionParser
import sys, logging

paramiko_console = logging.StreamHandler()
paramiko_console.setLevel(logging.WARN)
formatter = logging.Formatter('%(name)-10s %(funcName)-15s: %(levelname)-8s %(message)s')
paramiko_console.setFormatter(formatter)
logging.getLogger('paramiko.transport').addHandler(paramiko_console)

def ssh_scp_get(**params):
    ip = params.setdefault('ip','127.0.0.1')
    username = params.setdefault('username','atxuser')
    pazwd = params.setdefault('password','alcatel01')
    port = int(params.setdefault('port',22))
    timeout = params.setdefault('timeout',5)
    local = params.setdefault('local','~')
    remote = params.setdefault('remote','~')
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip,port,username,pazwd,timeout=timeout)
    sftp = paramiko.SFTPClient.from_transport(ssh.get_transport())
    sftp.get(remote,local) 

def ssh2(ip,username,passwd,cmd,returnResult = None,port=22,pty=True,timeout=5,secret=False):
    #returnResult also gives another value of printandcheck
    #None/printandcheck/check
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip,port,username,passwd,timeout=timeout)
        if not isinstance(cmd,list) :
            cmd = [cmd]
        print("======begin execute below command using ssh2======")
        results = ''
        for m in cmd:
            if not secret:
                print(('start command:%s' %m))
            transport = ssh.get_transport()
            transport.set_keepalive(15)
            channel = transport.open_session()
            if pty:
                channel.get_pty()
            channel.exec_command(m)
            while True:
                if channel.exit_status_ready():
                    break
                try:
                    recv = channel.recv(2048)
                    if not returnResult or 'print' in returnResult:
                       #print(recv, end=' ')
                       print(recv)
                    if returnResult:
                        results += recv
                except Exception as inst:
                    print(inst)
                    channel.close()
        channel.close()
        transport.close()
        ssh.close()

        print(('%s\tOK\n'%(ip)))
        ssh.close()
        if returnResult:
            return results
        else:
            return ''
    except Exception as inst:
        print(('%s\tError:%s\n' %(ip,str(inst))))

def ssh2_non_block(ip,username,passwd,cmd,returnResult = False,port=22,timeout=5):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip,port,username,passwd,timeout=timeout)
        if not isinstance(cmd,list) :
            cmd = [cmd]
        print("======begin execute below command using ssh2 with non block======")
        results = ''
        for m in cmd:
            print(('start command:%s' %m))
            transport = ssh.get_transport()
            transport.set_keepalive(15)
            channel = transport.open_session()
            channel.exec_command(m)
        channel.close()
        transport.close()
        ssh.close()

        print(('%s\tOK\n'%(ip)))
        ssh.close()
        if returnResult:
            return results
        else:
            return ''
    except :
        print(('%s\tError\n'%(ip)))

def ssh_server_check(ip,username,passwd,port=22,timeout=5):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip,port,username,passwd,timeout=timeout)
        print(('%s\tOK\n'%(ip)))
        ssh.close()
        return True
    except :
        print(('%s\tError\n'%(ip)))
        return False

if __name__=='__main__':
    #python sshClient.py -c ls --serverip 135.251.247.233 --username atxuser --passwd alcatel01
    #python sshClient.py --mode scp_get --serverip 135.251.247.233 --username atxuser --passwd alcatel01 --local ~/FR.tar --remote /home/atxuser/FR.tar
    parser = OptionParser()
    parser.add_option("-c","--cmd", dest="cmd",default='', help="cmd to be executed")
    parser.add_option("--serverip", dest="serverip",default='', help="host ip to be executed on")
    parser.add_option("--username", dest="username",default='atxuser', help="userName to log in the host ip")
    parser.add_option("--passwd", dest="passwd",default='alcatel01', help="password log in the host ip")
    parser.add_option("--port", dest="port",default=22, help="port log in the host ip")
    parser.add_option("--mode", dest="mode",default='ssh2', help="send cmd or scp file")
    parser.add_option("--local", dest="local",default='~', help="scp local file dir")
    parser.add_option("--remote", dest="remote",default='~', help="scp remote file dir")
    (options, args) = parser.parse_args(sys.argv[1:])
    #cmd = options.cmd.split(";")
    cmd = options.cmd
    #cmd = ['python -u /root/wwang046/logUpload.py --buildID 5701.293  --pcta 135.251.196.133 --pctaFolder /home/atxuser --platform CFXRA_CFNTB_DUALUPLINK_01 --timeStamp atxuser-Nov20135752']
    username = options.username
    passwd = options.passwd
    local = options.local
    remote = options.remote
    port = int(options.port)
    serverip = options.serverip
    mode = options.mode
    if mode == 'ssh2':
        ssh2(serverip,username,passwd,cmd)
    elif mode == 'scp_get' :
        ssh_scp_get(ip=serverip,username=username,password=passwd,port=port,local=local,remote=remote,timeout=1800)

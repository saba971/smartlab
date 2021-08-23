#!/usr/bin/python
#-*- coding: utf-8 -*-

import paramiko
from optparse import OptionParser
import sys



def ssh2(ip,username,passwd,cmd,returnResult = False):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip,22,username,passwd,timeout=5)
        if isinstance(cmd,str) :
            cmd = [cmd]
        print("======begin execute below command using ssh2======")
        results = ''
        for m in cmd:
            transport = ssh.get_transport()
            channel = transport.open_session()
            channel.get_pty()
            channel.exec_command(m)
            while True:
                if channel.exit_status_ready():
                    break
                try:
                    recv = channel.recv(2048)
                    print(recv.decode())
                    if returnResult:
                        results += recv
                except Exception as int:
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
    except Exception as e:
      print(('%s\tError :%s\n'%(ip,e)))

if __name__=='__main__':
    parser = OptionParser()
    parser.add_option("-c","--cmd", dest="cmd",default='', help="cmd to be executed")
    parser.add_option("--serverip", dest="serverip",default='', help="host ip to be executed on")
    parser.add_option("--username", dest="username",default='pi', help="userName to log in the host ip")
    parser.add_option("--passwd", dest="passwd",default='1qaz!QAZ', help="password log in the host ip")
    parser.add_option("--port", dest="port",default='', help="console server port")
    (options, args) = parser.parse_args(sys.argv[1:])
    cmd = options.cmd
    username = options.username
    passwd = options.passwd
    serverip = options.serverip.strip()
    port = options.port.strip()
    if len(port) > 2:
      port = port[2:]
    killCmd = '~/kill%s.sh' % port
    startCmd = '~/ps%s.sh' % port
    cmd=[killCmd,startCmd]
    ssh2(serverip,username,passwd,cmd)

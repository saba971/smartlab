#!/usr/bin/python
#-*- coding: utf-8 -*-

import paramiko,pexpect
from optparse import OptionParser
import telnetlib, time, re, os, sys, inspect, subprocess,datetime

def ssh2(ip,username,passwd,cmd,returnResult = False,port=22,timeout=5):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip,port,username,passwd,timeout=timeout)
        if not isinstance(cmd,list) :
            cmd = [cmd]
        print("======begin execute below command using ssh2======")
        results = ''
        for m in cmd:
            print(('start command:%s' %m))
            transport = ssh.get_transport()
            transport.set_keepalive(15)
            channel = transport.open_session()
            channel.get_pty()
            channel.exec_command(m)
            while True:
                if channel.exit_status_ready():
                    break
                try:
                    recv = channel.recv(2048)
                    if not returnResult:
                       #print(recv, end=' ')
                        print(recv)
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
    except :
        print(('%s\tError\n'%(ip)))

def Server_send(cmd, linecmd = 1):
    global telnetTn
    telnetTn.write(cmd)
    db_print(cmd, "send")
    if linecmd == 1:
        telnetTn.write("\r")

def Telnet_send(cmd, linecmd = 1):
    global telnetTn
    telnetTn.write(cmd)
    db_print(cmd, "send")
    if linecmd == 1:
        telnetTn.write("\r")

def send_telCmd(cmd):
    global telnetTn
    retBuf = telnetTn.read_very_eager()
    if "Terminal is idle for" in retBuf and "minutes,logging out !" in retBuf:
        db_print("Wanrning : cli is timeout, need to login cli!")
        loginState = False
        return send_telCmd(cmd)
    try:
        Telnet_send(cmd)
        time.sleep(1)
    except:
        error = AssertionError("Cli send cmd(%s) error!" %(cmd))
        raise error

    retBuf = ""
    iMissCount = 0
    for i in range(1, 1000):
        retTemp = telnetTn.read_very_eager()
        retBuf1 = retBuf + retTemp
        if(retBuf1 == retBuf):
            if(i >= 500) or (iMissCount >= 5):
                db_print ("Error : Cli wait the cli info timeout.")
                return retBuf
            else:
                iMissCount += 1
                time.sleep(0.5)
                continue;
        else:
            MissCount = 0
            retBuf = retBuf1

        tmpBuf = retBuf
        repList = {'\r\n':'', '\n\r':'', '\n':'', '\r':''}
        for repCount in repList:
            tmpBuf = tmpBuf.replace(repCount, repList[repCount])
        n = len(cmd)
        iPos = tmpBuf.find(cmd)
        if iPos >= 0:
           iPos = iPos+n
           buf = tmpBuf[:iPos]
           tmpBuf = tmpBuf[iPos:]
        if re.search(">.*#", retBuf) or re.search(">.*$", retBuf):
           break
        time.sleep(0.2)
    timeoutCount =  0
    return  retBuf

def sendCliCmd(cmd):
  retBuf = send_telCmd(cmd)
  db_print(retBuf, "recv")
  return retBuf

def pingIp(oam_ip):
    ret = os.system('/bin/ping -c 4 %s 2>&1 >/dev/null' % oam_ip)
    if not ret:
        db_print('%s is reachable' % oam_ip)
        return True
    else:
        db_print('%s is not reachable' % oam_ip)
        return False

def check_telnet(oam_ip):
    global telnetTn
    systemup = False
    time.sleep(180)
    #for trytimes in range (0,900):
    #change retry time to be 200
    for trytimes in range (0,200):
        if not pingIp(oam_ip):
            db_print('%s is not reachable, waiting longer...' % oam_ip)
            time.sleep(10)
        else:
            systemup = True
            break
    if systemup == False:
        db_print("30mins passed and OAM is not reachable")
        sys.exit(1)
    trytimes = 0
    systemup = False
    while trytimes < 40:
        try:
            telnetTn.open(oam_ip, 23)
            systemup = True
            break
        except:
            db_print("telnet OAM exception,wait 15s and continue...")
            time.sleep(15)
            trytimes = trytimes + 1
    if systemup == False:
        db_print("10mins passed and can not open telnet connection to OAM")
        sys.exit(1)
    db_print("Start to login via oam ip " + oam_ip)
    returnTmp = ""
    retryTimes = 0
    returnTmp = telnetTn.read_until("login",15)
    if "login" in returnTmp:
        returnTmp = returnTmp + telnetTn.read_until("*",10)
    while "isadmin>" not in returnTmp and retryTimes < 30:
        db_print(returnTmp, "recv")
        if "login" in returnTmp:
            Telnet_send('isadmin')
            returnTmp = telnetTn.read_until("password:",3)
            continue
        elif "enter new password:" in returnTmp:
            try:
                Telnet_send('isamcli!')
                returnTmp = telnetTn.read_until("*",3)
                db_print(returnTmp, "recv")
                continue
            except:
                time.sleep(15)
                returnTmp = ""
                Telnet_send("\r", 0)
                time.sleep(1)
                returnTmp = telnetTn.read_until("*",3)
                continue
        elif "re-enter  password:" in returnTmp:
            Telnet_send('isamcli!')
            returnTmp = telnetTn.read_until("*",3)
            db_print(returnTmp, "recv")
            continue
        elif "password:" in returnTmp:
            try:
                Telnet_send('i$@mad-')
                returnTmp = telnetTn.read_until("*",3)
                if "Login incorrect" in returnTmp:
                    db_print(returnTmp, "recv")
                    db_print("login with cli password")
                    raise Ex45ception()
                if "enter new password:" in returnTmp:
                    Telnet_send('isamcli!')
                    returnTmp = telnetTn.read_until("*",3)
                    db_print(returnTmp, "recv")
                if "re-enter  password:" in returnTmp:
                    Telnet_send('isamcli!')
                    returnTmp = telnetTn.read_until("*",3)
                    db_print(returnTmp, "recv")
                    continue
            except:
                Telnet_send('isadmin')
                returnTmp = telnetTn.read_until("*",1)
                db_print(returnTmp, "recv")
                Telnet_send('isamcli!')
                returnTmp = telnetTn.read_until("*",1)
                db_print(returnTmp, "recv")
                continue
        elif "Connection closed" in returnTmp:
            db_print("Connection closed")
            db_print("sleep 15 seconds and re-open cli port")
            time.sleep(15)
            returnTmp = ""
            Telnet_send("\r", 0)
            time.sleep(1)
            returnTmp = telnetTn.read_until("*",1)
            continue
        elif '''Enter Verb'''  in returnTmp:
            Telnet_send("logoff;", 0)
            time.sleep(1)
            returnTmp = telnetTn.read_until("*",1)
            continue
        else:
            db_print("Warnning : The abnormal scenario in openCli():%s" % returnTmp)
            retryTimes = retryTimes + 1
            if (retryTimes  >= 20):
                db_print("sleep 5 mins and CLI cannot be reached")
                return False
            Telnet_send("\r", 0)
            time.sleep(15)
            returnTmp = telnetTn.read_until("*",1)
            continue
        retryTimes = retryTimes + 1
    db_print("Telent CLI success")
    t3 = time.time()
    telnetTn.close()
    return True

def db_print(printStr, debugType="normal"):
    if debugType=="recv" :
        print  ("<<<" + printStr)
    elif debugType=="send" :
        print  (">>>" + printStr)
    else:
        print  ("---" + printStr)

def digi_login(craftIp,Username='root',passwd='dbps'):
    global exp
    try:
        exp = pexpect.spawn('telnet %s' % craftIp)
        exp.timeout = 60
        exp.logfile_read = sys.stdout
        exp.expect("login:")
        exp.sendline(Username)
        exp.expect('password:')
        exp.sendline(passwd)
        i = exp.expect(["#>",'incorrect','Connection refused',pexpect.EOF])
        if i == 0:
            db_print("DIGI logged in succesfully")
            return True
        else:
            db_print("DIGI Failed to login")
            return False
    except Exception as inst:
        db_print('Failed to access DIGI:%s' %inst)
        return False

def lant_cmd(traceIp,tracePort):
    global telnetTn
    returnTmp = ""
    retryTimes = 0
    port=tracePort[3:5]
    tunnel_cmd="tunnel %s" %port
    telnetTn = telnetlib.Telnet(traceIp)
    Server_send("\r",0)
    returnTmp = telnetTn.read_until(">",5)
    if ">" in returnTmp:
        pass
    else:
        returnTmp = returnTmp + telnetTn.read_until("*",10)
        while ">" not in returnTmp:
            if "login:" in returnTmp:
                Server_send("admin")
                returnTmp = telnetTn.read_until(">",3)
                continue
            elif "password:" in returnTmp:
                Server_send("PASS")
                returnTmp = telnetTn.read_until(">",3)
                continue
            else:
                retryTimes = retryTimes + 1
                if (retryTimes  >= 20):
                    db_print ("sleep 5 mins and CLI cannot be reached")
                    break
                Server_send("\r", 0)
                time.sleep(5)
                returnTmp = telnetTn.read_until("*",1)
                continue
    Server_send("enable")
    returnTmp = telnetTn.read_until("#",15)
    db_print(returnTmp,'recv')
    Server_send(tunnel_cmd)
    returnTmp = telnetTn.read_until("#",15)
    db_print(returnTmp,'recv')
    Server_send("accept")
    returnTmp = telnetTn.read_until("#",15)
    db_print(returnTmp,'recv')
    Server_send("kill connection")
    returnTmp = telnetTn.read_until("#",15)
    db_print(returnTmp,'recv')
    Server_send("exit")
    returnTmp = telnetTn.read_until("#",15)
    db_print(returnTmp,'recv')
    Server_send("exit")
    returnTmp = telnetTn.read_until("#",15)
    db_print(returnTmp,'recv')
    Server_send("exit")
    telnetTn.close()
    return returnTmp

def initializeDUT(server_ip, craftIp, craftPort, oam_ip, initCommands, extraCommands,product,oam_type = '',redund=False,toolOnly=False):
    global telnetTn,exp
    result = True
    if product in ['SDFX','SDOLT','NCDPU']:
        return True
    PING_TRY = 6
    if redund or oam_type in ['FANT-H','FANT-G','FANT-F']:
        PING_TRY = 12
    #check after ip is reachable, whether it is stabily reachable
    for i in range(0,PING_TRY):
        if pingIp(oam_ip):
            break
        else:
            time.sleep(10)

    if not pingIp(oam_ip):
        db_print("oam_ip not reachable,sleep 120s")    
        time.sleep(180)
        if craftIp.strip():
            configoam = True
            if len(craftPort) == 5:
                db_print("LANTRONICS GICI")
                lant_cmd(craftIp,craftPort)
            else:
                if digi_login(craftIp):
                    db_print("DIGI GICI - Legacy port server")
                    cmd = 'kill %s' % craftPort[2:4]
                    db_print(cmd)
                    exp.sendline(cmd)
                    time.sleep(2)
                    exp.expect([">","$"])
                    exp.sendline("exit")
                    exp.close()
                    del exp
                else:
                    db_print("DIGI GICI - Raspberry port server")                
                    remotescript = '/tmp/.jenkins/clearConsolePort.py'
                    cmd_console = 'python -u %s --serverip %s --port %s' %(remotescript,craftIp,craftPort)
                    tmp_res=ssh2(server_ip, 'atxuser','alcatel01',cmd_console,True)
                    print tmp_res
        else :
            configoam = False
            db_print("%s seconds passed and OAM is not reachable and no craft port provided for oam configuration!" %str(10*PING_TRY))
            return False
    else:
        configoam = False
        if redund or oam_type in ['FANT-H','FANT-G','FANT-F']:
            #check after ip is reachable, whether it is stabily reachable
            for i in range(0,10):
                if pingIp(oam_ip):
                    time.sleep(5)
                else:
                    configoam = True
                    break
        if configoam:
            if len(craftPort) == 5:
                db_print("LANTRONICS GICI")
                lant_cmd(craftIp,craftPort)
            else:
                if digi_login(craftIp):
                    db_print("DIGI GICI - Legacy port server")
                    cmd = 'kill %s' % craftPort[2:4]
                    db_print(cmd)
                    exp.sendline(cmd)
                    time.sleep(2)
                    exp.expect([">","$"])
                    exp.sendline("exit")
                    exp.close()
                    del exp
                else:
                    db_print("DIGI GICI - Raspberry port server")
                    remotescript = '/tmp/.jenkins/clearConsolePort.py'
                    cmd_console = 'python -u %s --serverip %s --port %s' %(remotescript,craftIp,craftPort)
                    tmp_res=ssh2(server_ip, 'atxuser','alcatel01',cmd_console,True)
                    print tmp_res

    #now change default passwd
    retryTimes = 0
    systemReady = False
    TELNET_TRY = 40
    if redund or oam_type in ['FANT-H','FANT-G','FANT-F']:
        TELNET_TRY = 80
    while True and retryTimes < TELNET_TRY:
        try:
            if configoam:
                db_print("Start to login via port server " + craftIp + " " + craftPort)
                telnetTn.open(craftIp, craftPort)
                Telnet_send("\r", 0)
            else:
                db_print("Start to login oam ip " + oam_ip)
                telnetTn.open(oam_ip, 23)
            returnTmp = telnetTn.read_until("login",15)
            systemReady = True
            break
        except Exception as inst:
            db_print("telnet failed with exception with %s,wait 15s and continue..." %inst)
            time.sleep(30)
            retryTimes = retryTimes + 1
    if not systemReady:
        db_print("%s seconds passed and can not log on system with login prompt!" %str(TELNET_TRY * 15))
        return False
    #if configoam:
    #     Telnet_send("\r", 0)
    #returnTmp = ""
    retryTimes = 0
    #returnTmp = telnetTn.read_until("login",15)
    if "login" in returnTmp:
        try:
            returnTmp = returnTmp + telnetTn.read_until("*",10)
        except Exception as inst:
            db_print("telnet read with exception:%s" %inst)

    #time0 = time.time()
    if len(craftPort) == 5 and "isadmin>" in returnTmp:
        db_print("for LANTRONICS GICI,clear buffer after logon if already match isadmin>")
        returnTmp=''
        try:
            time.sleep(30)
            db_print("input enter after 30s")
            Telnet_send("\r", 0)
            returnTmp = returnTmp + telnetTn.read_until("*",10)
        except Exception as inst:
            db_print("telnet read with exception:%s" %inst)

    passwd_count = 0
    while "isadmin>" not in returnTmp:
        db_print(returnTmp, "recv")
        try:
            if "<" in returnTmp:
                Telnet_send("\r", 0)
                returnTmp = telnetTn.read_until("*",10)
                continue
            elif "CLI(C) or a TL1 login(T)" in returnTmp:
                Telnet_send("C")
                returnTmp = telnetTn.read_until("*",3)
                continue
            elif "Would you like a CLI login(C)" in returnTmp:
                Telnet_send("C")
                returnTmp = telnetTn.read_until("*",3)
                continue
            elif "login" in returnTmp:
                Telnet_send('isadmin')
                returnTmp = telnetTn.read_until("password:",3)
                continue
            elif "The password can not be changed to this value" in returnTmp:
                db_print("Password changing issue.Exit and telnet it again")
                raise Exception()
            elif "enter new password:" in returnTmp:
                Telnet_send('isamcli!')
                returnTmp = telnetTn.read_until("*",3)
                db_print(returnTmp, "recv")
                continue
            elif "re-enter  password:" in returnTmp:
                Telnet_send('isamcli!')
                returnTmp = telnetTn.read_until("*",3)
                db_print(returnTmp, "recv")
                continue
            elif "password:" in returnTmp:
                if passwd_count == 0:
                    Telnet_send('i$@mad-')
                else:
                    Telnet_send('isamcli!')
                returnTmp = telnetTn.read_until("*",3)
                if "Login incorrect" in returnTmp:
                    db_print(returnTmp, "recv")
                    db_print("login with cli password")
                    passwd_count = passwd_count + 1
                    Telnet_send('isadmin')
                    returnTmp = telnetTn.read_until("*",1)
                    db_print(returnTmp, "recv")
                    if passwd_count > 1:
                        raise Exception()
                if "enter new password:" in returnTmp:
                    Telnet_send('isamcli!')
                    returnTmp = telnetTn.read_until("*",3)
                    db_print(returnTmp, "recv")
                if "re-enter  password:" in returnTmp:
                    Telnet_send('isamcli!')
                    returnTmp = telnetTn.read_until("*",3)
                    db_print(returnTmp, "recv")
                continue
            elif "Connection closed" in returnTmp:
                db_print("Connection closed")
                db_print("sleep 2 mins re-open cli port")
                time.sleep(120)
                returnTmp = ""
                Telnet_send("\r", 0)
                time.sleep(1)
                returnTmp = telnetTn.read_until("*",3)
                continue
            elif '''Enter Verb'''  in returnTmp:
                Telnet_send("logoff;", 0)
                time.sleep(1)
                returnTmp = telnetTn.read_until("*",1)
                continue
            else:
                db_print("Warning : The abnormal scenario in openCli():%s" % returnTmp)
                retryTimes = retryTimes + 1
                if (retryTimes  >= 25):
                    telnetTn.close()
                    return False
                Telnet_send("\r", 0)
                time.sleep(60)
                returnTmp = telnetTn.read_until("*",1)
                continue
        except Exception as inst:
            db_print('telnet or read with exception:%s retry' %inst)

            telnetTn.close()
            retryTimes = retryTimes + 1
            if (retryTimes  >= 25):
                return False
            db_print("sleep 2 mins re-open cli port")
            time.sleep(120)
            if configoam:
                telnetTn.open(craftIp, craftPort)
            else:
                telnetTn.open(oam_ip, 23)

            returnTmp = ""
            Telnet_send("\r", 0)
            time.sleep(1)
            returnTmp = telnetTn.read_until("*",3)
    t3 = time.time()
    db_print(str(t3))
    db_print(returnTmp,'recv')
    db_print("Telent CLI success with password changed")


    if configoam:
        cliOut = ''
        if len(craftPort) == 5 and initCommands:
            initCommands.append('exit all')
            initCommands.append('logout')
        for command in initCommands:
            cliOut = sendCliCmd(command)
            if 'admin save' in command and not 'Completed' in cliOut:
                time.sleep(5)
            elif 'admin software-mngt ihub database save-protected' in command and 'SWDB MGT error' in cliOut:
                time.sleep(10)
            else:
                time.sleep(3)
    db_print('extra config commands')
    if extraCommands:
        for command in extraCommands:
            db_print(command)
            sendCliCmd(command)
    telnetTn.close()
    if configoam and craftPort.strip():
        #os.system('(sleep 1;echo "root";sleep 1;echo "dbps";sleep 1;echo %s;sleep 1;echo "exit";sleep 1) | telnet %s' % (cmd, craftIp))
        if len(craftPort) == 5:
            db_print("LANTRONICS GICI")
            lant_cmd(craftIp,craftPort)
        else:
            if digi_login(craftIp):
                db_print("DIGI GICI - Legacy port server")
                cmd = 'kill %s' % craftPort[2:4]
                db_print(cmd)
                exp.sendline(cmd)
                time.sleep(2)
                exp.expect([">","$"])
                exp.sendline("exit")
                exp.close()
                del exp
            else:
                db_print("DIGI GICI - Raspberry port server")
                remotescript = '/tmp/.jenkins/clearConsolePort.py'
                cmd_console = 'python -u %s --serverip %s --port %s' %(remotescript,craftIp,craftPort)
                tmp_res=ssh2(server_ip, 'atxuser','alcatel01',cmd_console,True)
                print tmp_res
    time.sleep(60)
    if not check_telnet(oam_ip):
        db_print('%s is not reachable after oam config, so check the env!' % oam_ip)
        return False


    return True

if __name__=='__main__':
    parser = OptionParser()
    parser.add_option("--server_ip", dest="serverip",default='', help="server ip")
    parser.add_option("--craft_ip", dest="craftip",default='', help="craftip to be executed")
    parser.add_option("--craft_port", dest="craftport",default='', help="craftport to be executed on")
    parser.add_option("--isam_ip", dest="oamip",default='', help="isam ip")
    parser.add_option("--command", dest="initcommand",default='', help="init Commands")
    parser.add_option("--command_extra", dest="extracommand",default='', help="extra Commands")
    parser.add_option("--product", dest="product",default='', help="product type")
    parser.add_option("--oamtype", dest="oamtype",default='', help="oam type")
    parser.add_option("--redund", dest="redund",default='False', help="check if redundant setup or not")
    parser.add_option("--toolonly", dest="toolonly",default='False', help="Error log flag")
    (options, args) = parser.parse_args(sys.argv[1:])
    telnetTn = telnetlib.Telnet()
    serverip = options.serverip
    craftip = options.craftip
    craftport = options.craftport
    oamip = options.oamip
    #initcommand = options.initcommand
    extracommand = options.extracommand
    product = options.product
    oamtype = options.oamtype
    redund = options.redund
    toolonly = options.toolonly
    initcommand=options.initcommand.split(',')
    #print initcommand
    extracommand=options.extracommand.split(',') 
    res=initializeDUT(serverip, craftip, craftport, oamip, initcommand, extracommand, product, oamtype, redund, toolonly)
    print res
    if res:
        db_print('Initial config is success in ISAM')
    else:
        db_print('Initial config is failure in ISAM') 

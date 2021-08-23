#!/usr/bin/python

#coding:utf-8

import time
import re
import os,subprocess
import stat
import logging
import logging.handlers as handlers
import telnetlib
from optparse import OptionParser


parser = OptionParser()
parser.add_option("--craftIp", dest="craftIp",default='', help="Port server ip")
parser.add_option("--craftPort", dest="craftPort", help="Port server port")
parser.add_option("--LOG_FILE", dest="LOG_FILE",default='console.log', help="Log file name (eg. console.log)")
parser.add_option("--storeInterval", type="int", dest="storeInterval",default=5, help="log stored in a file every interval hours(eg. 5)")
parser.add_option("--dut_type", dest="dut_type", help="Setup type")
parser.add_option("--cmd", dest="cmd",default=None, help="send cmd to the craft (eg: reboot)")
(options, args) = parser.parse_args()

craftIp = options.craftIp
craftPort = options.craftPort
storeInterval = options.storeInterval
LOG_FILE = options.LOG_FILE
dut_type = options.dut_type
telnetTn=''
exe_cmd = options.cmd
#craftIp = "135.252.245.141"
#craftPort = "2005"

def db_print(printStr, debugType="normal"):
  if debugType=="recv" :
    print  ("<<<" + printStr)
  elif debugType=="send" :
    print  (">>>" + printStr)
  else:
    print  ("---" + printStr)

def Telnet_send(cmd, linecmd = 1):
  global tn
  tn.write(cmd)
  db_print(cmd, "send")
  if linecmd == 1:
    tn.write("\r")

def Server_send(cmd, linecmd = 1):
  global telnetTn
  telnetTn.write(cmd)
  db_print(cmd, "send")
  if linecmd == 1:
      telnetTn.write("\r")

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
    Server_send(tunnel_cmd)
    returnTmp = telnetTn.read_until("#",15)
    Server_send("accept")
    returnTmp = telnetTn.read_until("#",15)
    Server_send("kill connection")
    returnTmp = telnetTn.read_until("#",15)
    Server_send("exit")
    returnTmp = telnetTn.read_until("#",15)
    Server_send("exit")
    returnTmp = telnetTn.read_until("#",15)
    Server_send("exit")
    telnetTn.close()
    return returnTmp

def read_until_multiple(tn,timeout,*args):
    try:
        res = tn.expect(list(args),timeout)
        db_print(str(res))   
    except Exception as inst:
        db_print(str(inst))
        return ''
    return res[2]

print craftIp + ':' + craftPort

if ':' in dut_type:
    try:
        tmpList = dut_type.strip().split(':')
        product = tmpList[0]
        board = tmpList[1]
        slot = tmpList[2]
    except Exception as inst:
        slot = '0'
        db_print("wrong dut_type format! with exception:%s" %inst)
else:
    product = dut_type
    board = ''
    slot = '0'
board = board.lower()
trc_cmd_list = []
if product in ['REMOTE','SDFX','SDOLT','NCDPU']:
    Username = "root"
    Password = "2x2=4"
    dutPrompt = '#'
elif 'GPON' in product and board in ['fant-g','fant-h']:
    Username = "root"
    Password = "2x2=4"
    dutPrompt = '>'  
    product = 'REBORN_OTHER'
    print(Username+Password+dutPrompt+product)
elif board in ['cfnt-b','cfnt-c','cfnt-d']:
    Username = "root"
    Password = "2x2=4"
    dutPrompt = '#'  
    product = 'REBORN_miniOLT'
    print(Username+Password+dutPrompt+product)
    trc_cmd_list = ['cd /isam/slot_default/run','calamares -t /isam/slot_1101/run/tty1_ext']
elif board in ['cwlt-b','cwlt-c','cwlt-d','cglt-a','cglt-b','cglt-c']:
    Username = "root"
    Password = "2x2=4"
    dutPrompt = '#'  
    product = 'REBORN_miniOLT'
    print(Username+Password+dutPrompt+product)
    slot_dir = str(1100 + int(slot) + 2)
    trc_cmd_list = ['cd /isam/slot_default/run','calamares -t /isam/slot_%s/run/tty1_ext' %slot_dir]
else:    
    Username = "shell"
    Password = "nt"
    dutPrompt = '>' 
if len(craftPort) == 5:
    db_print("LANTRONICS GICI")
    lant_cmd(craftIp,craftPort)
else:        
    db_print("DIGI GICI")
    #cmd = '\"kill %s\"' % craftPort[2:4]
    cmd = 'python -u ./clearConsolePort.py --serverip %s --port %s' %(craftIp,craftPort)
    result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
    db_print(str(result))
    #os.system('(sleep 1;echo "root";sleep 1;echo "dbps";sleep 1;echo %s;sleep 1;echo "exit";sleep 1) | telnet %s' % (cmd, craftIp))

if product in ['REMOTE','SDFX','SDOLT','NCDPU','REBORN_OTHER','REBORN_miniOLT']:
    tn = telnetlib.Telnet(craftIp, craftPort, 30)
    Telnet_send("\r", 0)
    returnTmp = ""
    retryTimes = 0
    #returnTmp = tn.read_until("#",5)
    #returnTmp = read_until_multiple(tn,5,'[^#]#','[^-]>')
    #print('tonia:%s' %returnTmp)
    #if dutPrompt in returnTmp:
    #  pass
else:
    tn = telnetlib.Telnet(craftIp, craftPort, 30)  
    Telnet_send("\r", 0)
    returnTmp = ""
    retryTimes = 0
    returnTmp = tn.read_until(">",5)
    if ">" in returnTmp:
      pass
    else:
      returnTmp = returnTmp + tn.read_until("*",10)
      while ">" not in returnTmp:
        if "Login:" in returnTmp:
          Telnet_send(Username)
          returnTmp = tn.read_until(">",3)              
          continue
        else:
          retryTimes = retryTimes + 1
          if (retryTimes  >= 20):
            db_print ("sleep 5 mins and CLI cannot be reached")
            break
          Telnet_send("\r", 0)
          time.sleep(15)
          returnTmp = tn.read_until("*",1)                    
          continue
    #Telnet_send("bld info")
    
class SizedTimedRotatingFileHandler(handlers.TimedRotatingFileHandler):
      def __init__(self, filename, mode='a', maxBytes=0, backupCount=0, encoding=None,
                 delay=0, when='h', interval=1, utc=False):
        if maxBytes > 0:
            mode = 'a'
        handlers.TimedRotatingFileHandler.__init__(
            self, filename, when, interval, backupCount, encoding, delay, utc)
        self.maxBytes = maxBytes

      def shouldRollover(self, record):
        if self.stream is None:                 # delay was set...
            #print "delay was set"
            self.stream = self._open()
        if self.maxBytes > 0:                   # are we rolling over?
            #print "are we rolling over"
            msg = "%s\n" % self.format(record)
            self.stream.seek(0, 2)  #due to non-posix-compliant Windows feature
            if self.stream.tell() + len(msg) >= self.maxBytes:
               #print "oversize!!!!" 
               return 1
        t = int(time.time())
        if t >= self.rolloverAt:
            #print "rollover!!!!"
            return 1
        return 0

def my_SizedTimedRotatingFileHandler():
    log_filename=LOG_FILE
    logger=logging.getLogger('MyLogger')
    logger.setLevel(logging.DEBUG)
    handler=SizedTimedRotatingFileHandler(
        log_filename, when='h',interval=storeInterval,
        # encoding='bz2',  # uncomment for bz2 compression
        )
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    if product in ['REMOTE','SDFX','SDOLT','NCDPU','REBORN_OTHER','REBORN_miniOLT']:
        while True:
            con_log = read_until_multiple(tn,10,'isam-reborn login:','login:','Password:','/isam/scripts/swm_after_activate exit','[^#]#','[^-]>')
            time.sleep(0.3)
            if con_log and (con_log[0] == 0 or con_log[0] == 1 or con_log[0] == 2 or con_log[0] == 3 or con_log[0] == 4):
                print con_log
            logger.debug(con_log)
            if "isam-reborn login:" in con_log or "login:" in con_log:
                Telnet_send(Username)
                #returnTmp = tn.read_until(dutPrompt,3)
                logger.debug(Username)
                continue
            elif "Password:" in con_log:
                Telnet_send(Password)
                #returnTmp = tn.read_until(dutPrompt,3)
                logger.debug(Password)
                continue
            elif '/isam/scripts/swm_after_activate exit' in con_log:
                Telnet_send("\r", 0)
                if trc_cmd_list:
                    Telnet_send(trc_cmd_list[0] + "\r", 5)
                    con_log = read_until_multiple(tn,5,'[^#]#')
                    logger.debug(con_log)
                    time.sleep(0.2)
                    Telnet_send(trc_cmd_list[1] + "\r", 5)
                    time.sleep(5)
                    con_log = read_until_multiple(tn,10,'[^-]>')
                    logger.debug(con_log)
    else:
        while True:
            con_log=tn.read_very_eager()
            time.sleep(2)
            print con_log
            logger.debug(con_log)

def my_SingleFileHandler():
    log_filename=LOG_FILE
    logger=logging.getLogger('MyLogger')
    logger.setLevel(logging.DEBUG)
    handler=FileHandler(log_filename)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    while True:
        con_log=tn.read_very_eager()
        time.sleep(2)
        print con_log
        logger.debug(con_log)        


def reset_dut_via_trace():
    prompt = ' '+dutPrompt
    for k in range(0,10):
        returnTmp = tn.read_until(prompt, 5)
        if "ogin:" in returnTmp:
            Telnet_send(Username)
        elif "assword:" in returnTmp:
            Telnet_send(Password)
        elif dutPrompt in returnTmp:
            Telnet_send(exe_cmd)
            break

if exe_cmd:
    reset_dut_via_trace()
else:
    my_SizedTimedRotatingFileHandler()

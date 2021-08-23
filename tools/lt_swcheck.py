#!/usr/bin/python
import os,sys,time,inspect,re
import pexpect,logging
import com_tnd
from optparse import OptionParser

TND_SESSION={}
def connect_tnd (ip='0.0.0.0',port='23',username='shell',password='nt',\
session_name="first_tnd_session") :
    """
        build up the trace & debug session for sending TnD command
        this Keyword is based class com_tnd
    """
    global TND_SESSION
    keyword_name = 'connect_tnd'
    print "Module : " ,__name__," Keyword : ",keyword_name," -> input : ",ip," ",port," ",username," ",password," ",session_name
    ip = ip.encode("ascii")
    port = port.encode("ascii")
    username = username.encode("ascii")
    password = password.encode("ascii")
    try:
        TND_SESSION[session_name] = com_tnd.com_tnd\
        (ip,port=port,username=username,password=password)
        return_out=TND_SESSION[session_name].open_tnd ()
    except Exception as inst:
        raise AssertionError("%s -> fail to connect tnd: %s" % (__name__,inst))
    if return_out != "fail":
        print "Module : " ,__name__," Keyword : ",keyword_name, " -> tnd session created: ",session_name, " of ",str(TND_SESSION)
    else:
        print "tnd session unable to create"
    return return_out

def disconnect_tnd (session_name="first_tnd_session") :
      global TND_SESSION
      keyword_name = 'disconnect_tnd'
      try:
          TND_SESSION[session_name].close_tnd()
      except:
          raise AssertionError("Module:%s, Keyword:%s -> fail to close tnd session" \
          % (__name__,inspect.stack()[0][3]))
      else :
          print "Module : " ,__name__," Keyword : ",keyword_name, " -> tnd session ",session_name, " closed "
      TND_SESSION.pop(session_name)
      return "pass"

def send_tnd_command(command,timeout=0,session_name="first_tnd_session"):
      """
        send single tnd command
      """
      global TND_SESSION
      keyword_name = 'send_tnd_command'
      print "Module : " ,__name__," Keyword : ",keyword_name, " ->  input: ",command,", ", session_name
      try:
          cliobj = TND_SESSION[session_name]
          res = cliobj.send_command(command,timeout=int(timeout))
      except Exception as inst:
          raise AssertionError("%s-> fail to send command: %s: %s" \
          % (__name__,command,inst))
      else :
          print "Module : " ,__name__," Keyword : ",keyword_name, " -> TND REPLY: ",res
      return "pass"

def get_tnd_output (command,timeout='5',session_name="first_tnd_session"):

      """
          return the response of trace debug command
      """
      global TND_SESSION
      keyword_name = 'get_tnd_output'
      timeout = int(timeout)
      print "Module : " ,__name__," Keyword : ",keyword_name, " ->  input: ",command
      try:
          cliobj = TND_SESSION[session_name]
          res = cliobj.send_command(command,timeout=timeout)
          res = cliobj.send_command(command,timeout=timeout)
          print "Module : " ,__name__," Keyword : ",keyword_name, " -> TND REPLY: ",res
      except Exception as inst:
          raise AssertionError("%s -> fail to send command: %s: %s" \
          % (__name__,command,inst))
      else :
          return res


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("--isam_ip", dest="isam_ip",default='', help="ISAM ip")
    parser.add_option("--lt_list", dest="lt_list",default='', help="LT List")
    parser.add_option("--build", dest="build",default='', help="Build id")
    
    (options, args) = parser.parse_args(sys.argv[1:])
    LT_list=list(options.lt_list.split(','))
    print LT_list
    nbuild=options.build.split('.')
    test_bld0=nbuild[0]
    test_bld1=nbuild[1]
    test_bld=test_bld0[0]+test_bld0[1]+'.'+test_bld1
    print test_bld
    Board_list=[]
    lt_ret_flag=False
    cmd="eqpt displayAsam -s"
    cmdb="cmd buildVersion"
    ###Connect TND
    tnd_obj=connect_tnd(options.isam_ip)
    #send_tnd_command(cmd)
    tnd_out=get_tnd_output(cmd)
    for lt in LT_list:
        try:
            var=re.search('\s+(.*)\s+:\s+%s'%lt,tnd_out)
            board=var.group(1).strip()
            Board_list.append(board)
        except Exception as inst:
            Board_list=[]
    if not Board_list:
        print "No board list available"
        lt_ret_flag=False
    try:
        print Board_list
        for board_no in Board_list:
            cmda="login board %s" %board_no
            tnd_outa=get_tnd_output(cmda)
            if not re.search('Board not reachable',tnd_outa):
                tnd_out1=get_tnd_output(cmdb)
                if re.search('Version\s+:\s+(.*)',tnd_out1):
                    var1=re.search('Version\s+:\s+(.*)',tnd_out1)
                    bld_ver=var1.group(1).strip()
                    print bld_ver
                if re.search(test_bld,bld_ver):
                    print "SW version matches"
                    lt_ret_flag=True
                else:
                    print "SW version mismatch"
                    lt_ret_flag=False
                    break
                send_tnd_command('exit')
            else:
                print "Board not reachable"
                #lt_ret_flag=False
    except Exception as inst:
        print "Error in accessing board"
        lt_ret_flag=False
    disconnect_tnd()
    if lt_ret_flag:
        print "LT SW check is successfull"
    else:
        print "LT SW check is not successfull"   

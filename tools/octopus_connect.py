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
    parser.add_option("--cmd", dest="tnd_cmd",default='', help="TND command")

    (options, args) = parser.parse_args(sys.argv[1:])
    ###Create a TND Session
    for i in xrange(0,60):
        try:
            tnd_obj=connect_tnd(options.isam_ip)
        except Exception as inst:
            keyword_name = "create TND session failed"
            raise AssertionError("%s:%s-> fail to create TNDSESSION, exception: %s" \
            % (__name__,keyword_name, str(inst)))

        ###Get TND output
        try:
            tnd_out=get_tnd_output(options.tnd_cmd)
        except Exception as inst:
            keyword_name = "get TND output failed"
            raise AssertionError("%s:%s-> fail to get TND command output, exception: %s" \
            % (__name__,keyword_name, str(inst)))
        ####Disconnect TND Session
        try:
            disconnect_tnd()
        except Exception as inst:
            keyword_name = "Disconnect TND Session failed"
            raise AssertionError("%s:%s-> fail to close tnd session, exception: %s" \
            % (__name__,keyword_name, str(inst)))
        else:
            logging.debug("disconnect TND connection success " )
        if not re.search('phaseDiskSync\s+=\sCompleted',tnd_out):
            print('diskSync not finished,wait for 60s...')
            time.sleep(60)
        else:
            print('diskSync finished successfully')
            break
   

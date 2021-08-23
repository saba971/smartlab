#!/usr/bin/python
#import re
import time
import paramiko
import voice_test
import sys,logging,os,socket,re
from optparse import OptionParser

VOICE_SESSION = ""

port='22'
directory="/home/alcatel/MGC_367_ABOVE/"

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("--linux_ip", dest="linux_ip",default='', help="PCTA ip")
    parser.add_option("--port", dest="port",default='22', help="PCTA port")
    parser.add_option("--linuxuser", dest="linuxuser",default='atxuser', help="username")
    parser.add_option("--linuxpass", dest="linuxpass",default='alcatel01', help="password")

    (options, args) = parser.parse_args(sys.argv[1:])
    cmd1="/home/alcatel/MGC_367_ABOVE/callserver_sim -b -c -d -i -t /home/alcatel/MGC_367_ABOVE/mgc.cfg"
    cmd2="/home/alcatel/MGC_367_ABOVE/callserver_sim -b -c -d -i -t /home/alcatel/MGC_367_ABOVE/mgc.cfg"
    cmd3="sudo ./mpp_server %s > /tmp/MPPserverlog_traces &" %options.linux_ip
    command_list=[]
    command_list.append(cmd1)
    command_list.append(cmd2)
    command_list.append(cmd3)
    
    for command in command_list:
    ###Create a PCTA Session
        try:
            VOICE_SESSION = voice_test.com_pcta(options.linux_ip,port,options.linuxuser,options.linuxpass,directory,command,'%','available')
        except Exception as inst:
            keyword_name = "Create voice process failed"
            raise AssertionError("%s:%s-> fail to create voice process, exception: %s" \
            % (__name__,keyword_name, str(inst)))

    ###Start Voice process
        try:
            VOICE_SESSION.open_pcta()
        except Exception as inst:
           keyword_name = "start voice process failed"
           raise AssertionError("%s:%s-> fail to start voice process, exception: %s" \
           % (__name__,keyword_name, str(inst)))

    ####Disconnect PCTA Session
    try:
       VOICE_SESSION.close_pcta()
       del VOICE_SESSION
    except Exception as inst:
       keyword_name = "close voice process failed"
       raise AssertionError("%s:%s-> fail to close voice session, exception: %s" \
       % (__name__,keyword_name, str(inst)))      
    else:
        logging.debug("disconnect voice process success " )

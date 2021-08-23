#!/usr/bin/python
#import re
import time
import paramiko
import sys,logging,os,socket,re

VOICE_SESSION = ""

class com_pcta(object) :
    """ 
    com_pcta is the class will have ip, port, username, password and exec_file arguments.
        
    """
    def __init__(self,ip,port,username,password,exec_file,exec_cmd,prompt,available) :
    
        self.exec_file = exec_file.encode("ascii")
        self.exec_cmd  = exec_cmd.encode("ascii")
        if exec_file :
            self.exec_file = str(exec_file.encode("ascii"))
        else :
            self.exec_file = '/home/alcatel/MGC_367_ABOVE'

        self.ip = ip.encode("ascii")
        if port :
            self.port = int(port.encode("ascii"))
        else :
            self.port = 22
        self.username = username.encode("ascii")
        if not password or password.lower() == 'x' :
            self.password = None
        else :
            self.password = password.encode("ascii")
        self.exec_file = exec_file.encode("ascii")
        if prompt :
            self.prompt = prompt.encode("ascii")
        else :
            self.prompt = ">".encode("ascii")  
        if str(available).lower() == 'false' :
            self.available = 'False'
        else :
            self.available = 'True'          
        #transport and channel are the object variables which will have the transport & channel objects.
        self.transport = ""
        self.channel = ""
        if not self.available :
            msg = "PCTA is not available. all relative check will be skiped"
	    print msg		

    def open_pcta(self):
        """ 
        open_pcta will establish the ssh connection using paramiko and create a transport & channel objects for the
          ssh session & invoke the shell. Set the pty terminal session to run the sudo commands. Set default timeout
          as '3'. The channel will wait upto 3 seconds to get the data from the socket, else return.
            
        """
        if not self.available or self.available.lower() == "false":
            return  "pass"
        keyword_name = "open_pcta"
        logging.debug("%s:%s " % (__name__,keyword_name))
        try : 
            retry = 1
            while retry < 11:
                try:                                
                    self.transport = paramiko.Transport((self.ip, self.port))
                except Exception as inst:
                    if retry == 10:
                        raise AssertionError("%s:%s-> transport error for ip='%s' port='%s', exception:%s" \
                        % (__name__,keyword_name,self.ip,str(self.port),inst) )
                    logging.debug ( str(retry) + " : " + "transport failure,retry..." )
                    retry += 1
                    time.sleep(2)
                    continue

                try :  
                    if self.password :                    
                        self.transport.connect(username=self.username, password=self.password)
                    else :
                        myUSer = os.popen('whoami').read().replace('\n','')
                        private_key_file = os.path.expanduser('~'+myUSer+'/.ssh/id_rsa')
                        my_key = paramiko.RSAKey.from_private_key_file (private_key_file)
                        self.transport.connect(username=self.username,pkey=my_key)
                    
                    self.channel = self.transport.open_session()
                    self.channel.settimeout(3)
                    self.channel.get_pty('vt100')
                    self.channel.invoke_shell()
                    logging.debug("SSH session established successfully...")
                except Exception as inst:
                    if retry == 10:
                        print AssertionError("fail to do password validation, exception:\n%s" % (inst))
                    try :
                        self.channel.close()
                        self.transport.close()
                    except Exception as inst :
                        logging.debug ( "close channel or transport failure for exception: %s ,retry..." % str(inst) )

                    logging.debug ( str(retry) + " : " + "fail to open session,retry..." )
                    retry += 1
                    time.sleep(3)
                    continue
                else:
                    break

            pcta_path = os.path.dirname(self.exec_file)
            dir_prompt = "\$|\#|\%|\>"
            switch_dir =  "cd "+ pcta_path 

            # Switch directory to given 'exec_dir'
            return_info = self._exec_command(switch_dir,dir_prompt,"switch directory",10)     
            return_info = self._exec_command('pwd',pcta_path,"check directory",10)
            if not re.search(pcta_path,return_info):
                return_info = self._exec_command(switch_dir,dir_prompt,"switch directory again",20)
                return_info = self._exec_command('pwd',pcta_path,"check directory",10)
            if not re.search(pcta_path,return_info):    
                raise AssertionError("%s:%s -> fail to switch directory" \
                % (__name__,keyword_name))
                    
            # launch the pcta with the sudo permission   
            run_pcta = self.exec_cmd
            print run_pcta 
            return_info = self._exec_command(run_pcta,self.prompt,"execute voice process",10)
            if not re.search(self.prompt,return_info) :		    
                self.channel.close()
                self.transport.close()
                raise AssertionError("%s:%s -> fail to execute voice process : %s" \
                %(__name__,keyword_name,return_info))
  
            self.channel.settimeout(60)
            self.session_alive = True     
            time.sleep(5)

        except Exception as inst:
            s = sys.exc_info()
            raise AssertionError("line:%s, inst:%s" % (s[2].tb_lineno,inst) )
        return "pass"

    def _exec_command(self,command,expectPrompt,message="execute command",timeout=5):
        keyword_name = "_exec_command"
        returnTmp = ""
        try:
            returnTmp = self._ssh_sendcmd(command+"\n")
            logging.debug("write:'%s', expect:'%s'" % (command,expectPrompt))
            logging.debug("get return:\n%s\n" % returnTmp)
        except Exception as inst:
            msg = "fail to " + message
            raise AssertionError("%s:%s-> %s,exception:%s" % (__name__,keyword_name,msg,inst))
        return returnTmp

    def _ssh_sendcmd(self,cmd,prompt=None):
        result = ""
        data = ""	
        if not prompt :
            prompt = ".*>"	
        self.channel.send(cmd)
        time.sleep(0.1)
        # read the socket buffer until the channel exit_status_ready state
        while not self.channel.exit_status_ready():
            if self.channel.recv_ready() :
                # read the socket buffer
                data = self.channel.recv(4096)
                result = data
                while data :
                    try :
                        if re.search(prompt,result) :
                            return result
                        else :
                            data = self.channel.recv(1024)
                            result += data
                            continue
                    except socket.timeout:
                        return result
                    except Exception as inst :
                        logging.debug("Error : %s" % str(inst))
                        return result
            if self.channel.recv_stderr_ready():
                error_buf = self.channel.recv_stderr(1024)
                errinfo = ""
                while error_buf :
                    errinfo += error_buf
                    try :
                        error_buf = self.channel.recv_stderr(1024)
                    except Exception as inst :
                        logging.debug("Error : %s" % str(inst))
                        return errinfo  
			           
        return result

    def close_pcta(self):
        """ 
        close_pcta will close the ssh connection which is established using paramiko module
          
        """
        if not self.available :
            return "pass"
                    
        keyword_name = "close_voice"
        resultFlag = "OK"
        self.channel.settimeout(3)
        try:
            command = "exit\n"
            expectPrompt = "$|#|%"
            msg = "exit command execution"
            self._exec_command(command,expectPrompt,msg,5)
            self.channel.close()
            self.transport.close()
        except Exception as inst:
            msg = "VOICE can't been closed"
            raise AssertionError("%s:%s -> %s, exception: %s" \
            % (__name__,keyword_name,msg, inst))
             
        return "pass" 


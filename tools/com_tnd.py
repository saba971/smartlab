import os,sys,time,inspect,re
import pexpect

class com_tnd:
    def __init__(self,ip,port='23',username='root',password='2x2=4',prompt='USR.*>'):
        self.ip = ip.encode("ascii")
        self.port = port.encode("ascii")
        self.username = username.encode("ascii")
        self.password = password.encode("ascii")
        self.prompt = prompt.encode("ascii")
        self.tnd = ""
        self.tnd_alive = False
        
    def open_tnd(self):
        """
        To Open TND Login session 
        Author : 			Comments :
        Beno K Immanuel 	-		Developed 
        Chunyan 		- 		Modified """ 
        
        max_retry = 3
        i = 1
        while (i < max_retry) :
            if not self.tnd_alive :
		print "try to login traceDebug for the ",i," th time"
                try:
                    login_tnd = self._login_tnd()
                except Exception as inst :
                    raise AssertionError("Module:%s,Keyword:%s -> fail to open tnd:%s" \
                    % (__name__,inspect.stack()[0][3],inst))
                else :
                    if login_tnd != "pass" :
                        i += 1
                        time.sleep(10)               
            else:
                print "Retried and Connected sucessfully"		
                return "pass"    
        return "fail"

    def _login_tnd(self):
        """
        To Intialize the Trace& Debug session via OCTOPUS
        
        for Enabling or Disabling the Traces
        
        Author : 		 Comments :
        
        Beno K Immanuel   -  	 Developed 
        Chunyan  	 -  	 Modified """
        
	keyword_name = '_login_tnd'
        octopus_cmd = '/tmp/.jenkins/octopus STDIO %s:udp:%s' %(self.ip,self.port)
        try:
            self.interface = pexpect.spawn(octopus_cmd)
        except Exception :
            raise AssertionError("%s:%s -> fail to initial octopus by command:%s" \
            % (__name__,inspect.stack()[0][3],octopus_cmd))
        else :
	    print __name__," : ", keyword_name," -> ",octopus_cmd
            
        self.interface.sendline("\r")
        login = self.interface.expect(['Login:.*','No such file or directory.*',\
        'Connection Refused!.*','Unable to connect.*','closed by remote host.*',\
        pexpect.EOF,pexpect.TIMEOUT])
	print " LOGIN VAL ",login
        if login == 1:
            self.tnd_alive =False
            self.interface.close()      
            raise AssertionError("%s:%s -> Octopus is not available,\
            -- pls check in '/repo/<user>/robot/TOOLS/octopus'" \
            % (__name__,inspect.stack()[0][3]))
        elif login > 1 :
	    print __name__," : ", keyword_name," -> get return: ",self.interface.after
            self.tnd_alive = False
            self.interface.close()
            return "fail"
        self.interface.sendline(self.username)
	print __name__," : ", keyword_name," -> send:  ",self.username
        pwd = self.interface.expect(['Password:.*','ALL TASKS BUSY.',\
        'Invalid login.*',pexpect.TIMEOUT])
	print " PWD  VAL ",pwd
        if pwd == 1:       
            self.tnd_alive = False
            self.interface.close()
            time.sleep(10)
            return "fail"
        if pwd == 2:
            self.tnd_alive = False
            print "Invalid Login "
            self.interface.close() 
            return "fail"   
                   
        self.interface.sendline(self.password)

        prompt = self.interface.expect(['T&D console USR.*login.*',pexpect.TIMEOUT])
        #logger.info("PROMPT VAL '%s'" % prompt)
        #logger.info("%s-> get return: %s" % (__name__,self.interface.after))        

        if prompt == 0 :
            print "Successfully logged into the TND session"
            self.tnd_alive = True
            return "pass"
        else :
            print "fail to login the TND session"
            self.tnd_alive = False
            self.interface.close() 
            return "fail" 
     
    def send_command(self,cmd,timeout=0):
        """
        This keyword is used to Send the T&D Command through Octopus 
        
        Author : 			Comments :
        Beno K Immanuel 	-		Developed 
        Chunyan 		- 		Modified	    """
	
	keyword_name = 'send_command'
        if timeout != 0 :
            timeout = int(timeout)
        else:
            timeout = 60
        i = 0
        while (i < 3) :
            if not self.tnd_alive :
                self.open_tnd()
            if self.tnd_alive:
                cmdout =""
                #logger.info("---0  before %s: " % self.interface.before)
                #logger.info("---0   after  %s: " % self.interface.after)
                #self.interface.sendline("\r")
                #logger.info("---1  before %s: " % self.interface.before)
                #logger.info("---1   after  %s: " % self.interface.after)
                #cmdout  = cmdout+ self.interface.before+self.interface.after
                self.interface.sendline(cmd)   
                #logger.info("---1 -1  before %s: " % self.interface.before)
                #logger.info("---1  - 1 after  %s: " % self.interface.after)              
                #logger.info("%s:%s -> send: %s" \
                #% (__name__,inspect.stack()[0][3],cmd))
		print __name__," : ", keyword_name," -> send:  ",cmd             
                match_pattern = self.prompt
                try :
                    rep = self.interface.expect(['Inactivity timeout','err_code.*',\
                    match_pattern,'T&D console.*login',pexpect.TIMEOUT],timeout=timeout) 
                except Exception as inst:
                    #logger.warn("can not get response for send command, exception: "+str(inst))
		    print "can not get response for send command, exception: ",str(inst)
                print "TIMEOUT : ", str(pexpect.TIMEOUT)
                print "PROMPT :", str(rep)
                #logger.info("---2  before %s: " % self.interface.before)
                #logger.info("---2   after  %s: " % self.interface.after)
                #cmdout = cmdout +self.interface.before  +self.interface.after 
                
                #logger.info("CMD OUT : %s" %str(cmdout))                 
                if rep == 0 or rep == 4 :
                    self.tnd_alive = False
                    continue
                elif rep == 1 or rep == 2:
                    return self.interface.before  +self.interface.after 
                else:
                    if rep == 3:
                        cmdout = self.interface.before  +self.interface.after 
                        rep = self.interface.expect(['Inactivity timeout','.*err_code.*',\
                        match_pattern,'.*T&D console.*login',pexpect.TIMEOUT],timeout=timeout)   
                        cmdout = cmdout+self.interface.before  +self.interface.after                   
                        return cmdout
            else :
                self._login_tnd()
                i = i + 1
        
        return "fail"

    def close_tnd(self):
        """
        This keyword is used to Logout the created T&D Session
        
        Author : 			Comments :
        
        Beno K Immanuel 	-		Developed 
        Chunyan 			- 		Modified	
        """
        try :
            if self.tnd_alive :                
                self.interface.sendline('exit')
            self.interface.expect(['Logout .* console.*'])
            self.interface.sendline('\003')
            self.interface.expect(['octopus.*'])
            self.interface.sendline('q')
            self.interface.expect(['quit'])
            self.interface.expect([pexpect.EOF])
            self.interface.close()
            print "TND SESSION LOGGED OUT"	
        except Exception as inst :
            raise AssertionError("Module:%s,Keyword:%s -> fail to close tnd: %s" \
             % (__name__,inspect.stack()[0][3],inst)) 
        
        return "pass"  


   

#!/usr/bin/python
#coding:utf-8

import time, re, os, sys, inspect, subprocess,paramiko
from optparse import OptionParser
import datetime
import traceback
import pexpect
#from lib.resultParser.writer.trancehandle import TraceFileHandle
def sshPexpect(linuxMIp,linuxMPort,linuxPwd,logSPwd,cmdList,timeout=360):
        print(cmdList)
        interface = pexpect.spawn(cmdList['login'],timeout=int(timeout))
        print('send line:%s'%cmdList['login'])
        time.sleep(3)
        expect_value =interface.expect(\
        ['Are you sure you want to continue connecting \(yes\/no\)\?',\
        'assword:',\
        'Host key verification failed',\
        r"\$|\#|\%",\
        'Connection Refused!',\
        'Unable to connect',\
        'closed by remote host',\
        pexpect.EOF,pexpect.TIMEOUT],timeout)
        print('expect_value is:%s'%expect_value)
        enterTag=0
        if expect_value == 0:
            print("send: yes")
            interface.sendline("yes")
            expect_prompt = interface.expect(['.*assword:', pexpect.EOF,r"\$|\#|\%",pexpect.TIMEOUT],timeout)
            print('expect_prompt is:%s'%expect_prompt)
            if expect_prompt == 0:
                print("send: %s" % linuxPwd)
                interface.sendline(linuxPwd)
            elif expect_prompt == 1:
                return
            elif expect_prompt == 2:
                enterTag=True
            else:
                interface.close()
                raise AssertionError("unexpected error: %s" % str(interface.after))
        elif expect_value == 1 : 
            print("send: %s" % (linuxPwd))
            interface.sendline(linuxPwd)
        elif expect_value == 2 :
            if str(remotePort) == "22" :
                cmd = "ssh-keygen -R " + linuxMIp
            else :
                cmd = "ssh-keygen -R [" + linuxMIp + "]:" + str(linuxMPort)
            print( "exec '" + cmd + "' to clean inconsistent public key" )
            res = pexpect.run ( cmd ) 
            print(str(res))
            interface.close()
            raise AssertionError ("inconsistent public key cleaned, please retry")
        elif expect_value == 3:
            enterTag=True
        elif expect_value > 3 :
            interface.close()
            raise AssertionError("unexpected error: %s" %str(interface.after))
            
        try:      
            if not enterTag:
                expect_value = interface.expect([r"\$|\#|\%",pexpect.EOF, pexpect.TIMEOUT],timeout)
                if expect_value!=0:
                    interface.close()
                    raise AssertionError("unexpected error: %s" %str(interface.after))
                
            print('send line:%s'%cmdList['scp'])
            interface.sendline(cmdList['scp'])
           #expect_value = interface.expect([r"\$|\#|\%",pexpect.EOF, pexpect.TIMEOUT],timeout)
           #print('expect_value $ or # :%s'%expect_value)
           #print('login output is:%s'%interface.before.strip())
           #print('login output after is:%s'%interface.after.strip())
            expect_value = interface.expect(['assword:',pexpect.EOF, pexpect.TIMEOUT],timeout)
            print('expect_value assword:%s'%expect_value)
            if expect_value==0:
                print('send line:%s'%logSPwd)
                interface.sendline(logSPwd)
                expect_value = interface.expect([r"@.*(\$|\#|\%)",pexpect.EOF, pexpect.TIMEOUT],timeout)
                print('expect_value $ or # :%s'%expect_value)
                print('scp result is:%s'%interface.before.strip())
                interface.sendline('exit')
                expect_value = interface.expect([pexpect.EOF, pexpect.TIMEOUT],timeout)
                print('expect_value eof :%s'%expect_value)

            interface.close()
        except Exception as e: 
            e = sys.exc_info()[0]
            traceback.print_exc()
            print(traceback.format_exc())    
            raise AssertionError ("fail to get prompt after giving password")
        

def uploadToLogServer(hostname,port,username,password,local_file, remote_path):
    try:
        print('hostname=%s,port=%s,username=%s,password=%s,local_file=%s,remote_path=%s'%(hostname,port,username,password,local_file, remote_path))
        t = paramiko.Transport((hostname, port))
        t.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(t)
        print('start upload %s to %s at %s ' %(local_file,remote_path,datetime.datetime.now()))
        try:
            fileName=os.path.basename(local_file)
            sftp.put(local_file, os.path.join(remote_path, fileName))
        except Exception as e:
            e = sys.exc_info()[0]
            traceback.print_exc()
            print(traceback.format_exc())
            sftp.mkdir(remote_path)
            sftp.put(local_file, os.path.join(remote_path, fname))
        print('upload successfully %s ' % datetime.datetime.now())
        t.close()
    except Exception as e:
        e = sys.exc_info()[0]
        traceback.print_exc()
        print(traceback.format_exc())

def logServerCheckFile(host,username,password,pathList,port=22,create=False):
    print('host=%s,username=%s,password=%s,port=%s,create=%s'%(host,username,password,port,create))
    t = paramiko.Transport((host,port))
    t.connect(username=username, password=password)
    sftp = paramiko.SFTPClient.from_transport(t)
    try:
        for path in pathList:
            print('check %s'%path)
            try:
                sftp.stat(path)
                print('logServerCheckFile Path:%s exists' % path)
            except IOError as e:
                print('logServerCheckFile Path:%s not exists' % path)
                if create:
                    print('logServerCheckFile create path:%s' % path)
                    sftp.mkdir(path)
                else:
                    return 301
        return 300
    except Exception as e:
        print('logServerCheckFile exception is: %s'%e)
        return 302
    finally:
        sftp.close()
        
def logServerDeleteFile(host,username,password,pathList,port=22):
    t = paramiko.Transport((host,port))
    t.connect(username=username, password=password)
    sftp = paramiko.SFTPClient.from_transport(t)
    try:
        for path in pathList:
            try:
                sftp.stat(path)
                print('logServerDeleteFile delete Path:%s exists' % path)
                sftp.remove(path)
                print('logServerDeleteFile delete Path:%s successfully' % path)
            except IOError as e:
                print('logServerDeleteFile %s does not exist or delete fail' % path)
        return 300
    except Exception as e:
        print('logServerCheckFile exception is: %s'%e)
        return 301
    finally:
        sftp.close()
        
def translateFilesFromLinuxMToLogS(linuxMIp,linuxMPort,linuxUsr,linuxPwd,localFile,logSIp,logSPort,logSUser,logSPwd,logSUploadPath):
    try:
        cmd='ls -lR %s|grep -v ^d|awk "{print $9}" |tr -s "\n" | sed "s:^:`pwd`/:"'%localFile
        remoteExecuteCmd(linuxMIp, linuxMPort, linuxUsr, linuxPwd,cmd)
        print('remote linux check file list cmd:%s'%cmd)
        ssh_command1='ssh '+'-o GSSAPIAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '+linuxUsr+'@'+linuxMIp
        ssh_command2= 'scp -r '+'-o GSSAPIAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '+localFile+' '+logSUser+'@'+logSIp+':'+logSUploadPath
        cmdList={'login':ssh_command1,'scp':ssh_command2}
        sshPexpect(linuxMIp,linuxMPort,linuxPwd,logSPwd,cmdList)
        return 300
    except Exception as e:
        e = sys.exc_info()[0]
        traceback.print_exc()
        print(traceback.format_exc())
        print('translate Files FromLinuxM To LogS exception: %s'%e)
        return 301
    

def readFileFromLogServer(host_ip, port, username, password,file_path):
    print('readFileFromLogServer host_ip is:%s,file is:%s'%(host_ip,file_path))
    contentLines=[]
    client = paramiko.SSHClient()
    try:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host_ip, port, username, password, timeout=5)
        sftp_client = client.open_sftp()
        remote_file = sftp_client.open(file_path, 'r+')
        contentLines=remote_file.readlines()
        remote_file.close()
        print('readFileFromLogServer contentLines is:')
        print(contentLines)
        return 300
    except:
        print('failed to open the remote file!')
        return 301
    finally:
        client.close()
        return contentLines
    
def writeFileToLogServer(host_ip, port, username, password,file_path,contentList):
    print('writeFileToLogServer host_id:%s'%host_ip)
    print('writeFileToLogServer file_path is:%s'%file_path)
    print('writeFileToLogServer contenlist is:%s'%contentList)
    client = paramiko.SSHClient()
    try:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host_ip, port, username, password, timeout=5)
        sftp_client = client.open_sftp()
        remote_file = sftp_client.open(file_path, 'w')
        for line in contentList:
            remote_file.write(line)
        remote_file.close()
        return 300
    except:
        return 301
        print('failed to open the remote file!')
    finally:
        client.close()
        

    
def remoteExecuteCmd(host_ip, port, username, password,cmd):
    client = paramiko.SSHClient()
    try:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host_ip, port, username, password, timeout=5)
        stdin, stdout, stderr = client.exec_command(cmd)
        print(stdout.read().decode('utf-8'))
        return 300
    except:
        return 301
        print('failed to execute command!')
    finally:
        client.close()        


parser = OptionParser()
parser.add_option("--buildID", dest="buildID",default="", help="Build ID")
parser.add_option("--domain", dest="domain",default="", help="Domain of the Log")
parser.add_option("--platform", dest="platform",default="", help="Platform info")
parser.add_option("--atxPlatform", dest="atxPlatform",default="", help="Platform info")
parser.add_option("--atxIP", dest="atxIP",default="135.252.245.40", help="ATX IP")
parser.add_option("--pcta", dest="pcta",default="", help="PCTA info")
parser.add_option("--pctaPasswd", dest="pctaPasswd",default="alcatel01", help="PCTA password info")
parser.add_option("--pctaUser", dest="pctaUser",default="atxuser", help="PCTA user info")
parser.add_option("--pctaFolder", dest="pctaFolder",default="/tftpboot/atx/atxuser", help="LOG Folder info")
parser.add_option("--pctaPort", dest="pctaPort",default="22", help="pcta ssh port")
parser.add_option("--load", dest="load",default="ManualLoad", help="Platform info")
parser.add_option("--timeStamp", dest="timeStamp",default="", help="timeStamp of the Log")
parser.add_option("--testSummaryFile", dest="testSummaryFile",default="", help="timesummary file name")
parser.add_option("--serverNoTimestamp", dest="serverNoTimestamp",default=False, help="no timestamp on src log server")
parser.add_option("--traceFiles", dest="traceFiles",default='', help="upload trace log only")
parser.add_option("--domainDir", dest="domainDir",default='', help="domain specific log directory")
parser.add_option("--team", dest="team",default="", help="Team info")
parser.add_option("--batchType", dest="batchType",default="", help="Batch Type")
parser.add_option("--remote", dest="remote",default=False, help="if site is Antwerp this value is True, else is False")
(options, args) = parser.parse_args()

buildID = options.buildID
domain = options.domain
platform = options.platform
atxPlatform = options.atxPlatform
atxIP = options.atxIP
load = options.load
pcta = options.pcta
pctaPort = options.pctaPort
pctaPasswd = options.pctaPasswd
pctaUser = options.pctaUser
pctaFolder = options.pctaFolder
timeStamp = options.timeStamp
testSummaryFile = options.testSummaryFile
serverNoTimestamp = options.serverNoTimestamp
traceFiles = options.traceFiles
domainDir = options.domainDir
team = options.team
batchType = options.batchType
remote=options.remote
print('remote is:%s'%remote)
if not remote:
    if buildID.strip():
      os.getcwd()
      #os.chdir('/var/www/html/log')
      os.chdir('/data/logServer/log')
      if team.strip():
        if os.path.exists(team):
          print("team folder already exists:%s" % team)
        else:
          print("team folder Not exists. Create it:%s" % team)
          os.mkdir(team)
        os.chdir(team)
      if os.path.exists(buildID):
        print("%s folder already exists. enter it" % buildID)
      else:
        print("%s folder Not exists. Create it" % buildID)
        os.mkdir(buildID)
      os.chdir(buildID)
    
      if re.search('^MERCUR-NFXSD-FANTF-GPON-REDUND-DAILY-04$',platform):
        platform = 'NFXSD_FANTF_REDUND_weekly'
    # elif re.search('^MERCUR.*0[1-9]$',platform):
    #   platform = platform[:-3]
    
      if os.path.exists(platform):
        print("%s folder already exists. enter it" % platform)
      else:
        print("%s folder Not exists. Create it" % platform)
        os.mkdir(platform)
      os.chdir(platform)
      
      # below is for traceFile upload reusing original dirctory check and creating logic
      if traceFiles:
        if domainDir and os.path.exists(domainDir):
            os.chdir(domainDir)
        traceFileList = traceFiles.split(',')
        for traceFile in traceFileList:
          traceFile = re.sub(r'([\(|\)])',r'\\\1',traceFile)
          if re.search('testsummary',traceFile):
              cmd = "wget %s" %traceFile
          else:
              traceFolder = '/tmp/.jenkins/'+traceFile.split('/')[-1]
              cmd = "sshpass -p %s scp -P %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r %s@%s:%s ./" % (pctaPasswd,pctaPort,pctaUser,pcta,traceFolder)
          print('cmd=%s' % cmd)
          ret_code = os.system(cmd)
          print('cmd return value = %s' % ret_code) 
        print("tracefiles have been uploaded successfully")
        sys.exit()
      elif not timeStamp.strip():
        print("Invalid arguments")
        print("Please input at least buildID and timeStamp...")
        sys.exit()
      # for normal atc log upload  
      domainLogDir=''
      if pcta != "":
        pass
      else:
        if load != "ManualLoad":
          load = 'SD_' + buildID
        if atxPlatform == "":
          atxPlatform = platform.replace("_", "-")
      f=open('testsummaryAll_%s.log' % testSummaryFile,'a+')
      
      if domain != "":
        if pcta != "":
          print('serverNoTimestamp with domain =%s' % serverNoTimestamp)
          if serverNoTimestamp:
            cmd = "sshpass -p %s scp -P %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r %s@%s:%s ./SB_Logs_%s_%s" % (pctaPasswd,pctaPort,pctaUser,pcta,pctaFolder,timeStamp,domain)
          else:
            cmd = "sshpass -p %s scp -P %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r %s@%s:%s/%s ./SB_Logs_%s_%s" % (pctaPasswd,pctaPort,pctaUser,pcta,pctaFolder,timeStamp,timeStamp,domain)
        else:
          cmd = "sshpass -p \"alcatel01\" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r atxuser@%s:/tftpboot/atx/logs/%s/%s/%s ./SB_Logs_%s_%s" % (atxIP,atxPlatform,load,timeStamp,timeStamp,domain)
        print('cmd=%s' % cmd)
        ret_code = os.system(cmd)
        print('cmd return value = %s' % ret_code) 
        domainLogDir="SB_Logs_%s_%s" %(timeStamp,domain)
        if ret_code == 0:
          filedir = os.getcwd()
          if pcta != "":
            filepath = "%s/SB_Logs_%s_%s/testsummary.log" % (filedir,timeStamp,domain)
          else:
            filepath = "%s/SB_Logs_%s_%s/SB_Logs/testsummary.log" % (filedir,timeStamp,domain)
          f.writelines('######################%s########################\n\n' % domain)
          if os.path.exists(filepath):
            for line in open(filepath):
              f.writelines(line)
          else:
            f.writelines('No testsummary.log on Web server.ATC running maybe incompleted.Please check env\n\n')
          f.writelines('##################################################\n\n')
        else:
          filedir = os.getcwd()
          if pcta != "":
            filepath = "%s/SB_Logs_%s_%s/testsummary.log" % (filedir,timeStamp,domain)
          else:
            filepath = "%s/SB_Logs_%s_%s/SB_Logs/testsummary.log" % (filedir,timeStamp,domain)
          f.writelines('######################%s########################\n\n' % domain)
          if os.path.exists(filepath):
            for line in open(filepath):
              f.writelines(line)
          else:
            f.writelines('Log upload to Web server failed.Please check env network(return code = %s)\n\n' % ret_code)
          f.writelines('##################################################\n\n')
        f.close()
      else:
        if pcta != "":
          print('serverNoTimestamp =%s' % serverNoTimestamp)
          if serverNoTimestamp:
            cmd = "sshpass -p %s scp -P %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r %s@%s:%s ./SB_Logs_%s" % (pctaPasswd,pctaPort,pctaUser,pcta,pctaFolder,timeStamp)
          else:
            if batchType == 'non-framework':
                cmd = "sshpass -p %s scp -P %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r %s@%s:%s/%s ./%s" % (pctaPasswd,pctaPort,pctaUser,pcta,pctaFolder,timeStamp,timeStamp)
            else:
                cmd = "sshpass -p %s scp -P %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r %s@%s:%s/%s ./SB_Logs_%s" % (pctaPasswd,pctaPort,pctaUser,pcta,pctaFolder,timeStamp,timeStamp)
        else:
          cmd = "sshpass -p \"alcatel01\" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r atxuser@%s:/tftpboot/atx/logs/%s/%s/%s ./SB_Logs_%s" % (atxIP,atxPlatform,load,timeStamp,timeStamp)
        print('cmd=%s' % cmd)
        ret_code = os.system(cmd)
        print('cmd return value = %s' % ret_code)
        if batchType == 'non-framework':
            domainLogDir=timeStamp
        else:    
            domainLogDir="SB_Logs_%s" %timeStamp
            f.close()
            os.system('rm -rf testsummaryAll_%s.log' % testSummaryFile)
      if ret_code == 0:
        print('LOG_DIR:%s' %domainLogDir)
    else:
      print("Invalid arguments")
      print("Please input at least buildID and timeStamp...")
else:
    logSIp='10.131.213.53'
    logSPort=22
    logSUser='smtlab'
    logSPwd='smtlab'
    if buildID.strip():
        currentDir='/data/logServer/log'
        if team.strip():
            teamPath='%s/%s'%(currentDir,team)
            buildPath='%s/%s'%(teamPath,buildID)
            platformPath='%s/%s'%(buildPath,platform)
            checkPathList=[teamPath,buildPath,platformPath]
            logServerCheckFile(logSIp,logSUser,logSPwd,checkPathList,logSPort,create=True)
            currentDir=platformPath
        if traceFiles:
            domainPath='%s/%s'%(currentDir,domainDir)
            exist=logServerCheckFile(logSIp,logSUser,logSPwd,[domainPath],logSPort,create=False)
            if exist==300:
                currentDir=domainPath
           
            traceFileList = traceFiles.split(',')
            print('traceFileList is:')
            print(traceFileList)
            for traceFile in traceFileList:
                traceFile = re.sub(r'([\(|\)])',r'\\\1',traceFile)
                if re.search('testsummary',traceFile):
                    ret_code=uploadToLogServer(logSIp,logSPort,logSUser,logSPwd,traceFile,currentDir)
                else:
                    traceFolder = '/tmp/.jenkins/'+traceFile.split('/')[-1]
                    ret_code=translateFilesFromLinuxMToLogS(pcta,pctaPort,pctaUser,pctaPasswd,traceFolder,logSIp,logSPort,logSUser,logSPwd,currentDir)
            sys.exit()
        elif not timeStamp.strip():
            print("Invalid arguments")
            print("Please input at least buildID and timeStamp...")
            sys.exit()
            
        domainLogDir=''
        if pcta == '':
            if load != "ManualLoad":
                load = 'SD_' + buildID
            if atxPlatform == "":
                atxPlatform = platform.replace("_", "-")
                
        contentList=[]
        if domain != "":
            RemotePath='%s/SB_Logs_%s_%s'%(currentDir,timeStamp,domain)
            if pcta!="":
                print('serverNoTimestamp with domain =%s' % serverNoTimestamp)
                if serverNoTimestamp:
                    localFile=pctaFolder
                else:
                    localFile='%s/%s'%(pctaFolder,timeStamp)
                ret_code=translateFilesFromLinuxMToLogS(pcta,pctaPort,pctaUser,pctaPasswd,localFile,logSIp,logSPort,logSUser,logSPwd,RemotePath)
                filepath = "%s/testsummary.log" %RemotePath
            else:
                localFile='/tftpboot/atx/logs/%s/%s/%s'%(atxPlatform,load,timeStamp)
                ret_code=translateFilesFromLinuxMToLogS(atxIP,22,'atxuser','alcatel01',localFile,logSIp,logSPort,logSUser,logSPwd,RemotePath)
                filepath = "%s/SB_Logs/testsummary.log" %RemotePath
            print('tramslate summary return value = %s' % ret_code)
            
            domainLogDir="SB_Logs_%s_%s" %(timeStamp,domain)
            
            contentList.append('######################%s########################\n\n' % domain)
            exist=logServerCheckFile(logSIp,logSUser,logSPwd,[filepath],logSPort,create=False) 
            if exist:
                lines=readFileFromLogServer(logSIp, logSPort, logSUser, logSPwd,filepath)
                contentList+=lines
            else:
                if ret_code == 300:
                    contentList.append('No testsummary.log on Web server.ATC running maybe incompleted.Please check env\n\n')
                else:
                    contentList.append('Log upload to Web server failed.Please check env network(return code = %s)\n\n' % ret_code)
            contentList.append('##################################################\n\n')
            summaryFileName='%s/testsummaryAll_%s.log' % (currentDir,testSummaryFile)
            writeFileToLogServer(logSIp,logSPort,logSUser,logSPwd,summaryFileName,contentList)
            
        else:
            print('no domian switch')
            linuxMIp=pcta
            linuxMPort=pctaPort
            linuxUsr=pctaUser
            linuxPwd=pctaPasswd
           
            if pcta != "":
                print('serverNoTimestamp =%s' % serverNoTimestamp)
                if serverNoTimestamp:
                    print('serverNoTimestamp is True')
                    localFile=pctaFolder
                    RemotePath='%s/SB_Logs_%s'%(currentDir,timeStamp)
                else:
                    print('serverNoTimestamp is False')
                    if batchType == 'non-framework':
                        localFile='%s/%s'%(pctaFolder,timeStamp)
                        RemotePath='%s/%s'%(currentDir,timeStamp)
                    else:
                        localFile='%s/%s'%(pctaFolder,timeStamp)
                        RemotePath='%s/SB_Logs_%s'%(currentDir,timeStamp)
            else:
                localFile='/tftpboot/atx/logs/%s/%s/%s'%(atxPlatform,load,timeStamp)
                RemotePath='%s/SB_Logs_%s'%(currentDir,timeStamp)
                linuxMIp=atxIP
                linuxMPort=22
                linuxUsr='atxuser'
                linuxPwd='alcatel01'
            
            ret_code=translateFilesFromLinuxMToLogS(linuxMIp,linuxMPort,linuxUsr,linuxPwd,localFile,logSIp,logSPort,logSUser,logSPwd,RemotePath)
            
            print('no domain translate return value = %s' % ret_code)
            
            if batchType == 'non-framework':
                domainLogDir=timeStamp
            else:    
                domainLogDir="SB_Logs_%s" %timeStamp
                deleteFile='%s/testsummaryAll_%s.log'%(currentDir,testSummaryFile)
                logServerDeleteFile(logSIp,logSUser,logSPwd,[deleteFile],logSPort)               
        if ret_code == 300:
            print('LOG_DIR:%s' %domainLogDir)
    else:
        print("Invalid arguments")
        print("Please input at least buildID and timeStamp...") 

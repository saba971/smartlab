#! /usr/bin/python                                                                                                      
#coding:utf-8
# Author: Wang Weiwei <Weiwei.Wang@alcatel-sbell.com.cn>
import json,requests
import urllib
import ftplib
import socket
import tarfile,random
import pexpect
import copy,json
import logging,socket,paramiko
import telnetlib, time, re, os, ConfigParser, sys, inspect, subprocess,datetime
from lxml import etree
from argparse import ArgumentParser
import oswpUtility
from qemuUtility import startHostBySSH
ddir='/root/pylib'
sys.path.append(ddir)
from urlDaily import *
from retrieveLatestBuild import *
from sshClient import ssh2,ssh_scp_get,ssh2_non_block,ssh_server_check
import yaml
#import sw_update_netconf
from sw_update_netconf import Smartlab_Instance
from buildUtility import *
import json,requests
import com_tnd
import ipaddress
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
TND_SESSION={}
#HOST = '135.252.245.46'
LOCAL_LOAD_PATH='/tftpboot/atx/loads'
#DIRN = '/ftp'
LOCAL_LOAD_PATH='/tftpboot/atx/loads'
BUILD_ID_MAP_FILE = 'BuildIDMapping.yaml'
DIRN = '/loads'
ver2 = ''
#DIRN = '/ftpserver/loads'
TFTP_SERVER_IP = '135.252.245.44'
TFTP_SERVER_DIR = '/tftpboot'
REMOTEHOST='172.21.128.21'
VERSION_DICT = {'58':'499','5701':'499','5801':'599'}
JENKINS_FILE_DIR = '/var/www/html/repo/atxuser/cases'
SCRIPT_PATH='/var/jenkins_home/scripts'
PCTA_SESSION = ''
LIS_DIR = ''
MOSWA_OSWP_NAME = ''
MOSWA_OSWP_URL = ''
MOSWA_LIST = []
trans_mode = ''
file_index = ''
build = ''
NetLinuxPort = 2222 
NetOamPort = 830
MOSWA_NT_NETCONF_PORT = '832'
MOSWA_NT_TRACE_PORT = '923'
loginCmd = {'TELNET':'telnet ','SSH':'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null isadmin@'}

#SMARTLAB_SERVER='https://smartservice.int.nokia-sbell.com'
#SMARTLAB_SERVER='http://135.251.206.149'
#LOG_SERVER={'FQDN':'http://smartlab-service.int.net.nokia.com:9000/log','IP':'10.131.213.53','HTTP':'http://10.131.213.53:9000/log'}
fileYaml = 'buildHandling.yaml'
fileYaml = os.path.join(SCRIPT_PATH,fileYaml)
if not os.path.exists(fileYaml):
    print("buildHandling.yaml does not exist with buildHandling together")
    sys.exit(1)
fdYaml = open(fileYaml,'rb')
BUILDDICT = yaml.load(fdYaml,Loader=yaml.FullLoader)
SMARTLAB_SERVER=BUILDDICT.get('SMARTLAB_SERVER','https://smartservice.int.nokia-sbell.com')
LOG_SERVER=BUILDDICT['LOG_SERVER']
RELEASE_MAP=BUILDDICT['RELEASE_MAP']
ERROR_CODE=BUILDDICT['ERROR_CODE']
BUILD_SOURCE_REPLACEMENT=BUILDDICT.get('BUILD_SOURCE_REPLACEMENT','')
dict_m_d_map = {'Jan':'01','Feb':'02','Mar':'03','Apr':'04','May':'05','Jun':'06','Jul':'07','Aug':'08','Sep':'09','Oct':'10',\
                'Nov':'11','Dec':'12'}


RERUN_TIMEOUT = 60*60
logLevel={'normal':0,'info':1,'debug':2}
LEVEL='normal'

def _ls_filter(ver,m_today,d_today,tarList):
    def filterProcess(line):
        ll = line.split()
        # for normal tar file, should have 9 elements and time is 20:16 instead of 2017
        if len(ll) == 9 and len(ll[7]) == 5:
            if ver.find('.') == -1 and (dict_m_d_map[ll[5]] + ll[6]) >= (m_today + d_today) and re.match(r'SD_%s\.[\d]{3}\.tar' %ver,ll[8]):
                tarList.append(ll[7] + '-' + ll[8])
                return ll[8]        
            elif re.match(r'SD_%s\.tar' %ver,ll[8]):
                tarList.append(ll[7] + '-' + ll[8])
                return ll[8]
    return filterProcess

def pcta_process_kill(linuxIP,userName,passwd,linuxPORT):
    try:
        #To retrieve start PCTA process pid
        db_print("kill zombi pcta exe")
        pcta_cmd="ps -aef | grep pcta.exe | grep -v defunct | grep -v grep | awk '{print $2}'"
        pid=ssh2(linuxIP, userName,passwd,pcta_cmd,'check',port=int(linuxPORT))
        pid=pid.strip()
        for val in pid.split('\n'):
            if val != '':
                kill_cmd="sudo /bin/kill -9 %s" %val
                ssh2(linuxIP, userName,passwd,kill_cmd,port=int(linuxPORT))
        db_print("kill 4002 listening process")
        pcta_cmd = "/usr/sbin/lsof -i:4002 | awk 'NR>1 {print $2}'"
        #pid=ssh2(linuxIP, userName,passwd,pcta_cmd,'check',port=int(linuxPORT))
        cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s '%s'" %(passwd,userName,linuxIP,pcta_cmd)
        pid=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        pid=pid.strip().strip('\n')
        pids = ' '.join(pid.split('\n'))
        if pids:
            kill_cmd="sudo /bin/kill -9 %s" %pids
            ssh2(linuxIP, userName,passwd,kill_cmd,port=int(linuxPORT))
        #db_print("clean /usr/tmp/* for pcta")
        #pcta_cmd="rm -rf /usr/tmp/*"
        #pid=ssh2(linuxIP, userName,passwd,pcta_cmd,'check',port=int(linuxPORT))
    except Exception as inst:
        db_print("PCTA process kill error:%s" %inst)

def pcta_start(server_ip,linuxIP,linuxPORT,linuxUser,linuxPasswd,directory,pcta_exe_cmd):
    try:
        localscript = SCRIPT_PATH + '/pctaprocess_start.py'
        remotepath = '/tmp/.jenkins'
        remotescript = '/tmp/.jenkins/pctaprocess_start.py'
        cmd = "sshpass -p 'alcatel01' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'ls %s'" %(server_ip,remotescript)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        if not result.strip() == remotescript:
            cmd = "sshpass -p 'alcatel01' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'mkdir -p /tmp/.jenkins'" %server_ip
            db_print(cmd,'debug')
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
            db_print(cmd,'debug')
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        cmd_pcta = '%s --linux_ip %s --port %s --linuxuser %s --linuxpass %s --directory \'%s\' --command \'%s\' --prompt %s' %(remotescript,linuxIP,linuxPORT,linuxUser,linuxPasswd,directory,pcta_exe_cmd,'%')
        res=ssh2(server_ip, 'atxuser','alcatel01',cmd_pcta,'checkandprint')
        if not res.find('Ready to serve requests...') == -1:
            db_print("PCTA start successfully")
    except Exception as inst:
        db_print("PCTA start function failed:%s" %inst)

def octopus_check(server_ip,isamIP,tnd_cmd):
    try:
        localscript = SCRIPT_PATH + '/octopus_connect.py'
        remotepath = '/tmp/.jenkins'
        remotescript = '/tmp/.jenkins/octopus_connect.py'
        cmd = 'cksum %s' %localscript
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        new_cksum = result.strip().split(' ')[0]
        db_print('cksum:%s' %new_cksum)
        cmd = "sshpass -p 'alcatel01' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'cksum %s'" %(server_ip,remotescript)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        old_cksum = result.strip().split(' ')[0]
        db_print('cksum:%s' %old_cksum)
        result=''
        if new_cksum and not old_cksum == new_cksum :
            cmd = "sshpass -p 'alcatel01' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'mkdir -p /tmp/.jenkins'" %server_ip
            db_print(cmd,'debug')
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
            db_print(cmd,'debug')
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            localscript = SCRIPT_PATH + '/com_tnd.py'
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
            db_print(cmd,'debug')
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            cmd = 'ls %s/octopus' %remotepath
            tmp_res=ssh2(server_ip, 'atxuser','alcatel01',cmd,'check')
            if re.search('No such',tmp_res):
                cmd = 'uname -a'
                tmp_res=ssh2(server_ip, 'atxuser','alcatel01',cmd,'check')
                if re.search('el[\d]\.i686',tmp_res):
                    localscript = SCRIPT_PATH + '/octopus32'
                    remotepath = remotepath + '/octopus'
                else:
                    localscript = SCRIPT_PATH + '/octopus'
                    remotepath = remotepath + '/octopus'
                cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
                db_print(cmd,'debug')
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        cmd_octopus = '%s --isam_ip %s --cmd %s' %(remotescript,isamIP,tnd_cmd)
        tmp_res=ssh2(server_ip, 'atxuser','alcatel01',cmd_octopus,'check')
        print tmp_res
        if tmp_res.find('diskSync finished successfully') == -1:
            result = False
        else:
            result = True
        return result
    except Exception as inst:
        db_print("Octopus function failed:%s" %inst)
        return False

def ssh_linux(password,command):
    try:
        child =  pexpect.spawn(command)
        i = child.expect(['password:', r'\(yes\/no\)',r'.*[$#] ',pexpect.EOF])
        if i == 0:
                child.sendline(password)
        elif i == 1:
                child.sendline("yes")
                ret1 = child.expect(["password:",pexpect.EOF])
                if ret1 == 0:
                        child.sendline(password)
                else:
                        pass
        else:
                print "Error in scp"
                return False
        time.sleep(20)
        data = child.read()
        child.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
        child.close()
        return True
    except Exception as error:
        print error
        return False

def exist_extra_tar(buildID,linuxip,linux_user,linux_pass,pcta_folder="/tftpboot/atx/loads"):
    if product in ['SDFX','SDOLT','NCDPU']:
        ver_build='lightspan_' + buildID + '.extra.tar'
    else:
        ver_build='SD_' + buildID + '.extra.tar'
    cmd2="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'ls %s | grep %s'" %(linux_pass,linux_user,linuxip,pcta_folder,ver_build)
    result=subprocess.Popen(cmd2, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
    if result != "":
        print "%s available in %s" %(ver_build,pcta_folder)
        return True
    return False
        
def copy_extra_tar_to_linux(buildID,linuxip,linux_user,linux_pass,tftpserverip,product,privateNetwork,srcDir='/tftpboot',pcta_folder="/tftpboot/atx/loads"):
    if privateNetwork:
        db_print("inband setup,no need to copy extra tar happens on exec server")
        return True
    localDir = False
    orig_result = True
    if product in ['SDFX','SDOLT','NCDPU']:
        ver_build='lightspan_' + buildID + '.extra.tar'
    else:
        ver_build='SD_' + buildID + '.extra.tar'

    ####To check directory exists or not####
    cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'ls -d %s'" %(linux_pass,linux_user,linuxip,pcta_folder)
    result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
    if result == "":
        localDir = True
        print "%s directory not available" %pcta_folder
        cmd1="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'mkdir -p %s'" %(linux_pass,linux_user,linuxip,pcta_folder)
        cmd1a="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'chmod -R +x %s'" %(linux_pass,linux_user,linuxip,pcta_folder)
        try:
            result=subprocess.Popen(cmd1, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            print "%s directory created" %pcta_folder
            res1=subprocess.Popen(cmd1a, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            #check whether directory created successfuly
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            if result:    
                orig_result = True
        except:
            db_print("Unable to create directory")
            orig_result = False
            #sys.exit(1)    
    else:
        print "%s directory already available" %pcta_folder
        db_print("check extraTar dir is local dir or mounted one")
        cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'df --type=nfs -P %s'" %(linux_pass,linux_user,linuxip,pcta_folder)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        if result.strip().strip('\n'):
            localDir = False
            db_print("remote dir")
        else:
            localDir = True
            db_print("local dir")
    ####To copy extra_tar from tftpserver to linux machine####
    if orig_result:
        print "To check whether %s is available in %s" %(ver_build,pcta_folder)
        cmd2="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'tar -tf %s/%s'" %(linux_pass,linux_user,linuxip,pcta_folder,ver_build)
        result=subprocess.Popen(cmd2,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True).communicate()
        if len(result) == 2 and ('Error is not recoverable' in result[1] or 'Exiting with failure status'  in result[1]):
            db_print("extra tar not exist or not complete or 0 size")
            if localDir:
                print "Copy %s from tftpserver to PCTA machine" %ver_build
                cmd3="sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s/%s %s@%s:%s" %(linux_pass,srcDir,ver_build,linux_user,linuxip,pcta_folder)
                val_out=ssh2(tftpserverip,'atxuser','alcatel01',cmd3,'check')
                db_print("after copy,check tar completeness again")
                cmd2="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'tar -tf %s/%s'" %(linux_pass,linux_user,linuxip,pcta_folder,ver_build)
                result=subprocess.Popen(cmd2,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True).communicate()
                if len(result) == 2 and ('Error is not recoverable' in result[1] or 'Exiting with failure status'  in result[1]):
                    db_print("copied tar file is corrupted")
                    orig_result= False
                else:
                    db_print("copied tar file is complete")
            else:
                orig_result= False 
        else:
            db_print("%s is available in %s" %(ver_build,pcta_folder))
    else:
        print "Issue in dir creation/failed to copy extra tar"        
        orig_result= False
    return orig_result

def lis_build_dir_create(serverip,destDir,action,userName='atxuser',passwd='alcatel01'):
  dir_flag="True"
  ####To check directory exists or not####
  cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'ls -d %s'" %(passwd,userName,serverip,destDir)
  result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
  if action == "create":
      if result == "":
        print "%s directory not available" %destDir
        cmd1="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'mkdir -p %s'" %(passwd,userName,serverip,destDir)
        cmd1a="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'chmod -R +x %s'" %(passwd,userName,serverip,destDir)
        try:
            result=subprocess.Popen(cmd1, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            print "%s directory created" %destDir
            res1=subprocess.Popen(cmd1a, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            dir_flag="True"
        except:
            db_print("Unable to create directory")
            dir_flag="False"
            sys.exit(1)
      else:
        print "%s directory already available" %destDir
  elif action == "delete":
        if result == "":
            print "%s directory not available" %destDir
            print "Skip Delete %s Directory" %destDir
        else:
            print "%s directory already available" %destDir
            cmd1="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'rm -rf %s'" %(passwd,userName,serverip,destDir)
            try:
                result=subprocess.Popen(cmd1, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                print "%s Directory deleted" %destDir
            except:
                db_print("Unable to Delete directory")
                dir_flag="False"
            postfix = re.sub('^.*tftpboot\/?','',destDir).strip()
            if postfix:
                print "clean scripts for private network"
                aScript = '/tmp/.jenkins/buildUtility.py'
                aScript = postfix2script(aScript,postfix)
                cmd1="ps -aef | grep %s | grep -v grep | awk \'{print $2}\' | tr -s \'\n\' |xargs kill -9" %aScript
                cmd1="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s \"%s\"" %(passwd,userName,serverip,cmd1)
                db_print(cmd1,'debug')
                try:
                    result=subprocess.Popen(cmd1, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                    print "%s process killed" %aScript
                except:
                    db_print("Unable to kill process")
                    dir_flag="False"
                cmd1="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'rm -rf %s'" %(passwd,userName,serverip,aScript)
                try:
                    result=subprocess.Popen(cmd1, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                    print "%s Directory deleted" %aScript
                except:
                    db_print("Unable to Delete directory")
                    dir_flag="False"
  return dir_flag

def GetLISDir():
  lis_dir = ''
  try :
      build_url = os.environ['BUILD_URL']
      build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)
  except Exception as inst:
      db_print('Failed to get LIS  directory:%s' %inst)
      return lis_dir
  try:
      cmd = "curl -s %sconsoleText |grep -o -a -E 'LIS DIRECTORY: .*'" %build_url
      #db_print(cmd)
      result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
      result=result.rstrip('\n')
      nout=re.search('LIS DIRECTORY: (.*)',result)
      if nout:
        lis_dir=nout.group(1)
        lis_dir=lis_dir.strip()
        print lis_dir
  except Exception as inst:
      db_print('Failure in access LIS directory:%s' %inst)
      #sys.exit(1)
      pass
  return lis_dir

def GetLISTimestamp():
  lis_timestamp=''
  try :
      build_url = os.environ['BUILD_URL']
      build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)
  except Exception as inst:
      db_print('Failed to get LIS timestamp:%s' %inst)
      return lis_timestamp
  try:
      cmd = "curl -s %sconsoleText |grep -o -a -E 'LIS TIMESTAMP: .*'" %build_url
      #db_print(cmd)
      result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
      result=result.rstrip('\n')
      nout=re.search('LIS TIMESTAMP: (.*)',result)
      if nout:
        lis_timestamp=nout.group(1)
        lis_timestamp=lis_timestamp.strip()
        print lis_timestamp
  except Exception as inst:
      db_print('Failure in access LIS timestamp:%s' %inst)
      pass
  return lis_timestamp  
  
def GetLogDir():
  try :
      build_url = os.environ['BUILD_URL']
      build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)
  except Exception as inst:
      db_print('Failed to get buildurl:%s' %inst)
      return
  try:
      cmd = "curl -s %sconsoleText |grep -o -a -E 'LOG_DIR:SB_Logs_.*' |uniq |tail -1" %build_url
      #db_print(cmd)
      result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
      result=result.strip().strip('\n').split('\n')
      nout=re.search('LOG_DIR:(.*)',result[-1])
      logDir=nout.group(1)
      logDir=logDir.strip()
      #print logDir
      if logDir == 'SB_Logs_':
          logDir = ''
  except Exception as inst:
      db_print('Failure in access LOG_DIR:%s' %inst)
      logDir = ''
  return logDir
  
def Get_MOSWA_NAME():
  global MOSWA_OSWP_NAME
  if MOSWA_OSWP_NAME:
      return MOSWA_OSWP_NAME
  try :
      build_url = os.environ['BUILD_URL']
      build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)
  except Exception as inst:
      db_print('Failed to get LIS  directory:%s' %inst)
      return ''
  max_retry_num = 2 
  moswa_name = ''
  try:
      cmd = "curl -s %sconsoleText |grep -o -a -E 'MOSWA OSWP NAME: .*'" %build_url
      #db_print(cmd)
      for retry_num in range(max_retry_num):
          result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
          result=result.rstrip('\n')
          nout=re.search('MOSWA OSWP NAME: (.*)',result)
          if nout:
              moswa_name=nout.group(1)
              moswa_name=moswa_name.strip()
              break
          else:
              time.sleep(5)
              db_print("wait for console curl")              
  except Exception as inst:
      db_print('Failure in access MOSWA OSWP NAME:%s' %inst)
      sys.exit(1)
  return moswa_name
  
def Get_MOSWA_URL():
  global MOSWA_OSWP_URL
  if MOSWA_OSWP_URL:
      return MOSWA_OSWP_URL
  try :
      build_url = os.environ['BUILD_URL']
      build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)
  except Exception as inst:
      db_print('Failed to get LIS  directory:%s' %inst)
      return
  try:
      cmd = "curl -s %sconsoleText |grep -o -a -E 'MOSWA OSWP URL: .*'" %build_url
      db_print(cmd)
      result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
      result=result.rstrip('\n')
      nout=re.search('MOSWA OSWP URL: (.*)',result)
      moswa_url=nout.group(1)
      moswa_url=moswa_url.strip()
      print moswa_url
  except Exception as inst:
      db_print('Failure in access MOSWA OSWP URL:%s' %inst)
      sys.exit(1)
  return moswa_url
  
def getHomeDir(linuxIP='',userName='atxuser',passwd='alcatel01',linuxPORT='22'):
    try:
        cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p%s %s@%s 'ls -d ~'" %(passwd,linuxPORT,userName,linuxIP)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        homeDir = result.strip().split(' ')[0]
    except Exception as inst:
        db_print("get home dir with exception:%s" %inst)
        homeDir = '~'
    return homeDir

def checkFramework(batchCommand):
    apmeRun = False if re.search(r'[\s|\b]+-a',batchCommand) else True
    robotRun = True if re.search(r'[\s|\b]+--framework[\s|\b]+?ROBOT',batchCommand) else False
    if apmeRun:
        return 'APME'
    else:
        return 'ROBOT'

def createWorkDir(linuxIP,userName,passwd,linuxPORT,workDir,frameworkType):

    ####To check directory exists or not####
    cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p%s %s@%s 'ls -d %s'" %(passwd,linuxPORT,userName,linuxIP,workDir)
    result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]

    if result == "":
        db_print("%s:create directory" %workDir)
        try:
            #for LTB to print Updating related infor,need mkdir -p also for ROBOT
            db_print(cmd,'debug')
            if frameworkType == 'APME':
                subDirs = '%s/ARIES/RES_ROOT/focus %s/ARIES/DATA %s/ARIES/DATAFILES' %(workDir,workDir,workDir)
            else:
                subDirs = '%s/ROBOT' %workDir
            #subDirs = re.sub(r'(\/)',r'\\\1',subDirs)
            cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p%s %s@%s 'mkdir -p %s'" %(passwd,linuxPORT,userName,linuxIP,subDirs)
            db_print(cmd,'debug')
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p%s %s@%s 'chmod -R +x %s'" %(passwd,linuxPORT,userName,linuxIP,workDir)
            db_print(cmd,'debug')
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        except Exception as inst:
            db_print("Unable to create directory:%swith exception:%s" %(workDir,inst))
            return False
    else:
        db_print("%s directory already available" %workDir)
    return True

def isPlatformInGICIMAP():
    if not os.path.exists('GICI_MAPLIST.txt'):
        cmd = '''wget -q --timeout 10 --tries 1 "http://aww.sh.bel.alcatel.be/ClearCase/view/LATEST/cm8/auto/tools/pbscript/GICI_MAPLIST.txt"'''
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
    res = False
    #for trace_server in trace_server_list:
    #    if not ' ' in trace_server:
    #        continue
    #    tmpList = trace_server.split(' ')
    #    if len(tmpList) < 3:
    #        continue
    #    gici_ip = tmpList[0].strip()
    #    gici_port = tmpList[1].strip()
    try:
        job_name = os.environ['JOB_NAME']
        with open('GICI_MAPLIST.txt','r') as fin:
            for line in fin:
                if job_name in line:
                    res = True
                    break
            fin.close()
    except Exception as inst:
        res = True
    return res


  


def _get_extra_shelf_commands(linux_ip,user,passwd, port,action):
    global envOverriden
    try :
        workspace = os.environ['WORKSPACE']
        workspace = re.sub(r'([\(|\)])',r'\\\1',workspace)
    except Exception as inst:
        print 'failure to get workspace'
        workspace = '/tmp'
    lines=[]
    try:
        if action == 'config':
            cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:%s/configs/pre_shelf_config_command %s" %(passwd,port,user,linux_ip,envOverriden['HOME'],workspace)
        else:
            cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:%s/configs/post_shelf_unconfig_command %s" %(passwd,port,user,linux_ip,envOverriden['HOME'],workspace)
        result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        db_print("\n%s with output:%s" %(cmd,result))
        if action == 'config':
            aFile = open(workspace + '/pre_shelf_config_command','r')
        else:
            aFile = open(workspace + '/post_shelf_unconfig_command','r')
        lines = aFile.readlines()
        for idx in xrange(0,len(lines)):
            lines[idx] = lines[idx].strip('\n')
    except Exception as inst:
        #print "no extra shelf commands"
        pass
    return lines

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


def _download_case_list(linux_ip,username,passwd,port,robotCaseList):
    localDir = '/tmp'
    db_print('old_case_list:%s' %robotCaseList)
    try:
        workspace = os.environ['WORKSPACE']
        localDir = re.sub(r'([\(|\)])',r'\\\1',workspace)
    except Exception as inst:
        db_print("this operation can only run on jenkins server as run python script step:%s" %inst)
    local_case_list = []
    for caselist in robotCaseList.split(','):
        local_case = os.path.join(localDir,os.path.basename(caselist))
        if not os.path.exists(local_case):
            ssh_scp_get(ip=linux_ip,username=username,password=passwd,port=int(port),local=local_case,remote=caselist)
        local_case_list.append(local_case)
    new_case_list = ','.join(local_case_list)
    db_print('new_case_list:%s' %new_case_list)
    return new_case_list

def getLatestBuild(ver):
    t0 = time.time()
    try :
        build_id = os.environ['BuildID']
        #jenkins_home = os.environ['JENKINS_HOME']
        workspace = os.environ['WORKSPACE']
        #workspace = re.sub(r'([\(|\)])',r'\\\1',workspace)
        #build_id = ver
        #jenkins_home = "/tftpboot/atx/atxuser"
        #workspace = "/tftpboot/atx/atxuser/jenkins"
    except Exception as inst :
        db_print("this operation can only run on jenkins server as run python script step:%s" %inst)
        return (False,0) 
    if ver.find('.') != -1:
        try:
            os.chdir(workspace)
            fd=open('job_env.prop',"w+")
            fd.writelines('BuildIDNew=%s' %ver)
        except Exception as inst:
            db_print("file operation failure %s" %inst)
            return (False,0)
        fd.close()
        t1 = time.time()
        return (True,t1-t0) 
    try:
        f = ftplib.FTP(REMOTEHOST)
        #f = ftplib.FTP(HOST)
    except ftplib.error_perm:
        db_print('Cannot connect to ftp server"%s"' % HOST)
        return (False,0)
    db_print('Connected to ftp server"%s"' % HOST)
                                            
    try:
        f.login('rmtlab','rmtlab')
        #f.login('asblab2','asblab2')
    except ftplib.error_perm:
        db_print('login failed')
        f.quit()
        return (False,0)
    db_print('login sucessfully')

    try:
        f.cwd('/ftpserver/RLAB')
        #f.cwd('/loads')
    except ftplib.error_perm:
        db_print('failed to listed files')
        f.quit()
        return (False,0)
    r = "^SD_%s\.(\d{3})\.tar$" %ver
    listTar = []
    #(m_today,d_today)=time.strftime('%b-%d',time.localtime(time.time())).split('-')
    today_time = datetime.datetime.now()
    #change %b to be %m for comparison
    (m_today,d_today,w_today)=today_time.strftime('%m-%d-%w').split('-')
    today_3_ago = today_time + datetime.timedelta(days=-3)
    (m_today_3,d_today_3,w_today_3)=today_3_ago.strftime('%m-%d-%w').split('-') 
    #for Monday, then use latest build since last Friday
    if w_today == '1' :
        m_today = m_today_3
        d_today = d_today_3
    #if no version found in VERSION_DICT,means maintenance build,find latest build in last 30 days
    if not VERSION_DICT.has_key(ver):
        today_30_ago = today_time + datetime.timedelta(days=-30)
        (m_today_30,d_today_30,w_today_30)=today_30_ago.strftime('%m-%d-%w').split('-') 
        m_today = m_today_30
        d_today = d_today_30        
    #for REMOTEHOST it is 8 for HOST, it is 08
    d_today = d_today[1] if d_today[0] == '0' else d_today
    #print (m_today,d_today)
    l_filter = _ls_filter(ver,m_today,d_today,listTar)
    f.retrlines('LIST',l_filter)
    f.quit()
    db_print("####################################################")
    db_print("#All matched from FTP server are as follows:")
    db_print("####################################################\n")
    listTar = sorted(listTar,reverse=True)
    db_print(str(listTar))
    version_max = VERSION_DICT[ver] if VERSION_DICT.has_key(ver) else '900'
    latest_max = '000'
    for item in listTar:
        tarfile = item.split('-')[1][-7:-4]
        #version_max = VERSION_DICT[ver] if VERSION_DICT.has_key(ver) else '900'
        if tarfile < version_max and tarfile >= latest_max :
            latest_max = tarfile
    if latest_max > '000':
        latest_ver = '%s.%s' %(ver,latest_max)
        os.chdir(workspace)
    else :
        latest_ver = ''
    if not latest_ver:
        return False
    fd=open('job_env.prop',"w+")
    fd.writelines('BuildIDNew=%s' %latest_ver)
    fd.close()
    t1 = time.time()
    db_print("find build:%s" %latest_ver)
    return True
    
def getLatestBuildNew(ver,release,HOST,productType,hostFlag):
    t0 = time.time()
    latestBuildServer=''
    latest_ver=''
    orig_job_name=''
    job_num='1'

    try :
        build_id = os.environ['BuildID']
        workspace = os.environ['WORKSPACE']
        orig_job_name = os.environ['JOB_NAME'] 
        job_num = os.environ['BUILD_NUMBER']
    except Exception as inst :
        db_print("this operation can only run on jenkins server as run python script step:%s" %inst)
        return (False,0) 
    
    if not ver or ver=='latest':
        if hostFlag:
            db_print("build id must be present for host")
            return (False,0)
        try:
            HOSTDic=_parse_build_server(HOST)
            buildsList=getBuildbyRel(release,RELEASE_MAP,HOSTDic,productType)
            latest_ver=LatestBuild(buildsList)
            if latest_ver:
                bServerL=HOST.split(':')
                latestBuildServer=getAvailableBuild(bServerL,release,latest_ver,RELEASE_MAP,hostFlag,productType)
                reportLatestBuild(latest_ver)
            else:
                db_print("Does not get any build by smartLab!")
                return (False,0)
        except Exception as inst:
            db_print("getlatest build exception:%s" %inst)
            e = sys.exc_info()[0]
            import traceback
            traceback.print_exc()
            print(traceback.format_exc())
            return (False,0)  
    else:
        latest_ver=ver
     
    if latest_ver:
        try:
            os.chdir(workspace)
            fd=open('job_env.prop',"w+")
            fd.writelines('BuildIDNew=%s' %latest_ver)
            #only target report this status to sls
            if not hostFlag:
                data = {'jobName':orig_job_name,'jobNum':job_num,'currentStatus':'COMPLETED','buildID':latest_ver}
                reportStatus('build',data)
        except Exception as inst:
            db_print("file operation failure %s" %inst)
            return (False,0)
        fd.close()
   
    t1 = time.time()
    return (True,time.localtime(t1 - t0),latestBuildServer,latest_ver)

def prepareOSWP(release,build,buildServer,ftpServer,productType,extraOptions,JKS_BuildID,JKS_BuildIDNew,jobName,extraTar=False,defaultDB=True,toolOnly=False):
    resDict = {}
    result = True
    resDict['res'] = result
    tmpList = ftpServer.split(':')
    linuxIP = tmpList[0]    
    linuxPort = tmpList[1]
    linuxUser = tmpList[2]
    linuxPasswd = tmpList[3]
    lisDir = tmpList[4]
    postfix = re.sub('^.*tftpboot\/?','',lisDir)
    remoteScript = postfix2script('/tmp/.jenkins/buildUtility.py',postfix)
    db_print("for private network,try execute image flash script remotely")
    cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p%s %s@%s 'ls %s'" %(linuxPasswd,linuxPort,linuxUser,linuxIP,remoteScript)        
    result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
    if not result.strip():
        db_print("buildUtility script not on remote machine:%s" %linuxIP)
        resDict['res'] = False
        resDict['error'] = '501'
        return resDict
    try:
        cmd = "/usr/bin/python -u {script} --buildServer {tftpServer} --ftpServer {buildSource} --platformType {product}\
 --release {release} --build {build} --loadinfo {loadinfo} --extraTar {extraTar} --extraOptions \'\'\'{extraOptions}\'\'\'".format(
        script=remoteScript,tftpServer=buildServer,buildSource=ftpServer,product=productType,release=release,build=build,
        loadinfo=loadinfo,extraTar=extraTar,extraOptions = extraOptions)
        cmd += " --jksBuild {jksBuild} --jksNewBuild {jksNewBulld} --platform {jobName} --defaultDB {defaultDB}".format(jksBuild=JKS_BuildID,jksNewBulld=JKS_BuildIDNew,jobName=jobName,defaultDB=defaultDB)
        db_print(cmd)
        tmpRes1=ssh2(linuxIP,linuxUser,linuxPasswd,cmd,'check',int(linuxPort),True,20,True)
        print tmpRes1
        
    except Exception as inst:
        db_print("image flash fail with exception: %s" %inst)
        result = False
        tmpRes1=''   
    res = re.search(r'Image Flash Result:({.*})',tmpRes1)
    if res:
        resDict = json.loads(res.group(1))
    else:
        result = False
        resDict['res']=result
        resDict['error'] = '501'
    return resDict

def _check_build_dr4(ver):
    try:
        jenkins_home = os.environ['JENKINS_HOME']
        fd = open(os.path.join(jenkins_home,'scripts',BUILD_ID_MAP_FILE), 'rb')
        buildIdMap = yaml.load(fd,Loader=yaml.FullLoader)
        fd.close()
        qualType = 'P7'
        dr4Flag = False
        for elem_p7 in buildIdMap:
            if elem_p7['Type'] == qualType:
                dr4Flag = True
                break
        #db_print(str(buildIdMap))
        if dr4Flag:
            dr4Flag = False
            for key in elem_p7:
                #yaml is not sring, need translation
                #db_print('version is %s' %ver)
                #db_print('match:%s' %str(elem_p7[key]))
                if str(elem_p7[key]) == ver.replace('.extra', ''):
                    dr4Flag = True
                    break
    except Exception as inst:
        db_print('check build dr4 fail with exception:%s' %inst)
        dr4Flag = False
    return dr4Flag



def checkDiskSyncForRedundancy(server_ip,oam_ip,connectType='TELNET'):
    global exp,loginCmd
    cmd="\"inic showStates\""
    syncCheck = False
    syncComplete = False
    exp = pexpect.spawn(loginCmd[connectType]+oam_ip)
    exp.timeout = 60
    exp.logfile_read = sys.stdout
    if not login(connectType):
        db_print("########################################")
        db_print("Login OAM failed.Please check your ENV")
        db_print("########################################")
        syncCheck = False
        return syncCheck
    exp.sendline("show equipment slot nt-b")
    res = exp.expect(['\r\nnt-b\s+(\S+)',pexpect.EOF,pexpect.TIMEOUT])
    if res == 0:
        actType = exp.match.groups()[0]
        if not actType == 'empty':
            syncCheck = True
    if syncCheck:
        syncComplete=octopus_check(server_ip,oam_ip,cmd)
    if syncComplete:
        db_print("diskSync finished")
    else:
        db_print('diskSync not finished,timeout')
    return syncComplete


  

    return True

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

def Server_send(cmd, linecmd = 1):
    global telnetTn
    telnetTn.write(cmd)
    db_print(cmd, "send")
    if linecmd == 1:
        telnetTn.write("\r")

def db_print(printStr, debugType="normal", hideCont = ''):
    global logLevel,LEVEL
    if hideCont:
        printStr = printStr.replace(hideCont, '********')
    if debugType=="recv" :
        print  ("<<<" + printStr)
    elif debugType=="send" :
        print  (">>>" + printStr)
    elif logLevel[debugType] <= logLevel[LEVEL]:
        print  ("---" + printStr)

def digi_login(craftIp,Username='root',passwd='dbps'):
    global exp1
    try:
        exp1 = pexpect.spawn('telnet %s' % craftIp)
        exp1.timeout = 60
        exp1.logfile_read = sys.stdout
        exp1.expect("login:")
        exp1.sendline(Username)
        exp1.expect('password:')
        exp1.sendline(passwd)
        i = exp1.expect(["#>",'incorrect','Connection refused',pexpect.EOF])
        if i == 0:
            db_print("DIGI logged in succesfully")
            return True
        else:
            db_print("DIGI Failed to login")
            return False
    except Exception as inst:
        db_print('Failed to access DIGI:%s' %inst)
        return False

def login(connectType):
    if connectType == 'SSH':
        out=ssh_login()
    else:
        out=telnet_login()
    return out

def telnet_login(Username='isadmin',passwd='isamcli!',Password2="      " ,PasswordDefault="i$@mad-"):
    global exp
    try:
        #db_print('args are:%s:%s:%s:%s' %(Username,passwd,Password2,PasswordDefault))
        exp.expect("login:")
        exp.sendline(Username)
        exp.expect('password:')
        exp.sendline(passwd)
        try:
            if exp.expect(["#","incorrect"],timeout=10):
                raise Exception("login failed")
        except:
            db_print('login with default password...')
            exp.sendline(Username)
            exp.expect('password:')
            exp.sendline(PasswordDefault)
            try:
                if exp.expect(["new password","incorrect"]) != 0:
                    raise Exception("login failed")
                exp.sendline(passwd)
                exp.expect("re-enter")
                db_print('repeat entering new password!')
                exp.sendline(passwd)
                exp.expect(["#","$"])
            except:
                db_print('login with password2...')
                exp.sendline(Username)
                exp.expect('password:')
                exp.sendline(Password2)
                if exp.expect(["#","Connection closed"]) != 0:
                    return False
        db_print('login successfully:TELNET')
        return True
    except:
        return False

def ssh_login(Username='isadmin',passwd='isamcli!',Password2="      " ,PasswordDefault="i$@mad-"):
    global exp
    try:
        ssh_flag=False
        i = exp.expect(['password:', r'\(yes\/no\)',r'Connection refused',pexpect.EOF])
        if i == 0:
                exp.sendline(passwd)
        elif i == 1:
                exp.sendline("yes")
                ret1 = exp.expect(["password:",pexpect.EOF])
                if ret1 == 0:
                        exp.sendline(passwd)
                else:
                        pass
        elif i == 2:
                print "Device is not reachable"
        else:
                print "Timeout : Error in SSH connect"
        var= exp.expect(['#',r'Permission denied',pexpect.EOF])
        if var == 0:
            db_print('login successfully:SSH')
            ssh_flag=True
        elif var == 1:
            exp.sendline(PasswordDefault)
            exp.expect("new password:")
            exp.sendline(passwd)
            exp.expect("re-enter  password:")
            exp.sendline(passwd)
            exp.expect(["#",pexpect.TIMEOUT])
            db_print('login successfully')
            ssh_flag=True                   
        else:
            db_print('Login failure')
        return ssh_flag                
    except Exception as error:
        print error
        return False


def sendCliCmd(cmd):
  retBuf = send_telCmd(cmd)
  db_print(retBuf, "recv")
  return retBuf

def _adjust_link_speed(oam_ip,product,connectType='TELNET'):
    global exp,loginCmd
    if product in ['SDFX','SDOLT','NCDPU']:
        return True
    systemup = True
    exp = pexpect.spawn(loginCmd[connectType]+oam_ip)
    exp.timeout = 60
    exp.logfile_read = sys.stdout
    if not login(connectType):
        db_print("########################################")
        db_print("Login OAM failed.Please check your ENV")
        db_print("########################################")
        systemup = False
    exp.sendline("show equipment slot")
    index4 = exp.expect(['fant-','(ag|na)nt-','rant-','srnt-(\w)',pexpect.TIMEOUT])
    if index4 == 0:
        db_print("FX platform")
        db_print("No need to adjust link speed")
    elif index4 == 1:
        db_print("FD platform")
        exp.sendline("info configure system max-lt-link-speed detail")
        index5 = exp.expect(['no link-speed','twodotfive-gb','ten-gb','twenty-gb','forty-gb',pexpect.TIMEOUT])
        if index5 < 2:
            db_print('FD platform max linkspeed is too low,change speed to 10G and reboot...')
            exp.sendline("configure system max-lt-link-speed link-speed ten-gb")
            time.sleep(3)
            exp.sendline("admin equipment reboot-isam without-self-test")
            exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
            time.sleep(30)
            exp.close()
            del exp
            systemup = False
            time.sleep(120)
            for trytimes in range (0,60):
                if not pingIp(oam_ip):
                    db_print('%s is not reachable, waiting longer...' % oam_ip)
                    time.sleep(30)
                else:
                    systemup = True
                    break
            if systemup == False:
                db_print("30mins passed and OAM is not reachable after config max link speed")
                sys.exit(1)
            time.sleep(150)
            systemup = False
            for trytimes in range (0,60):
                exp = pexpect.spawn(loginCmd[connectType]+oam_ip)
                exp.timeout = 60
                exp.logfile_read = sys.stdout
                if not login(connectType):
                    db_print("Login OAM failed.skip testing")
                    db_print("wait for 30 seconds and retry")
                    time.sleep(30)
                    exp.close()
                else:
                    systemup = True
                    break
            if systemup:
                db_print("link speed adjust successfully with warm reboot!")
            exp.close()
            del exp
    else:
        exp.close()
        del exp
    return systemup

def _backup_db_before_activation(build,shelfIp,dbBackup,dbServer,product,connectType='TELNET'):
    global exp,TFTP_SERVER_IP,loginCmd
    if product in ['SDFX','SDOLT','NCDPU']:
        return
    exp = pexpect.spawn(loginCmd[connectType]+shelfIp)
    exp.timeout = 60
    exp.logfile_read = sys.stdout
    if not login(connectType):
        db_print("########################################")
        db_print("Login OAM failed.Please check your ENV")
        db_print("########################################")
    db_print('get oswp index')
    if dbBackup == 'true':
        tag = time.strftime("%Y%m%d",time.localtime())
        db = shelfIp + '_' + build + '_' + tag
        if dbServer != '':
            exp.sendline("admin software-mngt database upload actual-active:%s:dm_%s.tar" % (dbServer,db))
        else:
            exp.sendline("admin software-mngt database upload actual-active:%s:dm_%s.tar" %(db,TFTP_SERVER_IP))
        time.sleep(180)
        db_print("Actual database backup as dm_%s.tar" %db)
    exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
    exp.close()
    del exp

def _get_oswp_index(build,shelfIp,product,connectType='TELNET',password='isamcli!'):
    global exp,loginCmd
    if product in ['SDFX','SDOLT','NCDPU']:
        return ''
    db_print('args are:%s:%s:%s' %(build,shelfIp,password))
    #b = build.split('.')
    #i1 = b[0]
    #oswp_version = b[0]
    #i1 = i1[0:2]
    #i2 = b[1]

    (oswp_version,i2) = build.split('.')
    i1 = oswp_version[0:2]
    if re.search('p',i2):
        i2=i2.split('p')[0] 
    oswpIndex = 'L6GPAA' + i1 + '.' + i2
    oswpIndex1 = 'l6gpaa' + i1 + '.' + i2
    oswpIndex2 = 'L6GPAA' + i1 + '.' + i2
    oswpIndex3 = 'L6GPAB' + i1 + '.' + i2
    oswpIndex4 = 'L6GPAC' + i1 + '.' + i2
    oswpIndex5 = 'L6GPAE' + i1 + '.' + i2
    oswpIndex6 = 'L6GPAH' + i1 + '.' + i2
    oswpIndex7 = 'L6GPAD' + i1 + '.' + i2
    oswpIndex8 = 'L6GPAI' + i1 + '.' + i2

    exp = pexpect.spawn(loginCmd[connectType]+shelfIp)
    exp.timeout = 60
    exp.logfile_read = sys.stdout
    if not login(connectType):
        db_print("########################################")
        db_print("Login OAM failed.Please check your ENV")
        db_print("########################################")
    db_print('get oswp index')
    exp.sendline("show equipment slot")
    index4 = exp.expect(['(cf|fa)nt-','nant-','rant-a','srnt-(\w)','(ag|nr)nt-','rant-b','rant-c','drnt-c','nrnt-i','sfhm-e',pexpect.TIMEOUT])
    if index4 == 0:
        oswpIndex = oswpIndex3
        db_print("FX platform")
    elif index4 == 1:
        oswpIndex = oswpIndex2
        db_print("FD platform")
    elif index4 == 2:
        oswpIndex = oswpIndex4
        db_print("RANT-A platform")
    elif index4 == 3 or index4 == 7 or index4 == 8 or index4 == 9:
        oswpIndex = oswpIndex5
        db_print("7367 platform")
    elif index4 == 4:
        oswpIndex = oswpIndex2
        db_print("AGNTA/NRNTA/NANTA/D/E platform")
    elif index4 == 5:
        oswpIndex = oswpIndex7
        db_print("RANT-B platform")
    elif index4 == 6:
        oswpIndex = oswpIndex8
        db_print("RANT-C platform")
    if oswp_version < '5401':
        db_print("Build is older than 5401.using l6gpaa index")
        oswpIndex = oswpIndex1
    if product == 'SDFX_AH' or product == 'SDFX-AH':
        oswpIndex = oswpIndex6

    exp.sendline("exit all")
    time.sleep(3)
    exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
    #time.sleep(30)
    exp.close()
    del exp
    return oswpIndex

  
def _get_oswp_info(shelfIp,product,connectType='TELNET',password='isamcli!'):
    global exp,loginCmd
    if product in ['SDFX','SDOLT','NCDPU']:
        return []
    db_print('args are:%s:%s' %(shelfIp,password))
    n = 0
    exp = pexpect.spawn(loginCmd[connectType]+shelfIp)
    exp.timeout = 60
    exp.logfile_read = sys.stdout
    if not login(connectType):
        db_print("########################################")
        db_print("Login OAM failed.Please check your ENV")
        db_print("########################################")
    oswp_info = []
    
    num_try = 0

    tmp1 = ''
    tmp2 = ''
    db_print('get oswp info')
    while num_try < 10:
        exp.sendline("show software-mngt oswp")
        time.sleep(3)
        oswp = "1"
        try:
            oswp_match = exp.expect(['1\s{5}(.*?)\r\n2\s{5}(.*?)\r\n',pexpect.EOF])

            if oswp_match == 0:
                tmpList = exp.match.groups()
                tmp1 = re.split('[\s|\b]+',tmpList[0])
                tmp2 = re.split('[\s|\b]+',tmpList[1])

                active_index = '1'
                active_oswp = ''
                active_status = 'enabled'
                active_state = ''
                stdby_index = '2'
                stdby_oswp = ''
                stdby_status = 'enabled'
                stdby_state = ''
                #if not (tmp1[2] == 'active' or tmp2[2] == 'active'):
                #    db_print("oswp status not stable yet:%s:%s" %(tmpList[0],tmpList[1]))
                #    time.sleep(10)
                #    num_try = num_try + 1
                #    continue
                #check act-act-nt
                if tmp1[2] == 'act-act-nt' or tmp2[2] == 'act-act-nt':
                    db_print("oswp status not stable yet:%s:%s" %(tmpList[0],tmpList[1]))
                    time.sleep(60)
                    num_try = num_try + 1
                    continue
                if tmp1[2] == 'active':
                    active_oswp = tmp1[0]
                    active_status = tmp1[1]
                    active_state = tmp1[2]
                    stdby_oswp = stdby_oswp if tmp2[0] == 'NO_OSWP' else tmp2[0]
                    stdby_status = tmp2[1]
                    stdby_state = tmp2[2]
                else :
                    active_index = '2'
                    active_oswp = tmp2[0]
                    active_status = tmp2[1]
                    active_state = tmp2[2]
                    stdby_index = '1'
                    stdby_oswp = stdby_oswp if tmp1[0] == 'NO_OSWP' else tmp1[0]
                    stdby_status = tmp1[1]
                    stdby_state = tmp1[2]

                
                oswp_entry={}                 
                oswp_entry['index'] = active_index
                oswp_entry['oswpIndex'] = active_oswp
                oswp_entry['status'] = active_status
                oswp_entry['state'] = active_state
                oswp_info.append(oswp_entry)
                oswp_entry={}
                oswp_entry['index'] = stdby_index
                oswp_entry['oswpIndex'] = stdby_oswp
                oswp_entry['status'] = stdby_status
                oswp_entry['state'] = stdby_state
                oswp_info.append(oswp_entry)
            break
        except Exception as inst:
            db_print("Unable to find a match for oswp version - Using OSWP 1:%s" %inst)
            #if timeout, then return
            return oswp_info
    exp.sendline("exit all")
    time.sleep(3)
    exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
    #time.sleep(30)
    exp.close()
    del exp
    if not oswp_info :
        try:
            active_index = '1'
            active_oswp = ''
            active_status = 'enabled'
            active_state = ''
            stdby_index = '2'
            stdby_oswp = ''
            stdby_status = 'enabled'
            stdby_state = ''
            #if tmp1[2] == 'act-act-nt':
            #    active_oswp = tmp1[0]
            #    active_status = tmp1[1]
            #    stdby_oswp = stdby_oswp if tmp2[0] == 'NO_OSWP' else tmp2[0]
            #    stdby_status = tmp2[1]
            #elif tmp2[2] == 'act-act-nt' :
            #    active_index = '2'
            #    active_oswp = tmp2[0]
            #    active_status = tmp2[1]
            #    stdby_index = '1'
            #    stdby_oswp = stdby_oswp if tmp1[0] == 'NO_OSWP' else tmp1[0]
            #    stdby_status = tmp1[1]
            if tmp1[2] == 'active':
                active_oswp = tmp1[0]
                active_status = tmp1[1]
                active_state = tmp1[2]
                stdby_oswp = stdby_oswp if tmp2[0] == 'NO_OSWP' else tmp2[0]
                stdby_status = tmp2[1]
                stdby_state = tmp2[2]
            else:
                active_index = '2'
                active_oswp = tmp2[0]
                active_status = tmp2[1]
                active_state = tmp2[2]
                stdby_index = '1'
                stdby_oswp = stdby_oswp if tmp1[0] == 'NO_OSWP' else tmp1[0]
                stdby_status = tmp1[1]
                stdby_state = tmp1[2]   
            oswp_entry={}                 
            oswp_entry['index'] = active_index
            oswp_entry['oswpIndex'] = active_oswp
            oswp_entry['status'] = active_status
            oswp_entry['state'] = active_state
            oswp_info.append(oswp_entry)
            oswp_entry={}
            oswp_entry['index'] = stdby_index
            oswp_entry['oswpIndex'] = stdby_oswp
            oswp_entry['status'] = stdby_status
            oswp_entry['state'] = stdby_state
            oswp_info.append(oswp_entry)    
        except Exception as inst:
            pass    
    return oswp_info

def clearOSWP(shelfIp,product,connectType='TELNET',password='isamcli!'):
    global exp,loginCmd
    if product in ['SDFX','SDOLT','NCDPU']:
        db_print("this version skip")
        return [True,0]
    db_print('args are:%s:%s' %(shelfIp,password))
    n = 0
    exp = pexpect.spawn(loginCmd[connectType]+shelfIp)
    exp.timeout = 60
    exp.logfile_read = sys.stdout
    if not login(connectType):
        db_print("########################################")
        db_print("Login OAM failed.Please check your ENV")
        db_print("########################################")

    exp.sendline("show software-mngt oswp")
    time.sleep(3)
    oswp = "1"
    try:
        #oswp_match = exp.expect([re.compile("1.* active "), re.compile("2.* active ")])
        #  oswp_match = cli.expect({re.compile(?n)([1-2]) .* +enabled active}
        oswp_match = exp.expect(['1\s{5}(.*?)\r\n2\s{5}(.*?)\r\n',pexpect.EOF])
        #print("oswp_match is  %s type:%s" % (oswp_match,type(oswp_match)))
        #if oswp_match == 0 or oswp_match == 1:
        #    oswp = str(int(oswp_match)+1)
    
        #    if oswp == "1":
        #        stdby = "2"
        #    else:
        #        stdby = "1"
        if oswp_match == 0:
            tmpList = exp.match.groups()
            tmp1 = re.split('[\s|\b]+',tmpList[0])
            tmp2 = re.split('[\s|\b]+',tmpList[1])
            cmd1 = ''
            cmd2 = ''
            if tmp1[2] == 'active':
                if tmp2[1] == 'empty':
                    db_print("oswp 1 is active and oswp 2 is empty")
                else:
                    cmd1 = 'admin software-mngt oswp 1 commit'
                    cmd2 = 'admin software-mngt oswp 2 abort-download'

            if tmp2[2] == 'active':
                if tmp1[1] == 'empty':
                    db_print("oswp 2 is active and oswp 1 is empty")
                else:
                    cmd1 = 'admin software-mngt oswp 2 commit' 
                    cmd2 = 'admin software-mngt oswp 1 abort-download'
            if cmd1: 
                while True:
                    exp.sendline(cmd1)     
                    try:
                        ret = exp.expect(["SWDB MGT error 25","Error : resource is currently held by one manager"], timeout=5)                
                    except:
                        print("commit cli execute successfully")
                        break
                    time.sleep(15)
                exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
            if cmd2:                
                exp.sendline(cmd2)   
                time.sleep(5)   
                exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])             
    except Exception as inst:
        db_print("Unable to find a match for oswp version :%s" %inst)

    exp.sendline("exit all")
    time.sleep(3)
    exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
    #time.sleep(30)
    exp.close()
    del exp



def processCommonOptions(runType,batchCommand,release,coverage,testRun,build,extraTar=''):
    #remove APME: or ROBOT first
    batchCommand = batchCommand.strip(" ")
    batchCommand = re.sub('^\S+?:','',batchCommand)
    if runType == 'ATX':
        if release :
            batchCommand = re.sub(r'-release[\s|\b]+?[\d|\.]{3,6}','-release ' + release,batchCommand)
            if not re.search('-release',batchCommand):
                batchCommand += ' -release ' + release
        if testRun == 'true' :
            batchCommand = batchCommand + ' -testrun'
        else :
            batchCommand = batchCommand + ' -updateid %s' %build
        if coverage :
            batchCommand = re.sub(r'-coverage[\s|\b]+?[\w]{5,6}','-coverage ' + coverage,batchCommand)
            if not re.search('-coverage[\s|\b]+?',batchCommand):
                batchCommand += ' -coverage ' + coverage
        if re.search('-repoupdate',batchCommand):
            batchCommand = re.sub('-repoupdate[\s|\b]+?[\S]+','',batchCommand)
        batchCommand = batchCommand + ' -repoupdate NO'
        batchCommand = batchCommand + ' -noload'
    elif runType == 'LTB':
        batchCommand = batchCommand.rstrip(' ')
        if release :
            batchCommand = re.sub(r'-R[\s|\b]+?[\d|\.]{3,6}','-R ' + release,batchCommand)
            if not re.search('-R[\s|\b]+?',batchCommand):
                batchCommand += ' -R ' + release
        if coverage.lower() in ['smoke','daily','weekly'] :
            batchCommand = re.sub(r'-T[\s|\b]+?[\w]{5,6}','-T ' + coverage,batchCommand)
            if not re.search('-T[\s|\b]+?',batchCommand):
                batchCommand += ' -T ' + coverage
        #for areaci phase1,do not override -T
        #else:
        #    batchCommand = re.sub(r'-T[\s|\b]+?[\w]{5,6}','',batchCommand)
        if not testRun == 'true':
            batchCommand = batchCommand + ' -b ' + build + ' -u ' + "smartlab"
        #if extraTar and not re.search('--framework[\s\t]+ROBOT',batchCommand):
        if extraTar:
            batchCommand = batchCommand + ' -K ' + extraTar
        #for LTB, -e MERC/MERC_HOST must be the last one
        #res = re.search('(.+?)([\s|\t]+-e[\s|\t]+[\w]+)([\s|\t]+.*)',batchCommand)
        #if res:
        #    try:
        #        batchCommand = res.group(1) + res.group(3) + res.group(2)
        #    except Exception as inst:
        #        pass
        
    return batchCommand

def _map_jenkins_var_to_robot_options(runType,suiteRerun,robotCaseList,caseMode,robotOptions):
    robotVarList = []
    #actually only supported and tested for pybot
    if runType == 'PYBOT_LAUNCHER':
        if robotOptions :
            varList = robotOptions.split(',')
            for item in varList:
                tmpList1 = item.split('-',1)
                #if tmpList1[0] in ['dryrun'] :
                #    if tmpList1[1] == 'enable':
                #        itemArg = '--' + tmpList1[0]
                #else :
                #    itemArg = '--' + tmpList1[0] + ' ' + tmpList1[1]
                if tmpList1[0] in ['dryrun'] :
                    itemArg = '--' + tmpList1[0] + ' = ' + tmpList1[1]
                else:
                    itemArg = '--' + tmpList1[0] + ' = ' + tmpList1[1]    
                robotVarList.append(itemArg)
        if suiteRerun == 'true':
            robotVarList.append('--rerunfailed = enable')
        if robotCaseList:
            #prerunOption = _generate_prerun_option(caseFile)
            if caseMode == 'INC':
                for caseFile in robotCaseList.split(','):
                    robotVarList.append('--argumentfile = ' + caseFile)
            else:
                skipCaseList = robotCaseList.replace(',',':')
                robotVarList.append('--prerunmodifier = ' + '/repo/atxuser/robot/LIBS/PRE_RUN_MODIFIER/exclude_tests.py:' + skipCaseList)
    elif runType == 'LTB':
        if robotOptions :
            varList = robotOptions.split(',')
            for item in varList:
                robotVarList.append(item)
        if suiteRerun == 'true':
            robotVarList.append('rerunfailed-enable')
        if robotCaseList:
            if caseMode == 'INC':
                for caseFile in robotCaseList.split(','):
                    robotVarList.append('argumentfile-' + caseFile)
            else:
                skipCaseList = robotCaseList.replace(',',':')
                robotVarList.append('prerunmodifier-' + '/repo/atxuser/robot/LIBS/PRE_RUN_MODIFIER/exclude_tests.py:' + skipCaseList)
    return robotVarList

def processBatchCommandFinal(batchCommand,**args):
    release = args.setdefault("release","")
    domain = args.setdefault("domain","")
    suiteRerun = args.setdefault("suiteRerun",'')
    loadInfo = args.setdefault("loadInfo","")
    testRun = args.setdefault("testRun",'')
    build = args.setdefault("build","")
    domainSplit = args.setdefault("domainSplit",'')
    coverage = args.setdefault("coverage",'')
    robotCaseList = args.setdefault("robotCaseList",'')
    robotOptions = args.setdefault("robotOptions",'')
    loadinfo = args.setdefault("loadinfo",'')
    updateRepo = args.setdefault('updateRepo','')
    extraTar = args.setdefault('extraTar','')
    hostFlag = args.setdefault('hostFlag',False)
    oamIP = args.setdefault('oamIP','')
    update_build = args.setdefault("update_build","")
    domainMode = args.setdefault("domainMode","INC")
    caseMode = args.setdefault("caseMode","INC")
    STCServer = args.setdefault("STCServer","")
    stcVersion = args.setdefault("stcVersion","")   
    avBuild = args.setdefault("avBuild","")
    pctaIPaddr = args.setdefault("pctaIPaddr","")
    db_print('pcta:%s,stc:%s,version:%s' %(pctaIPaddr,STCServer,stcVersion))
    product = args.setdefault("product","")  
    if batchCommand.find('/ATX/bin/atx') != -1 :
        runType = 'ATX' 
    elif batchCommand.find('pybot_launcher') != -1 :
        runType = 'PYBOT_LAUNCHER'
    elif batchCommand.find('pybot') != -1 :
        runType = 'PYBOT'
    else:
        runType = 'LTB'

    if product == 'NBN-4F' and loadinfo == 'load':
        batchCommand = re.sub(r'-V[\s]NBN_4F:[\S]*?([^/]+\.csv)',r'-V NBN_4F:/tmp/\1',batchCommand)
        db_print("for NBN-4F,replace original csv to be csv under /tmp")
        db_print(batchCommand)
    #domainMode = 'INC'
    #caseMode = 'INC'
    commandList = []
    commandDomainList = []
    if update_build:
        build=update_build
    batchCommandList=batchCommand.split(';')
    batchDomainList = domain.split(';')
    tmpBatchDomainList = []
    if len(batchDomainList) == 0:
        for i in range(1,len(batchCommandList)):
            batchDomainList.append('')
    else:
        #there is batchDomain separated with ;,means special keyword dictionary default_domain
        keyMatch = False
        for i in range(0,len(batchDomainList)):
            batchDomain = batchDomainList[i]
            res = re.search('(^\S+?):(.*)',batchDomain)
            if res:
                keyMatch = True
                break
        if not keyMatch and len(batchDomainList) > 1:
            db_print("wrong domain mapping to batch command,exit")
            return []
        for i in range(0,len(batchCommandList)):
            batchCommand = batchCommandList[i]
            if keyMatch:
                res = re.search('(^\S+?):(.*)',batchCommand)            
                batchKey = ""
                batchDomain = ''
                if res:
                    batchCommand = res.group(2)
                    batchKey = res.group(1)
                    res1 = re.search(r'%s:([^;]+)' %batchKey,domain) 
                    if res1:
                        batchDomain = res1.group(1)
            else:
                batchDomain = batchDomainList[0]
            tmpBatchDomainList.append(batchDomain)
    batchDomainList = tmpBatchDomainList

    if runType == 'ATX':
        for i in range(0,len(batchCommandList)):
            batchCommandList[i] = processCommonOptions(runType,batchCommandList[i],release,coverage,testRun,build)
        #if domain is empty,return command list directly
        if not domain :
            if updateRepo == 'true':
                batchCommandList[0] = batchCommandList[0].replace(' -repoupdate NO',' -repoupdate YES')
            if loadinfo and loadinfo == 'load':
                batchCommandList[0] = batchCommandList[0].replace('-noload','-load SD_' + build + '.tar')
            commandList = batchCommandList
            return (commandList,commandDomainList)
        #if domain is not empty and command list is more than 2, return directly
        if len(batchCommandList) > 2:
            commandList = batchCommandList
            return (commandList,commandDomainList)


        for (batchCommand,domain) in zip(batchCommandList,batchDomainList):
            #observing atx script,only with two branches, either robot only or apme only
            domainList = domain.split(',')
            robotVarList = []
            domainRobotList = []
            domainOtherList = []
            if re.search(r'[\s|\b]+-framework[\s|\b]+?ROBOT',batchCommand) :
                robotRun = True
                apmeRun = False
            else:
                robotRun = False
                apmeRun = True
            if not domainList:
                domainCommand = _getdomainCommand(batchCommand,runType,[],[],[])
                commandList.append(domainCommand)
            elif domainSplit == 'true' :
                for item in domainList:
                    splitdomainRobotList=[]
                    splitdomainOtherList=[]
                    if robotRun :
                        splitdomainRobotList.append(item)
                    else:
                        splitdomainOtherList.append(item)
                    domainCommand = _getdomainCommand(batchCommand,runType,splitdomainRobotList,splitdomainOtherList,robotVarList)
                    commandList.append(domainCommand)
                    commandDomainList.append(item)
            else:
                if robotRun:
                    domainRobotList = domainList
                else:
                    domainOtherList = domainList
                domainCommand = _getdomainCommand(batchCommandList[0],runType,domainRobotList,domainOtherList,robotVarList)
                commandList.append(domainCommand)
        if updateRepo == 'true':
            commandList[0] = commandList[0].replace(' -repoupdate NO',' -repoupdate YES')
        if loadinfo and loadinfo == 'load':
            commandList[0] = commandList[0].replace('-noload','-load SD_' + build + '.tar')
    elif runType == 'PYBOT_LAUNCHER' or runType == 'PYBOT':
        robotVarList = _map_jenkins_var_to_robot_options(runType,suiteRerun,robotCaseList,caseMode,robotOptions)
        domainRobotList = []
        if runType == 'PYBOT_LAUNCHER':
            robotVarList.append('COVERAGE = ' + coverage)
            robotVarList.append('RELEASE = ' + release)
            robotVarList.append('BUILD = ' + build)
            robotVarList.append('IS_HOST = ' + str(hostFlag))

        if hostFlag:
           batchCommand = batchCommand + ' --dutIP ' + oamIP
            
        if not domain:
            domainCommand = _getdomainCommand(batchCommand,runType,[],[],robotVarList)
            commandList.append(domainCommand)
            return (commandList,commandDomainList)
        domainList = domain.split(',')
        if not domainMode == 'INC':
            for item in domainList:
                if runType == 'PYBOT_LAUNCHER':
                    robotVarList.append('--exclude = ' + item)
                else:
                    robotVarList.append('--exclude ' + item)
            domainCommand = _getdomainCommand(batchCommand,runType,[],[],robotVarList)
            commandList.append(domainCommand)
            return (commandList,commandDomainList)
        if domainSplit == 'true' :
            for item in domainList:
                if runType == 'PYBOT_LAUNCHER':
                    domainCommand = _getdomainCommand(batchCommand,runType,domainRobotList+['--include = ' + item],[],robotVarList)
                else:
                    domainCommand = _getdomainCommand(batchCommand,runType,domainRobotList+['--include ' + item],[],robotVarList)
                commandList.append(domainCommand)
                commandDomainList.append(item)
        else:
            for item in domainList:
                if runType == 'PYBOT_LAUNCHER':
                    domainRobotList.append('--include = ' + item)
                else:
                    domainRobotList.append('--include ' + item)
            domainCommand = _getdomainCommand(batchCommand,runType,domainRobotList,[],robotVarList)
            commandList.append(domainCommand)
    else:       
        for i in range(0,len(batchCommandList)):
            batchCommandList[i] = processCommonOptions(runType,batchCommandList[i],release,coverage,testRun,build,extraTar)
            #process -G in LTB
            if oamIP and hostFlag:
                batchCommandList[i] = re.sub(r'-G[\s|\b]+?[\S]+','-G ' + oamIP,batchCommandList[i])
            #for -v handling,only with -v, then we have Creating/Updating /tftpboot/atx/atxuser/....
            if not re.search('-v',batchCommandList[i]):
                batchCommandList[i] += ' -v'
            #process -PCTA & -STC in LTB        
            #for IPV6 in PCTA,do not overriden anything                    
            if not re.search(r'-P[\s|\t]PCTA:.+PCTA_IPV6',batchCommandList[i]) and (pctaIPaddr or STCServer):
                res = re.search(r'-P[\s|\t]([\S]+)',batchCommandList[i])
                pDict={}
                if res:
                    pParams= res.group(1)
                    #pDict=dict(map(lambda y:y.split(':',1),pParams.split(',')))
                    for aParam in pParams.split(','):
                        if 'PCTA:' in  aParam or 'STC:' in  aParam:
                            (key,value)=aParam.split(':',1)
                        else:
                            key = 'PCTA'
                            value = aParam

                        pDict[key]=value

                if 'STC' in pDict:
                    pDict['STC'] = 'STC:' + pDict['STC']
                if STCServer:
                    pDict['STC'] = STCServer
            
                if 'PCTA' in pDict:
                    pDict['PCTA'] = 'PCTA:' + pDict['PCTA']
                if pctaIPaddr:
                    if 'PCTA' in pDict:
                        pDict['PCTA'] = re.sub(r'^PCTA:[^\:]+','PCTA:' +pctaIPaddr, pDict['PCTA'])
                    else:
                        pDict['PCTA'] = 'PCTA:' +pctaIPaddr
                if res:
                    batchCommandList[i]=re.sub(r'-P([\s|\t][\S]+)','-P ' + ','.join(pDict.values()),batchCommandList[i])
                else:
                    batchCommandList[i] +=' -P ' +  ','.join(pDict.values())
            #process stc version in LTB
            if stcVersion:
                if not re.search('--STC',batchCommandList[i]):
                    batchCommandList[i] += ' --STC ' + stcVersion
                #db_print('handle -stc:%s' %batchCommandList[i])
        #from Smartlab Service 2.1,remove
        #if len(batchCommandList) >= 2:
            #if there are more than 3 LTB commands, means do not process the LTB command
            #num_robot = 0
            #for batchCommand in batchCommandList:
            #    if re.search(r'[\s|\b]+--framework[\s|\b]+?ROBOT',batchCommand):
            #        num_robot = num_robot + 1 
            #        if num_robot > 1:
            #            print 'for more than 1 robot LTB commands,do not do domain split'
            #            domainSplit = 'false'
            #            break
            #print 'for more than 1 robot LTB commands,do not do domain split'
            #domainSplit = 'false'
        avRobotOptions = ''
        if avBuild and type(avBuild) == dict:
            updatePlugin = avBuild.get('updatePlugin',False)
            if updatePlugin:
                avRobotOptions = 'variable-UPDATE_PLUGIN:' + str(updatePlugin)
            updateAV = avBuild.get('updateAV',False)
            if updateAV:
                if avRobotOptions:
                    avRobotOptions += ',variable-UPDATE_AV:' + str(updateAV)
                else:
                    avRobotOptions = 'variable-UPDATE_AV:' + str(updateAV)
            if updateAV and avBuild.get('updateAV',''):
                avVersion=avBuild['avVersion']
                avRobotOptions += ',variable-AV_VERSION:' + str(avVersion)
        for (batchCommand,domain) in zip(batchCommandList,batchDomainList):
            domainRobotList=[]
            domainOtherList=[]
            domainList=[]

            domainList = domain.split(',') 
            apmeRun = False if re.search(r'[\s|\b]+-a',batchCommand) else True
            robotRun = True if re.search(r'[\s|\b]+--framework[\s|\b]+?ROBOT',batchCommand) else False
            print 'apmeRun is %s' %apmeRun
            print 'robotRun is %s' %robotRun
            if robotRun :
                #robot only or robot/apme mixed run(not supported now)
                domainRobotList = copy.copy(domainList)
            elif apmeRun:
                #apme only
                domainOtherList = copy.copy(domainList)

            robotVarList = []
            #if robot run robotVarlist will be handled else empty
            
            if robotRun:
                if avRobotOptions :
                    robotOptions = robotOptions + ',' + avRobotOptions if robotOptions else avRobotOptions
                robotVarList = _map_jenkins_var_to_robot_options(runType,suiteRerun,robotCaseList,caseMode,robotOptions)
                
            if not domainList:
                domainCommand = _getdomainCommand(batchCommand,runType,domainRobotList,domainOtherList,robotVarList)
                commandList.append(domainCommand)
                continue
            if domainList and not domainMode == 'INC':
                for item in domainList:
                    if item:
                        robotVarList.append('exclude-' + item)
                domainCommand = _getdomainCommand(batchCommand,runType,[],domainOtherList,robotVarList)
                commandList.append(domainCommand)
                continue
            if domainSplit == 'true' or not robotRun:
                for item in domainList:
                    splitdomainRobotList=[]
                    splitdomainOtherList=[]
                    if item:
                        if robotRun :
                            splitdomainRobotList.append(item)
                        else:
                            splitdomainOtherList.append(item)
                    domainCommand = _getdomainCommand(batchCommand,runType,splitdomainRobotList,splitdomainOtherList,robotVarList)
                    commandList.append(domainCommand)  
                    commandDomainList.append(item)  
            else:
                domainCommand = _getdomainCommand(batchCommand,runType,domainRobotList,domainOtherList,robotVarList)
                commandList.append(domainCommand)
    return (commandList,commandDomainList)



def _removeDomain(batchCommand,domain_type):
    if domain_type == 'ROBOT':
        batchCommand = re.sub('[\s]+--framework([\s]+[\S]+)?','',batchCommand)
        batchCommand = re.sub('[\s]+-a','',batchCommand)
    else:
        batchCommand = re.sub('[\s]+--framework([\s]+[\S]+)?','',batchCommand)
        batchCommand += ' --framework ROBOT'
        if not re.search('[\s]+-a',batchCommand):
            batchCommand += ' -a'
    res = re.search(r'(-d[\s|\b]+?([\S]+))',batchCommand)

    if res:
        fixDomainString = res.group(1)
        fixDomain = res.group(2)
        #if there are domains already, remove them first
        batchCommand = batchCommand.replace(fixDomainString,'')
        fixDomainList = fixDomain.split('ROBOT:')
        if domain_type == 'ROBOT':
            #remove +
            if fixDomainList and fixDomainList[0]:
                #domainOtherList.append(fixDomainList[0][:-1])
                batchCommand = batchCommand + ' -d %s' % fixDomainList[0].strip('+')
        else:
            fixDomainList.remove(fixDomainList[0])
            #domainOtherList.append(fixDomainList[0])
            if fixDomainList:
                #domainOtherList.append(fixDomainList[0][:-1])
                batchCommand = batchCommand + ' -d ROBOT:%s' % fixDomainList[0]
    return batchCommand

def _getdomainCommand(batchCommand,runType,domainRobotList,domainOtherList,robotVarList):
    batchCommand = batchCommand.strip()
    if not domainRobotList and not domainOtherList and not robotVarList:
        #if no domain in input,run the batchCommand directly
        return batchCommand
    newDomainRobotList = copy.deepcopy(domainRobotList)
    newDomainOtherList = copy.deepcopy(domainOtherList)
    newRobotVarList = copy.deepcopy(robotVarList)
    newDomainRobotList = [i.lower() for i in newDomainRobotList if i != '']
    newDomainOtherList = [i for i in newDomainOtherList if i != '']
    newRobotVarList = [i for i in newRobotVarList if i != '']
    #for idx in range(0,len(newDomainRobotList)):
    #    domainRobotList[idx] = domainRobotList[idx].lower()
    if runType == 'PYBOT':
        res = re.search('[\s|\b]+?([\S]+)$',batchCommand)
        if not res:
            print '\nThis is a bad pybot command without data source in the end'
            return None
        dataSource = res.group(1)
        batchCommand = re.sub(dataSource,'',batchCommand)
        batchCommand = batchCommand + ' '.join(newDomainRobotList + newRobotVarList) + ' ' + dataSource
        return batchCommand
    elif runType == 'PYBOT_LAUNCHER':
        #print batchCommand

        batchCommand = batchCommand + '\n' + '\n'.join(newRobotVarList + newDomainRobotList)
        return batchCommand
    elif runType == 'ATX':
        res = re.search(r'(-domainlist[\s|\b]+?([\S]+))',batchCommand)
        fixDomainOther = ''
        fixDomainRobot = ''

        if res:
            fixDomainString = res.group(1)
            fixDomain = res.group(2)
            #if there are domains already, remove them first
            batchCommand = batchCommand.replace(fixDomainString,'')
            fixDomainList = fixDomain.split('ROBOT:')

            if len(fixDomainList) == 2:
                #remove +
                if fixDomainList[0]:
                    newDomainOtherList.insert(0,fixDomainList[0][:-1])
                newDomainRobotList.insert(0,fixDomainList[1])
            else:
                newDomainOtherList.insert(0,fixDomainList[0])

        if newDomainRobotList:
            #robot only
            batchCommand = batchCommand + ' -domainlist ROBOT:' + ','.join(newDomainRobotList + newRobotVarList)
        else:
            #apme only
            batchCommand = batchCommand + ' -domainlist ' + ','.join(newDomainOtherList)
        return batchCommand
            
    #LTB handling
    res = re.search(r'(-d[\s|\b]+?([\S]+))',batchCommand)
    fixDomainOther = ''
    fixDomainRobot = ''

    if res:
        fixDomainString = res.group(1)
        fixDomain = res.group(2)
        #if there are domains already, remove them first
        batchCommand = batchCommand.replace(fixDomainString,'')
        fixDomainList = fixDomain.split('ROBOT:')

        if len(fixDomainList) == 2:
            #remove +
            if fixDomainList[0]:
                newDomainOtherList.insert(0,fixDomainList[0][:-1])
            robot_tag_list=fixDomainList[1].split(',')
            robot_tag_keep_list = []
            robot_tag_change_list = []
            for robot_tag in robot_tag_list:
                if robot_tag.startswith('include-'):
                    robot_tag_change_list.append(robot_tag)
                else:
                    robot_tag_keep_list.append(robot_tag)
            #fixDomainList[1] = ','.join(robot_tag_keep_list)
            if robot_tag_keep_list:
                newDomainRobotList = [','.join(robot_tag_keep_list)]
            else:
                newDomainRobotList = []
            if robot_tag_change_list:
                if domainRobotList:
                    temp_robot_tag_change_list = copy.deepcopy(robot_tag_change_list)
                    for domainRobot in domainRobotList:
                        domainRobot = 'dom_' + domainRobot.lower()
                        for idInclude in xrange(len(robot_tag_change_list)):
                            tag_list = robot_tag_change_list[idInclude].split('OR')
                            for idx in xrange(len(tag_list)):
                                tag_list[idx] = tag_list[idx] + 'AND' + domainRobot
                            temp_robot_tag_change_list[idInclude] = 'OR'.join(tag_list)
                        newDomainRobotList = newDomainRobotList + copy.deepcopy(temp_robot_tag_change_list)
                else:
                    newDomainRobotList = newDomainRobotList + robot_tag_change_list   
            else:
                for domainRobot in domainRobotList:
                    newDomainRobotList.append(domainRobot.lower())
            #newDomainRobotList.insert(0,fixDomainList[1])
            #db_print('newDomainRobotList:%s' %str(newDomainRobotList))
        else:
            newDomainOtherList.insert(0,fixDomainList[0])

    domainOther = ','.join(newDomainOtherList)
    if newDomainOtherList and newDomainRobotList:
        #mixed robot/apme,not supported now
        newDomainRobotList += newRobotVarList
        domainRobot = ','.join(newDomainRobotList) 
        domainCommand = batchCommand + ' -d %s+ROBOT:%s' %(domainOther,domainRobot)
        #remove all -a option since this is mixed apme and robot
        domainCommand = re.sub('[\s]+-a','',domainCommand)
        if not re.search('--framework',domainCommand):
            domainCommand = domainCommand + ' --framework ROBOT'
    elif newDomainOtherList:
        domainCommand = batchCommand + ' -d %s' %domainOther
        #remove all -a option since this is mixed apme and robot
        domainCommand = re.sub('[\s]+-a','',domainCommand)
    elif newDomainRobotList:
        newDomainRobotList += newRobotVarList
        domainRobot = ','.join(newDomainRobotList)
        domainCommand = batchCommand + ' -d ROBOT:%s' %domainRobot
        if not re.search('--framework',domainCommand):
            domainCommand = domainCommand + ' --framework ROBOT'
    else:
        #robotRun, no domain, but with robot variable
        newDomainRobotList += newRobotVarList
        domainRobot = ','.join(newDomainRobotList)
        domainCommand = batchCommand + ' -d ROBOT:%s' %domainRobot
    return domainCommand

def _getdomain(batchCommand):    
    res = re.search(r'-d[\s|\b]+?([\S]+)',batchCommand)
    if res:
        domainString = res.group(1)
        domainList = re.split('[,|+]',domainString)
        newdomainList = []
        for item in domainList:
            item = item.strip('ROBOT:')
            m = re.search("(\w+)(\-(\S+))?",item)
            if m:
                key=m.group(1)
                if key.lower() not in ["argumentfile","variable","listener","prerunmodifier","test","exclude","suite","debugfile","rerunfailed","dryrun"]:
                    newdomainList.append(key)
        if len(newdomainList) == 1:
            return newdomainList[0]
        else:
            return '' 
    else:
        return ''

def dryrunBatch(commandList, prerunConfig, domainList=[],linuxIP='',userName='atxuser',passwd='alcatel01',domainSplit='',defaultDB = '',dbDict={},linuxPORT='22',traceOnly=False): 
    jobname = os.environ['JOB_NAME']
    jobNum = os.environ['BUILD_NUMBER']
    reportJobInstantStatus(jobname,jobNum,'005')
    if commandList[0].find('/ATX/bin/atx') != -1 :
        runType = 'ATX' 
    elif commandList[0].find('pybot_launcher') != -1 :    
        runType = 'PYBOT_LAUNCHER'
    elif commandList[0].find('pybot') != -1 :
        runType = 'PYBOT'
    else:
        runType = 'LTB'
    #if domain:
    #    domainList = domain.split(',')
    #else:
    #    domainList=[]
    #for dryrun, remove METRICS USER
    #prerunConfig = re.sub('export METRICS_USER=[^;]+','',prerunConfig)
    #prerunConfig = prerunConfig.lstrip(';').rstrip(';').replace(';;',';')
    #prerunConfig = prerunConfig + ';export METRICS_USER=' if prerunConfig else 'export METRICS_USER='
    if len(domainList) >=2 and not len(domainList) == len(commandList) and domainSplit == 'true':
        print 'when domainSplit set true, domainlist number is the same as commandlist or else return'
        return
    dryrunDirList = []
    product = dbDict['product']

    for batchCommand in commandList:
        if runType == 'PYBOT_LAUNCHER':
            working_dir = ''
            batchCommand = _prepare_pybot_launcher(batchCommand,linuxIP, userName,passwd,linuxPORT,working_dir,traceOnly)
            #batchCommand = _prepare_pybot_launcher(batchCommand,linuxIP, userName,passwd,linuxPORT,traceOnly)
        domainCommand = prerunConfig + ';' + batchCommand if prerunConfig else batchCommand
        if traceOnly:
            print domainCommand
            continue
        #domainCommand=domainCommand.split(';')
        try:
            result = ssh2(linuxIP, userName,passwd, domainCommand,'check',port=int(linuxPORT))
        except Exception as inst:
            db_print('ssh exception with %s' %inst)
            result = ''
        if runType == 'ATX':
            #res = re.search('Time stamp = ([\d]{8}-[\d]{6})',result)
            #if res:
            #homeDir = '/tftpboot/atx/atxuser/
            return []
        elif runType == 'LTB' or runType == 'PYBOT_LAUNCHER':
            if result:
                res = re.search('((root|atxuser)\-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[\d]{8})',result)
                if res:
                    dryrunDirList.append(res.group(1))
    return dryrunDirList

def runBatch(commandList, prerunConfig, domainList,linuxIP='',userName='atxuser',passwd='alcatel01',domainSplit='',defaultDB = '',dbDict={},traceOnly=False,linuxPORT='22',storeLog=True):
    global envOverriden
    jobname = os.environ['JOB_NAME']
    jobNum = os.environ['BUILD_NUMBER']
    if domainList and any(domainList):
        reportJobInstantStatus(jobname,jobNum,'061')
    else:
        reportJobInstantStatus(jobname,jobNum,'060')
    result = True
    t0 = time.time()

    if commandList[0].find('/ATX/bin/atx') != -1 :
        runType = 'ATX' 
    elif commandList[0].find('pybot_launcher') != -1 :    
        runType = 'PYBOT_LAUNCHER'
    elif commandList[0].find('pybot') != -1 :
        runType = 'PYBOT'
    else:
        runType = 'LTB'

    build_url = ''
    job_name = ''
    job_num = '1'
    if traceOnly:
        workspace = '/tmp/'
        job_name = 'NFXSE_FANTF_XGSPON_FWLTB_OLD_01'
    else:
        try :
            orig_workspace = os.environ['WORKSPACE']
            #workspace = '/tmp/'
            job_name = os.environ['JOB_NAME'] 
            orig_job_name = job_name
            build_url = os.environ['BUILD_URL']
            job_num = os.environ['BUILD_NUMBER']
            #job_name = re.sub(r'([\(|\)])',r'\\\1',orig_job_name)
            build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)
            workspace = re.sub(r'([\(|\)])',r'\\\1',orig_workspace)
        except Exception as inst :
            db_print("this operation can only run on jenkins server as run python script step:%s" %inst)
            return False
    job_name = re.sub(r'([\(|\)])',r'\\\1',orig_job_name)
    try:
        smart_srv_ip=build_url.split(':')[1].strip('//')
    except Exception as inst:
        smart_srv_ip='135.251.206.143'
    smart_srv_port='80001'
    all_jenkins_summary = workspace + '/' + 'testsummary.log'
    jenkins_summary = workspace + '/' +'tmp_testsummary.log'
    #cmd = "rm %s %s" %(jenkins_summary,all_jenkins_summary)
    if os.path.exists(all_jenkins_summary):
        cmd = "rm %s" % all_jenkins_summary
        result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        db_print("clean testsummary.log before test run\n%s with output:%s" %(cmd,result))
    if os.path.exists(jenkins_summary):
        cmd = "rm %s" % jenkins_summary
        result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        db_print("clean testsummary.log before test run\n%s with output:%s" %(cmd,result))
    #if domain:
    #    domainList = domain.split(',')
    #else:
    #    domainList=[]
    if len(domainList) >=2 and not len(domainList) == len(commandList) and domainSplit == 'true':
        print 'when domainSplit set true, domainlist number is the same as commandlist or else return'
        return

    saveTrace = dbDict.setdefault('saveTrace',False)
    trace_server_list = dbDict.setdefault('trace_server_list',None)
    team = dbDict.setdefault('team','')
    oam_type = dbDict.setdefault('oam_type','')
    redund = dbDict.setdefault('redund',False)
    oam_ip = dbDict.setdefault('oam_ip','')
    oswpIndex = dbDict.setdefault('oswpIndex','')
    craftIp = dbDict.setdefault('craftIp','')
    craftPort = dbDict.setdefault('craftPort','')
    dbBackup = dbDict.setdefault('dbBackup',False)
    dbServer = dbDict.setdefault('dbServer','')
    dbMode  = dbDict.setdefault('dbMode','')
    product = dbDict['product']
    #redund = dbDict.setdefault('oam_type',False)
    connectType = dbDict.setdefault('connectType','')
    SERVER_IP = dbDict.setdefault('SERVER_IP','')
    dutInstanceList = dbDict.setdefault('dutInstanceList','')
    buildInstance = dbDict.setdefault('buildInstance','')
    cmdLocation = dbDict.setdefault('cmdLocation','')
    defaultDB = dbDict.setdefault('defaultDB','')
    redund = dbDict.setdefault('redund','')
    SCRIPT_PATH = dbDict.setdefault('SCRIPT_PATH','')
    failRerun = dbDict.setdefault('failRerun',False)
    build_id = dbDict.setdefault('build','')
    if craftIp :
        initCommands = dbDict.setdefault('initCommands',[])
        extraCommands =  dbDict.setdefault('extraCommands',[])
        #print '----get new initCommands:'
        #print initCommands
        #print extraCommands
    if saveTrace:
        saveTrace = not isPlatformInGICIMAP()
    homeDir = ''
    if not runType == 'ATX':
        homeDir = getHomeDir(linuxIP, userName, passwd, linuxPORT)
        if not envOverriden['HOME'] == '~':
            homeDir = envOverriden['HOME']
        if not homeDir:
            db_print("can not get homedir for linux machine")
            return (False,0)

    for idx,batchCommandInit in enumerate(commandList):
        rerunFlag = False
        while True:
            batchCommand = batchCommandInit
            if runType == 'ATX':
                timeStamp = time.strftime('%m%d%Y-%H:%M:%S',time.localtime())
                batchCommand += " --timestamp %s" %atxTimeStamp
            else:
                working_dir = ''
                timeStamp = ''
                #for qemu host batch,1st domain will use the qemu working directory

                try:
                    cmd = "curl -s %sconsoleText |grep -o -a -E 'qemu is up with working_dir:[[:graph:]]+(root|atxuser)-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[0-9]{8}'|uniq |tail -1" %build_url
                    result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                    tmpList = result.split(':',1)
                    if len(tmpList) == 2:
                        working_dir = tmpList[1].rstrip('\n')
                        tmpList = working_dir.rpartition('\/')
                        timeStamp = tmpList[-1]
                except Exception as inst:
                    db_print('this is not qemu batch')

                if not working_dir:
                    timeStamp=userName + '-' + time.strftime('%b%d%H%M%S',time.localtime())
                    working_dir = homeDir + '/' + timeStamp
                frameworkType = checkFramework(batchCommand)
                if not createWorkDir(linuxIP, userName, passwd, linuxPORT, working_dir,frameworkType):
                    db_print("create home dir fail:skip this batch command")
                    continue
            
            #this logic was prepared previously for pybot launcher ?? not needed now.
            #extra_tar_file = ''

            #try:
            #    cmd = "curl -s %sconsoleText |grep -o -a -E 'LTB extraTar file:[[:graph:]]+'|uniq |tail -1" %build_url
            #    result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            #    tmpList = result.split(':',1)
            #    if len(tmpList) == 2:
            #        extra_tar_file = tmpList[1].rstrip('\n')
            #except Exception as inst:
            #    db_print('no LTB extraTar file')
            result = True
            if runType == 'LTB':
                #batchCommand = re.sub(r'(launchTestBatch[\S]+)',r'\1 -D ' + working_dir + ' ',batchCommand)
                batchCommand += ' -D %s' %working_dir
                #if extra_tar_file:
                #    batchCommand += ' -K %s' %extra_tar_file
                if '-e MERC_HOST' in batchCommand:
                    batchCommand = batchCommand.replace(' -e MERC_HOST','')
                    batchCommand += ' -e MERC_HOST'
            elif runType == 'PYBOT_LAUNCHER':
                batchCommand = _prepare_pybot_launcher(batchCommand,linuxIP, userName,passwd,linuxPORT,working_dir,traceOnly)
                if working_dir:
                    batchCommand += ' --logDirectory %s/ROBOT' %working_dir
                batchCommand += ' --testSummary'

            domainCommand = prerunConfig + ';' + batchCommand if prerunConfig else batchCommand
            if traceOnly:
                print domainCommand
                continue
            #domainCommand=domainCommand.split(';')
            #prepare some parameters for result handling and domain report
            #load only used for ATX
            load = 'ManualLoad'
            if runType == 'ATX':
                res = re.search(r'-system[\s|\b]+?([\S]+)',batchCommand)
                platform = res.group(1)
                res = re.search('-load[\s|\b]+?([\S]+)',batchCommand)
                if res:
                    load = res.group(1).lstrip('SD_').rstrip('.tar')
                else:
                    load = 'ManualLoad'
            else:
                platform = job_name
            if domainList and domainSplit == 'true':
                domain = domainList[idx]
            else:
                domain = ''
            load = load if idx == 0 else 'ManualLoad'
        
        #report status before domain run
        #if domain:
        #    reportStatus('domain',orig_job_name,job_num,'STARTED',timeStamp,domain)
        #else: 
        #    if idx == len(commandList) -1 :
        #        reportStatus('batch',orig_job_name,job_num,'STARTED',timeStamp)
        #    else:
        #        reportStatus('batch',orig_job_name,job_num,'partial_started',timeStamp)

            if saveTrace:
                start_trace_saver(linuxIP,userName,passwd,linuxPORT,trace_server_list,product)
            if envOverriden['PROGRESS_LINK']:
                db_print("overridden progress link:%s" %envOverriden['PROGRESS_LINK'])
            batchStartTime = time.time()
            if rerunFlag:
                db_print('RERUN LTB INDEX:%s:%s' %(idx,timeStamp))
            if product in ["Voice","REMOTE"] and ("-T weekly" in domainCommand or "-T daily"  in domainCommand):
                db_print("daily voice")
                ssh2(linuxIP, userName,passwd, domainCommand,port=int(linuxPORT),pty=False)
            else:
                ssh2(linuxIP, userName,passwd, domainCommand,port=int(linuxPORT))
            db_print('deal with moswa_upgrade upload')
            if idx == 0 and os.path.exists(os.path.join(orig_workspace,'moswa_upgrade.json')):
                db_print("Upload moswa_upgrade.json to batch directory")
                json_file = os.path.join(workspace,'moswa_upgrade.json')
                cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s %s@%s:%s" %(passwd,linuxPORT,json_file,userName,linuxIP,working_dir+'/ROBOT')
                db_print(cmd,'debug')
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                print 'get result:%s' %result
            else:
                db_print('idx=%s'%idx)
                db_print('upgrade.json exist:%s'%os.path.exists(os.path.join(orig_workspace,'moswa_upgrade.json')))
            batchEndTime = time.time()
            res,timeStamp=handleRunResult(build_id,domain,platform,runType,linuxIP,linuxPORT,userName,passwd,team,working_dir,load,storeLog)

            #reportStatusSocket(smart_srv_ip,smart_srv_port,'domain',job_name,domain)
            #reportStatus('domain',job_name,job_num,'COMPLETED',domain)
            if not domain:
                #after the last domain is finished, send message for batch
                #reportStatusSocket(smart_srv_ip,smart_srv_port,'batch',job_name)
                if idx == len(commandList) -1 :
                    data = {'jobName':orig_job_name,'jobNum':job_num,'currentStatus':'COMPLETED','timeStamp':timeStamp}
                    reportStatus('batch',data)
                    #reportStatus('batch',orig_job_name,job_num,'COMPLETED',timeStamp)
                else:
                    data = {'jobName':orig_job_name,'jobNum':job_num,'currentStatus':'partial_completed','timeStamp':timeStamp}
                    #reportStatus('batch',orig_job_name,job_num,'partial_completed',timeStamp)
                    reportStatus('batch',data)
            if defaultDB == 'true' and idx < len(commandList) -1:
                #checkDiskSyncForRedundancy(oam_ip)
                db_print('activate oswp after batch run')
                res = DUT.cleanDBParallel(dutInstanceList,buildInstance=buildInstance,cmdLocation=cmdLocation,mode=dbMode,toolOnly=True,SCRIPT_PATH=SCRIPT_PATH,workspace=workspace,redund=redund,defaultDB=defaultDB)
                if not res['res']:
                    result = False
                    if saveTrace:
                        try:
                            stop_trace_saver(linuxIP,userName,passwd,linuxPORT,trace_server_list)
                            upload_trace_saver(linuxIP,trace_server_list,team)
                        except Exception as inst:
                            db_print("trace saver with exception:%s" %inst)
                    break
                #for activate oswp between different domain ,oam ip will not be lost, do not do initialize dut
                if not product in ['NCDPU','SDFX','SDOLT']:
                    #db_print('backup database before activating oswp after batch run')
                    #if pingIp(oam_ip) and not check_telnet(oam_ip):
                    #    db_print('%s is not reachable. skip this step. Please check the env!' % oam_ip)
                    #    return(True,0)
                    #else:
                    #    initializeDUT(craftIp, craftPort,oam_ip,initCommands,extraCommands,product,oam_type,redund,True)
                    #product = dbDict['product']
                    DUT.configDUT(dutInstanceList,cmdType='banner',action='add',platform=job_name,cmdLocation = cmdLocation)
                    if saveTrace:
                        DUT.configDUT(dutInstanceList,cmdType='command',action='add',command='configure system security ssh access debugkernel ssh',platform=job_name,cmdLocation = cmdLocation)
            if saveTrace:
                try:
                    stop_trace_saver(linuxIP,userName,passwd,linuxPORT,trace_server_list)
                    upload_trace_saver(linuxIP,trace_server_list,team)
                except Exception as inst:
                    db_print("trace saver with exception:%s" %inst)
            if failRerun and (batchEndTime - batchStartTime < RERUN_TIMEOUT) and result and not rerunFlag:
                db_print('LTB will be reran')
                rerunFlag = True
                continue
            break
    try:
        db_print("clean ltb commands generated without XTERM")
        tempLTB = commandList[0]
        res = re.search(r'^(.*?launchTestBatch\.[\d]{8}-[\d]{6})[\s]',tempLTB)
        if res:
            cmd = 'rm -rf %s' %res.group(1)
            ssh2(linuxIP, userName,passwd, cmd,port=int(linuxPORT))
    except Exception as inst:
        db_print("clean ltb fail with exception:%s" %inst)
    t1 = time.time()
    return (result,time.localtime(t1 - t0))

def reportJobInstantStatus(jobName,jobNum,jobStatus,errorCode=None):
    try:
        data = {}
        data['jobName'] = jobName
        data['jobNum'] = jobNum
        data['currentStatus'] = jobStatus
        if errorCode:
            data['errorCode'] = errorCode
            db_print("Failed with error:%s" %ERROR_CODE.get(errorCode,''))
        db_print('report data:%s to %s/api/reportJobStatus' %(data,SMARTLAB_SERVER))
        for i in range(2):
            res = requests.post("%s/api/reportJobStatus" %SMARTLAB_SERVER,json.dumps(data),verify=False)
            resDic=json.loads(res.text)
            db_print('report result:%s' %resDic)
            if resDic['status']=='OK':
                db_print('ReportJobInstantStatus successfully!')
                break
            else:
                db_print('ReportJobInstantStatus fail,reason is %s,try again!'%resDic['reason'])
                time.sleep(30)
    except Exception as inst:
        db_print('report status failure:%s' %inst)

#def reportStatus(report_type,job_name,job_num,status,timestamp=None,domain=None):
def reportStatus(report_type,report_data):
    try:
        data = copy.deepcopy(report_data)
        data['type'] = report_type

        db_print('report data:%s to %s/api/dbOperation' %(data,SMARTLAB_SERVER))
        for i in range(2):
            res = requests.post("%s/api/dbOperation" %SMARTLAB_SERVER,json.dumps(data),verify=False)
            resDic=json.loads(res.text)
            db_print('report result:%s' %resDic)
            if resDic['status']=='OK':
                db_print('reportStatus successfully!')
                break
            else:
                db_print('reportStatus fail,reason is %s,try again!'%resDic['reason'])
                time.sleep(30)
    except Exception as inst:
        db_print('report status failure:%s' %inst)
        
def reportLatestBuild(buildID):
    try:
        data = {}
        jobName = os.environ['JOB_NAME']
        jobNum = os.environ['BUILD_NUMBER']
        data['jobName'] = jobName
        data['jobNum'] = jobNum
        data['buildID'] = buildID

        time.sleep(30)
        db_print('report data:%s to %s/api/latestBuildRequest' %(data,SMARTLAB_SERVER))
        for i in range(5):
            res = requests.post("%s/api/latestBuildRequest" %SMARTLAB_SERVER,json.dumps(data),verify=False)
            resDic=json.loads(res.text)
            db_print('report result:%s' %resDic)
            if resDic['status']=='OK':
                db_print('SmartLab Service change test status and test result build successfully!')
                break
            else:
                db_print('SmartLab Service change test status and test result build fail,reason is %s,try again!'%resDic['result'])
                time.sleep(30)
    except Exception as inst:
        db_print('report status failure:%s' %inst)

def reportStatusSocket(smart_srv_ip,smart_srv_port,report_type,job_name,domain=None):
    try:
        timestamp=time.strftime('%b%d%H%M%S',time.localtime())
        if report_type == 'domain' and domain:
            report_msg = 'JOB:%s:timestamp:%sDOMAIN:%s' %(job_name,domain,timestamp)
        elif report_type == 'batch':
            report_msg = 'JOB:%s:timestamp:%s:BATCH' %(job_name,timestamp)   
        else:  
            return 
        sock =  socket.socket(socket.AF_INET,socket.SOCK_STREAM)  
        sock.connect((smart_srv_ip,smart_srv_port))  
        sock.send(report_msg)
        sock.shutdown(1)
        sock.close()
    except Exception as inst:
        db_print('report status failure:%s' %inst)

def _prepare_pybot_launcher(batchCommand,linuxIP, userName,passwd,linuxPORT,working_dir,traceOnly=False):
    (baseCommand,otherOptions) = batchCommand.split('\n',1)
    res = re.search('( --argumentFile\s([\S]+))',baseCommand)
    if not res:
        db_print('command is with error, exit')
        return None
    baseCommand = re.sub(res.group(1),'',baseCommand)
    oldArgFile = res.group(2)
    newArgFile = 'robot_variable.txt'
    timeStamp=time.strftime('%b%d%H%M%S',time.localtime())
    tmpArgFile = timeStamp + '_robot_variable.txt'
    tmpDir = '/tmp'
    if working_dir:
        newArgFile = working_dir + '/ROBOT/robot_variable.txt'
    else:
        newArgFile = tmpDir + '/' + tmpArgFile
    try : 
        if traceOnly:
            workspace = '/tftpboot/atx/atxuser'
        else:
            workspace = os.environ['WORKSPACE']
            workspace = re.sub(r'([\(|\)])',r'\\\1',workspace)
    except Exception as inst:
        print 'prepare pybot launcher command with exception :%s' %inst
        workspace = '/tmp'
    try:
        tmpArgFile = workspace + '/' + tmpArgFile
       
        cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:%s %s" %(passwd,linuxPORT,userName,linuxIP,oldArgFile,tmpArgFile)
        result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        db_print("\n%s with output:%s" %(cmd,result))
        aFile = open(tmpArgFile,'r')
        aOptions = aFile.readlines()
        aFile.close()

        for item in aOptions:
            if item.find('COVERAGE') == -1 and item.find('BUILD') == -1 and item.find('RELEASE') == -1:
                otherOptions = item + otherOptions
        aFile = open(tmpArgFile,'w+')
        aFile.writelines(otherOptions)
        aFile.writelines("\n")
        aFile.close()
        #cmd = "sshpass -p 'alcatel01' ssh -o StrictHostKeyChecking=no -p%s atxuser@%s 'mkdir -p %s'" %(linuxPORT,linuxIP,logDir)
        #result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        #newArgFile = tmpDir + '/' + newArgFile
        db_print("\n%s with output:%s" %(cmd,result))
        cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s %s@%s:%s" %(passwd,linuxPORT,tmpArgFile,userName,linuxIP,newArgFile)
        result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        db_print("\n%s with output:%s" %(cmd,result))
        os.remove(tmpArgFile)
        baseCommand = baseCommand + ' --argumentFile ' + newArgFile
    except Exception as inst:
        print 'prepare pybot launcher command with exception :%s' %inst
        return None
    return baseCommand

def _generate_prerun_option(caselistfile):
    caselist = ''
    try:
        with open(caselistfile,'r') as f:
            for line in f:
                case = line.split(' ')[-1].strip()
                if case:
                    caselist += ':' + case
            f.close()
            caselist = caselist.lstrip(':')
    except Exception as inst:
        db_print('\n generate prerun option failure with exceptipn:%s' %inst)
        return ''
    return caselist 

def _get_pcta_info_from_atx(linux_ip,user,passwd,batchCommand):
    res = re.search('-system[\s]+([\S]+)',batchCommand)
    if not res:
        return ''
    atxname = res.group(1) 
    try :
        workspace = os.environ['WORKSPACE']
        workspace = re.sub(r'([\(|\)])',r'\\\1',workspace)
    except Exception as inst:
        print 'failure to get workspace'
        workspace = '/tmp'
    lines=[]
    try:
        cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s:/tftpboot/atx/data/%s.data %s" %(passwd,user,linux_ip,atxname,workspace)
        result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        db_print("\n%s with output:%s" %(cmd,result))
        aFile = open(workspace + '/' + atxname + '.data','r')    
        lines = aFile.readlines()
    except Exception as inst:
        print 'failure to get atx datafile with exception:%s' %inst
        return ''
    pctaIp = ''
    for line in lines:
        res1 = re.search('{sLinuxIP[\s\b\t]+(.*)}',line)
        if res1:
            pctaIp = res1.group(1)
            return pctaIp
    return pctaIp

def _get_extra_init_commands(linux_ip,user,passwd, port):     
    global envOverriden  
    try :
        workspace = os.environ['WORKSPACE']
        workspace = re.sub(r'([\(|\)])',r'\\\1',workspace)
    except Exception as inst:
        print 'failure to get workspace'
        workspace = '/tmp'
    lines=[]

    try:
        cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:%s/configs/extra_init_commands %s" %(passwd,port,user,linux_ip,envOverriden['HOME'],workspace)
        result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        db_print(cmd,'debug')
        db_print("with output:%s" %result)
        aFile = open(workspace + '/extra_init_commands','r')
        lines = aFile.readlines()
        for idx in xrange(0,len(lines)):
            lines[idx] = lines[idx].strip('\n')
    except Exception as inst:
        #print "no extra init commands"
        pass
    return lines

def handleRunResult(build_id,domain,platform,runType,linux_ip,port,username,passwd,team,working_dir,load='ManualLoad',uploadLog=True):
    global envOverriden
    try :
        orig_job_name = os.environ['JOB_NAME'] 
        job_name = re.sub(r'([\(|\)])',r'\\\1',orig_job_name)
        job_num = os.environ['BUILD_NUMBER'] 
        orig_workspace = os.environ['WORKSPACE']
        workspace = re.sub(r'([\(|\)])',r'\\\1',orig_workspace)
        build_url = os.environ['BUILD_URL']
        job_url = re.sub('[\d]+\/$','',build_url)
        job_url = re.sub(r'([\(|\)])',r'\\\1',job_url)
        #updated when build id set latest
        #build_id = os.environ['BuildIDNew']
        #jenkins_home = os.environ['JENKINS_HOME']
        linux_ip = os.environ['LinuxIP'].split(':')[0]
        platformType = os.environ['PlatformType']
        ftpServer  = os.environ['TftpServer']
        build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)
        if runType != 'python' or runType != 'tcl':
            jenkins_summary = workspace + '/' + 'tmp_testsummary.log'
            #jenkins_summary = workspace + '/testsummary_' + timeStamp + '.log'
            orig_jenkins_summary = orig_workspace + '/' + 'tmp_testsummary.log'
            #logSrv = '135.251.200.212' if not platformType == 'other' else ftpServer
        logSrv = LOG_SERVER['IP']
        logSrvFqdn = LOG_SERVER['FQDN']
        logSrvHttp = LOG_SERVER['HTTP']
        logTool = '/root/wwang046/logUpload.py' if not platformType == 'other' else '/tftpboot/atx/atxuser/jenkins/logUpload.py'
        res = True
        domainLogDir = ''
        logToolLocal=SCRIPT_PATH+'/logUpload4ant.py'
        try:
            #replaced by curl http url directly
            #cmd = "cp -rf %s %s" %(jenkins_log,jenkins_target)
            #result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            #db_print("\n%s with output:%s" %(cmd,result))
            #for uniq timestamp, always get the latest one so tail -1
            #cmd = "cat %s |grep -o -E 'Creating [[:graph:]]+(root|atxuser)-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[0-9]{8}'|uniq |tail -1" %jenkins_target
            time.sleep(5)

            if runType == 'LTB':
                if not working_dir:
                    cmd = "curl -s %sconsoleText |grep -o -a -E '(Creating|Updating) [[:graph:]]+(root|atxuser|%s)-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[0-9]{8} directory'|uniq |tail -1" %(build_url,username)
                    result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                    result = result.strip()
                    if not result:
                        return False,''
                    result = result.split(' ')[1].strip()
                #for LTB, timeStamp is already determined at the LTB start phase, we can use it
                    timeStamp = os.path.basename(result)
                    homeDir = os.path.dirname(result)
                    db_print("\n%s with output:%s" %(cmd,timeStamp))
                else:
                    homeDir = os.path.dirname(working_dir)
                    timeStamp = os.path.basename(working_dir)
                if not homeDir:
                    homeDir = envOverriden['HOME']

                jenkins_summary = workspace + '/testsummary_' + timeStamp + '.log'
                orig_jenkins_summary = orig_workspace + '/testsummary_' + timeStamp + '.log'
                cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:%s/%s/testsummary.log %s" %(passwd,port,username,linux_ip,homeDir,timeStamp,jenkins_summary)
                result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                db_print("\n%s with output:%s" %(cmd,result),'debug')
                
                ####To check log moved to storage or not
                try:
                    #ssh_scp_get(ip=linux_ip,username=username,password=passwd,port=int(linuxPORT),local=jenkins_summary,remote=os.path.join('~',timeStamp,'testsummary.log'))
                    cmd1 = "curl -s %sconsoleText |grep -o -a -E 'Moving [[:graph:]]+(root|atxuser|%s)-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[0-9]{8} to (.*) in /storage success...'|uniq |tail -1" %(build_url,username)
                    result1=subprocess.Popen(cmd1, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                    result1 = result1.strip()
                    nout=re.search('to (.*) in',result1)
                    path=nout.group(1).strip()
                    logpath="/storage/"+path
                    storage_flag="True"
                    cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:%s/testsummary.log %s" %(passwd,port,username,linux_ip,logpath,jenkins_summary)
                    result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                    db_print("\n%s with output:%s" %(cmd,result))
                except Exception as inst:
                    db_print('Logs not moved to /storage')
                    storage_flag="False"
                if not os.path.exists(jenkins_summary):
                    res = False
                if not uploadLog:
                    return True,''
                if domain:      
                    #domain = domain.strip('ROBOT:')
                    if storage_flag != "True":
                        if Site!='Antwerp':
                            cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --pctaUser %s --pctaPasswd %s --team %s --platform %s --domain %s --timeStamp %s;'" %(logSrv,logTool,build_id,linux_ip,homeDir,port,username,passwd,team,job_name,domain,timeStamp)
                        else:
                            cmd="python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --pctaUser %s --pctaPasswd %s --team %s --platform %s --domain %s --remote True --timeStamp %s;" %(logToolLocal,build_id,linux_ip,homeDir,port,username,passwd,team,job_name,domain,timeStamp)    
                    else:
                        if Site!='Antwerp':
                            cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --pctaUser %s --pctaPasswd %s --team %s --platform %s --serverNoTimestamp True --domain %s --timeStamp %s;'" %(logSrv,logTool,build_id,linux_ip,logpath,port,username,passwd,team,job_name,domain,timeStamp)  
                        else:
                            cmd="python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --pctaUser %s --pctaPasswd %s --team %s --platform %s --serverNoTimestamp True --domain %s --remote True --timeStamp %s;" %(logToolLocal,build_id,linux_ip,logpath,port,username,passwd,team,job_name,domain,timeStamp)        
                    result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                    db_print("\n%s with output:%s" %(cmd,result))
                    
                else:
                    #job_name = re.sub(r'(|)',r'\\\1',job_name)
                    if storage_flag != "True":
                        if Site!='Antwerp':
                            cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --pctaUser %s --pctaPasswd %s --team %s --platform %s --timeStamp %s;'" %(logSrv,logTool,build_id,linux_ip,homeDir,port,username,passwd,team,job_name,timeStamp)
                        else:
                            cmd="python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --pctaUser %s --pctaPasswd %s --team %s --platform %s --remote True --timeStamp %s;" %(logToolLocal,build_id,linux_ip,homeDir,port,username,passwd,team,job_name,timeStamp)
                    else:
                        if Site!='Antwerp':
                            cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --pctaUser %s --pctaPasswd %s --team %s --platform %s --serverNoTimestamp True --timeStamp %s;'" %(logSrv,logTool,build_id,linux_ip,logpath,port,username,passwd,team,job_name,timeStamp)  
                        else:
                            cmd="python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --pctaUser %s --pctaPasswd %s --team %s --platform %s --serverNoTimestamp True --remote True --timeStamp %s;" %(logToolLocal,build_id,linux_ip,logpath,port,username,passwd,team,job_name,timeStamp)    
                    result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                    db_print("\n%s with output:%s" %(cmd,result))
                res_match = re.search('LOG_DIR:([\S]+)',result)    
                if res_match:
                    domainLogDir = res_match.group(1).strip('\n')    
                fd=open(orig_jenkins_summary,"a+")
                fd.writelines("\n########################################################################")
                fd.writelines("\nConsole log details :")
                fd.writelines("\n" + build_url + "console")
                fd.writelines("\nATC log details :")
                if domainLogDir:
                    fd.writelines("\n%s/%s/%s/%s/%s/\n" %(logSrvFqdn,team,build_id,orig_job_name,domainLogDir))
                else:
                    fd.writelines("\n%s/%s/%s/%s/\n" %(logSrvFqdn,team,build_id,orig_job_name))
                fd.writelines("\n########################################################################")
                fd.close()
                all_jenkins_summary = os.path.join(workspace,'testsummary.log')
                cmd = "cat %s >> %s" %(jenkins_summary,all_jenkins_summary)
                result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                db_print("append testsummary.log \n%s with output:%s" %(cmd,result))
            elif runType == 'PYBOT_LAUNCHER':
                cmd = "curl -s %sconsoleText |grep -o -a -E 'outputdir [[:graph:]]+(root|atxuser|%s)-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[0-9]{8}'|uniq |tail -1" %(build_url,username)

                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                result = result.strip()[9:]
                timeStamp = os.path.basename(result)
                jenkins_summary = workspace + '/testsummary_' + timeStamp + '.log'
                orig_jenkins_summary = orig_workspace + '/testsummary_' + timeStamp + '.log'
                homeDir = os.path.dirname(result)
                db_print("\n%s with output:%s" %(cmd,timeStamp))
                cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:%s/%s/ROBOT/ATDD_focus.tms %s" %(passwd,port,username,linux_ip,envOverriden['HOME'],timeStamp,jenkins_summary)
                result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                db_print("\n%s with output:%s" %(cmd,result))
                #try:
                    #ssh_scp_get(ip=linux_ip,username=username,password=passwd,port=int(linuxPORT),local=jenkins_summary,remote=os.path.join('~',timeStamp,'ROBOT','ATDD_focus.tms'))
                #except Exception as inst:
                #    db_print("get tms file failure with %s" %inst)
                if not os.path.exists(jenkins_summary):
                    res = False
                if not uploadLog:
                    return True,''
                if domain:      
                    #domain = domain.strip('ROBOT:')
                    if Site!='Antwerp':
                        cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --team %s --platform %s --domain %s --timeStamp %s;'" %(logSrv,logTool,build_id,linux_ip,homeDir,port,team,job_name,domain,timeStamp)
                    else:
                        cmd="python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --team %s --platform %s --domain %s --remote True --timeStamp %s;" %(logToolLocal,build_id,linux_ip,homeDir,port,team,job_name,domain,timeStamp)
                    result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                    db_print("\n%s with output:%s" %(cmd,result))
                    #reportStatus('domain',job_name,job_num,'COMPLETED',timeStamp,domain)
                else:
                    if Site!='Antwerp':
                        cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --team %s --platform %s --timeStamp %s;'" %(logSrv,logTool,build_id,linux_ip,homeDir,port,team,job_name,timeStamp)
                    else:
                        cmd="python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --team %s --platform %s --remote True --timeStamp %s;" %(logToolLocal,build_id,linux_ip,homeDir,port,team,job_name,timeStamp)
                    result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                    db_print("\n%s with output:%s" %(cmd,result))
                res_match = re.search('LOG_DIR:([\S]+)',result)    
                if res_match:
                    domainLogDir = res_match.group(1).strip('\n')
                fd=open(orig_jenkins_summary,"a+")
                fd.writelines("\n########################################################################")
                fd.writelines("\nConsole log details :")
                fd.writelines("\n" + build_url + "console")
                fd.writelines("\nATC log details :")
                if domainLogDir:
                    fd.writelines("\n%s/%s/%s/%s/%s/\n" %(logSrvFqdn,team,build_id,orig_job_name,domainLogDir))
                else:
                    fd.writelines("\n%s/%s/%s/%s/\n" %(logSrvFqdn,team,build_id,orig_job_name))
                fd.writelines("\n########################################################################")
                fd.close()
                all_jenkins_summary = workspace + '/' + 'testsummary.log'
                cmd = "cat %s >> %s" %(jenkins_summary,all_jenkins_summary)
                result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                db_print("append testsummary.log \n%s with output:%s" %(cmd,result))
            elif runType == 'ATX':
                cmd = "curl -s %sconsoleText |grep -o -a -E 'Time stamp = [0-9]{8}-[0-9]{6}'|uniq" %build_url
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                #remove empty line
                result=result.strip()
                resultTmp = result.split('\n')
                timeStamp0 = resultTmp[0][13:]
                timeStamp = resultTmp[-1][13:]
                jenkins_summary = workspace + '/testsummary_' + timeStamp + '.log'
                orig_jenkins_summary = orig_workspace + '/testsummary_' + timeStamp + '.log'
                if not uploadLog:
                    return True,''
                if domain:
                    if Site!='Antwerp':
                        cmd = "ssh -o StrictHostKeyChecking=no root@%s 'python -u %s --buildID %s --team %s --platform %s --atxIP %s --atxPlatform %s --load %s --testSummaryFile %s --timeStamp %s --domain %s;'" %(logSrv,logTool,build_id,team,job_name,linux_ip,platform,load,timeStamp0,timeStamp,domain)
                    else:
                        cmd = "python -u %s --buildID %s --team %s --platform %s --atxIP %s --atxPlatform %s --load %s --testSummaryFile %s --timeStamp %s --remote True --domain %s;" %(logToolLocal,build_id,team,job_name,linux_ip,platform,load,timeStamp0,timeStamp,domain)
                else:
                    if Site!='Antwerp':
                        cmd = "ssh -o StrictHostKeyChecking=no root@%s 'python -u %s --buildID %s --team %s --platform %s --atxIP %s --atxPlatform %s --load %s --testSummaryFile %s --timeStamp %s;'" %(logSrv,logTool,build_id,team,job_name,linux_ip,platform,load,timeStamp0,timeStamp)
                    else:
                        cmd = "python -u %s --buildID %s --team %s --platform %s --atxIP %s --atxPlatform %s --load %s --testSummaryFile %s --remote True --timeStamp %s;" %(logToolLocal,build_id,team,job_name,linux_ip,platform,load,timeStamp0,timeStamp)

                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                db_print("\n%s with output:%s" %(cmd,result))
                res_match = re.search('LOG_DIR:([\S]+)',result)    
                if res_match:
                    domainLogDir = res_match.group(1).strip('\n')
                logurl = "%s/%s/%s/%s/" %(logSrvHttp,team,build_id,job_name)
                testsummaryurl = logurl + "SB_Logs_" + timeStamp + "_" + domain if domain else logurl + "SB_Logs_" + timeStamp
                testsummaryurl += "/SB_Logs/testsummary.log"
                cmd = "curl %s -o %s" %(testsummaryurl,jenkins_summary)
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                db_print("\n%s with output:%s" %(cmd,result))
                if not os.path.exists(jenkins_summary):
                    res = False
                all_jenkins_summary = workspace + '/' + 'testsummary.log'
                cmd = "cat %s >> %s" %(jenkins_summary,all_jenkins_summary)
                result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                db_print("append testsummary.log \n%s with output:%s" %(cmd,result))
                fd=open(orig_workspace + '/' + 'testsummary.log',"a+")
                fd.writelines("\n########################################################################")
                fd.writelines("\nConsole log details :")
                fd.writelines("\n" + build_url + "console")
                fd.writelines("\nATC log details :")
                if domainLogDir:
                    fd.writelines("\n%s/%s/%s/%s/%s/\n" %(logSrvFqdn,team,build_id,orig_job_name,domainLogDir))
                else:
                    fd.writelines("\n%s/%s/%s/%s/\n" %(logSrvFqdn,team,build_id,orig_job_name))
                fd.writelines("\n########################################################################")
                fd.close()
            elif runType == 'tcl':
                batchType='non-framework'
                cmd = "curl -s %sconsoleText |grep -o -a -E 'LOG_DIR:(.*)' |uniq |tail -1" %build_url
                cmd1 = "curl -s %sconsoleText |grep -o -a -E 'LOG_FILE:(.*)' |uniq |tail -1" %build_url
                resulta=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                resulta = resulta.strip()
                if not resulta:
                    return False,''
                resulta = resulta.split(':')
                homeDir = resulta[1]
                resultb=subprocess.Popen(cmd1, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                resultb = resultb.strip()
                if not resultb:
                    return False,''
                resultb = resultb.split(':')
                timeStamp = resultb[1]
                if not uploadLog:
                    return True,''
                if Site!='Antwerp':
                    cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --pctaUser %s --pctaPasswd %s --team %s --platform %s --timeStamp %s --batchType %s;'" %(logSrv,logTool,build_id,linux_ip,homeDir,port,username,passwd,team,job_name,timeStamp,batchType)
                else:
                    cmd="python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --pctaUser %s --pctaPasswd %s --team %s --platform %s --timeStamp %s --remote True --batchType %s;" %(logToolLocal,build_id,linux_ip,homeDir,port,username,passwd,team,job_name,timeStamp,batchType)
                result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                db_print("\n%s with output:%s" %(cmd,result))
                res_match = re.search('LOG_DIR:([\S]+)',result)
                if res_match:
                    domainLogDir = res_match.group(1).strip('\n')
            if runType != 'python' or runType != 'tcl':                
                fd_file=os.path.basename(orig_jenkins_summary)    
                fd_file = os.path.join(job_url,'ws',fd_file)
                if Site!='Antwerp':
                    cmd = "ssh -o StrictHostKeyChecking=no root@%s 'python -u %s --buildID %s --team %s --platform %s --traceFiles %s;'" %(logSrv,logTool,build_id,team,job_name,fd_file)
                else:
                    baseSummary=os.path.basename(orig_jenkins_summary)
                    fd_file=os.path.join(workspace,baseSummary)
                    cmd = "python -u %s --buildID %s --team %s --platform %s --remote True --traceFiles %s;" %(logToolLocal,build_id,team,job_name,fd_file)
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                db_print("\n%s with output:%s" %(cmd,result))
            if (runType == 'LTB' or runType == 'PYBOT_LAUNCHER') and domain:
                #reportStatus('domain',orig_job_name,job_num,'COMPLETED',timeStamp,domain)
                data = {'jobName':orig_job_name,'jobNum':job_num,'currentStatus':'partial_completed','timeStamp':timeStamp,'Domain':domain}
                reportStatus('domain',data)
            db_print("LOG_DIR:%s" %domainLogDir)
            return res,timeStamp
        except Exception as inst:
            db_print("jenkins console and log upload failure with exception :%s!" %inst)
            return False,''        
    except Exception as inst :
        db_print("this operation can only run on jenkins server as run python script step:%s" %inst)
        return False,'' 

#def updateREPO(linuxIP,userName,passwd,linuxPORT): 
#    try :
#        cmd = "python -u ~/repoupdate.py --pcta %s --pctaPort %s" %(linuxIP,linuxPORT)
#        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
#        db_print("\n%s with output:%s" %(cmd,result))
#    except Exception:
#        db_print("testsummary file operation exception :%s!" % str(inst))
#        return False 
#    return True

def updateREPO(linuxIP,linuxUser,linuxPasswd,linuxPORT,cstag,purgeRepo,repoInfo):
    try :
        logging.debug('%s'%repoInfo)
        if repoInfo:
            repoInfo = json.dumps(eval(repoInfo))
        else:
            repoInfo = '{}'
        cmd = "python -u /var/jenkins_home/scripts/repoUpdate.py --pcta %s  --pctaUser %s --pctaPasswd %s --pctaPort %s --csTag %s --repoInfo '''%s'''" %(linuxIP,linuxUser,linuxPasswd,linuxPORT,cstag,repoInfo)
        if purgeRepo:
            cmdClean = "python -u /var/jenkins_home/scripts/repoClean.py --pcta %s  --pctaUser %s --pctaPasswd %s --pctaPort %s" %(linuxIP,linuxUser,linuxPasswd,linuxPORT)
            result=subprocess.Popen(cmdClean, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            db_print("\n%s with output:%s" %(cmdClean,result))
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        db_print("\n%s with output:%s" %(cmd,result))
    except Exception as inst:
        db_print("update repo exception :%s!" % str(inst))
        return False
    return True


def _cleanQemu(linuxIP,userName,passwd,linuxPORT): 
    try :
        build_url = os.environ['BUILD_URL']
        build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)
    except Exception as inst:
        db_print('clean qemu with exception:%s' %inst)
        return
    
    cmd = "curl -s %sconsoleText |grep -o -a -E 'qemu is up with host tap:qemu-tap[0-9]'" %build_url
    db_print(cmd)
    result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
    res = re.search('tap:([\S]+)',result)
    tap = ''
    if res:
        db_print(result)
        tap = res.group(1)
    pid = ''
    cmd = "curl -s %sconsoleText |grep -o -a -E 'or kill pid with [0-9]{1,}'" %build_url
    result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
    db_print(cmd)
    res = re.search('pid with ([\d]+)',result)
    if res:
        db_print(result)
        pid = res.group(1)
    if tap:
        delCmdList = ['sudo ip link set %s down' %tap]
        delCmdList.append('sudo ip link del %s' %tap)
        ssh2(linuxIP, userName,passwd,delCmdList, port=int(linuxPORT))
    if pid:
        killCmd = 'kill -TERM %s' %pid
        ssh2(linuxIP, userName,passwd,killCmd, port=int(linuxPORT))

def cleanEnvPostRun(linuxIP,userName,passwd,oam_ip,linuxPctaexe='',hostFlag=False,linuxPORT='22'):
    jobname = os.environ['JOB_NAME']
    jobNum = os.environ['BUILD_NUMBER']
    get_url = os.environ['BUILD_URL']
    reportJobInstantStatus(jobname,jobNum,'007') 
    if hostFlag:
        _cleanQemu(linuxIP,userName,passwd,linuxPORT)
    try:
        cmd1 = 'ps -ef |grep xterm |grep %s |grep -v grep |cut -c 9-15' %oam_ip
        ssh2(linuxIP, userName,passwd, cmd1, port=int(linuxPORT))
        cmd3 = "ps -C octopus |awk \'{print $1}\' |sed -n \'2,$p\' |tr -s '\n' |xargs kill -9"
        #ssh2(linuxIP, 'atxuser','alcatel01', cmd3, port=int(linuxPORT))
        results=subprocess.Popen(cmd3, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        cmd = "curl -s %sconsoleText |grep -o -a -E '(START TRACE SAVER:file_name is :.*)|(START TRACE SAVER JOB:file_name is :.*)'" %get_url
        result = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True).communicate()[0]
        #cmd2 = "ps -ef |grep launchTestBatch |grep %s |grep -v grep | awk '{print $2,$3}'" %oam_ip
        #results=ssh2(linuxIP, userName,passwd, cmd2,True ,port=int(linuxPORT))
        #resultsList = results.split('\n')
        #zombiePid = ''
        #parentPid = '1'
        #for item in resultsList:
        #    if item.strip():
        #        pidList = item.strip().split(' ')
        #        parent = pidList [0]
        #        if pidList[1] == '1':
        #            zombiePid = pidList[0]
        #            break
        #        elif pidList[1] == parentPid:
        #            zombiePid = parentPid
        #            break
        #        else:
        #            parentPid = pidList[0]
        #if zombiePid:
        #    cmd3 = 'pstree -p %s -A' %zombiePid
        #    results=ssh2(linuxIP, userName,passwd, cmd3,True,port=int(linuxPORT))
        #    res = re.findall(r'\(([\d]+)\)',results)
        #    if res:
        #        res.reverse()
        #        cmd4 = 'kill -9'
        #        for item in res:
        #            cmd4 += ' %s' %item
        #        ssh2(linuxIP,userName,passwd, cmd4,port=int(linuxPORT))
        #db_print("zombie pids and child pids have been killed")
        try:
            if linuxPctaexe != '':
                #To retrieve start PCTA process pid
                pcta_cmd="ps -aef | grep pcta.exe | grep -v defunct | grep -v grep | awk '{print $2}'"
                pid=ssh2(linuxIP, userName,passwd,pcta_cmd,'check',port=int(linuxPORT))
                pid=pid.strip()
                #To kill PCTA process pid
                if pid:
                    kill_cmd="sudo /bin/kill -9 %s" %pid
                    ssh2(linuxIP, userName,passwd,kill_cmd,port=int(linuxPORT))
        except Exception as inst:
            db_print("PCTA process kill error:%s" %inst)

        try:
            trace_file = ""
            trace_file_list=[]
            cmd = "curl -s %sconsoleText |grep -o -a -E '(START TRACE SAVER:file_name is :.*)|(START TRACE SAVER JOB:file_name is :.*)'" %get_url
            result = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True).communicate()[0]
            resultList = result.strip().strip('\n').split('\n')
            for result in resultList:
                nout=re.search(r':file_name is :(.*)',result)
                if nout:
                    trace_files=nout.group(1)
                    for trace_file in trace_files.split(','):
                        trace_file=os.path.basename(trace_file.strip())
                        trace_file_list.append(trace_file)
            trace_file = ' '.join(trace_file_list)
            if trace_file:
                cmd = 'cd /tmp/.jenkins;rm -rf %s' %trace_file
                results=ssh2(linuxIP, userName,passwd, cmd,'check',port=int(linuxPORT))
        except Exception as inst:
            db_print("tmp trace file cleanning error:%s" %inst)
    except Exception as inst:
        db_print("post env cleaning error:%s" %inst)
    post_summary()

def post_summary():
    try:
        lst1=[]
        freason={}
        count=0
        print"*********************************************************************************************************************"
        print"                                         JOB-SUMMARY                                           "
        print"*********************************************************************************************************************"

        jobname = os.environ['JOB_NAME']
        jname=jobname
        #print(jname)
        url="http://smartlab-service.int.net.nokia.com:8080/job/%s/lastBuild/api/python?pretty=true"%(jname)
        #print(url)
        fRead = eval(urllib.urlopen(url).read())
        jobnumber = fRead["number"]
        #print(jobnumber)
        url="http://smartlab-service.int.net.nokia.com:8080/job/%s/%s/consoleText"%(jname,jobnumber)
        #print(url)
        page = requests.get(url)
        FO=open("jen_console.txt",'w+')
        for line in page:
            line=line.strip('\n')
            FO.write(line)
        FO.close
        for line in open("jen_console.txt",'r'):
            if "---STEP:" in line:
                m=line.split("---STEP:")[1].split(":")[0]
                lst1.append(m)
                for i in lst1:
                    freason[i] = None
            if "Failreason~" in line:
                freason[m]=line
                del lst1[:]
        for key in freason:
            if freason[key]!=None:
                count=count+1
                print("---Failed Step~"'%s')%(key)
                print(freason[key])
        if count==0:
            print("---No Failures!!!")
        FO.close
        print"*********************************************************************************************************************"
    except Exception as e:
        print(e)

def generateCaseList(linux_ip,resultDirList,linuxPORT,username,passwd,robotOnly = True,debug=False): 
    try :
        if debug:
            jenkins_home = '/tftpboot/atx/atxuser'
            workspace = '/tftpboot/atx/atxuser/jenkins'
            job_name = 'NFXSE_FANTG_FGLTB_I'
            jenkins_build_id = '35'
        else:
            jenkins_home = os.environ['JENKINS_HOME']
            workspace = os.environ['WORKSPACE']
            job_name = os.environ['JOB_NAME'] 
            jenkins_build_id = os.environ['BUILD_ID']
    except Exception as inst :
        db_print("this operation can only run on jenkins server as run python script step:%s" %inst)
        return ''
    orig_workspace = workspace
    workspace = re.sub(r'([\(|\)])',r'\\\1',workspace)
    job_name = re.sub(r'([\(|\)])',r'\\\1',job_name)
    if not os.path.exists(os.path.join(jenkins_home,'CASELISTDIR')):
        os.mkdir(os.path.join(jenkins_home,'CASELISTDIR'))
    caselistfile = os.path.join(jenkins_home,'CASELISTDIR','caselist_' + job_name + '_' + jenkins_build_id + '.txt')
    casefile = open(caselistfile,'w+')
    for homeDir in resultDirList:     
        cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p%s %s@%s 'ls %s/ROBOT/*.xml |grep -v _rerun'" %(passwd,linuxPORT,username,linux_ip,homeDir)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        print 'get result:%s' %result
        xmlfiles = result.strip().split('\n')
        for each in xmlfiles:
            if each.find('output.xml') != -1 :
                outputfile = each.strip()
                tmp_jenkins_xml = os.path.join(workspace,'output.xml')
                cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:%s %s" %(passwd,linuxPORT,username,linux_ip,outputfile,tmp_jenkins_xml)
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                
                print 'get result:%s' %result
                try:
                    #ssh_scp_get(ip=linux_ip,username=username,password=passwd,port=int(linuxPORT),local=tmp_jenkins_xml,remote=outputfile)
                    outputlist = getcaselistfromxml(os.path.join(orig_workspace,'output.xml'))
                    outputlines = '\n'.join(outputlist)
                except Exception as inst:
                    db_print("output.xml parse error:%s" %inst)
                    outputlines = []
                #print 'get outputlist:%s' %outputlist
                try:
                    casefile.writelines(outputlines)
                    os.remove(os.path.join(orig_workspace,'output.xml'))
                except Exception as inst:
                    db_print("output.xml file remove error:%s" %inst)
                #delete dry run directory
        cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p%s %s@%s 'rm -rf %s'" %(passwd,linuxPORT,username,linux_ip,homeDir)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        print 'get result:%s' %result
    casefile.close()
    return caselistfile

def getcaselistfromxml(filename):
    try:
        tree = etree.parse(filename)
    except Exception as inst:
        print 'output.xml parse failure %s' %inst
        return
    
    caselist = []
    for item in tree.findall('//suite/test'):
        #print 'item is %s' %item
        caselist.append(item.getparent().attrib['name'] + '.' + item.attrib['name'])
    return caselist

def updatelauchTesBatchFile(tempFile,launchTestBatch,timeStampForBatch=''):
    attachedFunCode = '''#!/bin/ksh
    # proc inserted via atx
      _callExecForATX () {
      #echo "\\nargs: $*"
      sNewCmd=$*          
      sNewCmd=$(echo $sNewCmd | awk '{print substr( $0, index( $0, " -e" )+3, length($0) ) }')
      ind=$(echo $sNewCmd | awk '{print index( $0, "xec" )}')
      #echo "index --> $ind"
      if [[ $ind -eq 1 ]] ; then
      sNewCmd=$(echo $sNewCmd | awk '{print substr( $0,4, length($0) ) }')
      fi
      #echo "\\nnew cmd-: $sNewCmd" 
      $sNewCmd 
    }
'''
    #attachedJenkinsServer = 'export ATXServerIP=' + socket.gethostbyname(socket.gethostname()) + '\n'
    attachedLoadName = 'export LoadName=SD_' + build + '\n'
    attachedTimeStam = 'export TimeStamp=' + timeStampForBatch + '\n'
    with open(launchTestBatch,'a') as fin:
        fin.write(attachedFunCode)
        #fin.write(attachedJenkinsServer)
        fin.write(attachedLoadName)
        fin.write(attachedTimeStam)
        with open (tempFile,'r') as fout:
            temLine = fout.readline()
            while temLine:
                if 'xterm ' in temLine:
                    temLine = temLine.replace('xterm','_callExecForATX')
                if 'ATC Realtime Logs Monitor' in temLine:
                    while True:
                        temLine = fout.readline()
                        if not temLine.strip(' ').endswith('\\') and temLine is not '':
                            temLine = fout.readline()
                            break; 
                fin.write(temLine)
                temLine = fout.readline()

def updatelaunchTestBatchCmd(batchCommandAtx,linuxIP,username,passwd,linuxPORT,timeStampForBatch='tmp'):
    global envOverriden
    batchComlaunchList = filter(lambda str_filter:'launchTestBatch' in str_filter, reduce(lambda str_iter1,str_iter2:str_iter1+str_iter2,map(lambda str_iter:str_iter.split(' '), batchCommandAtx.split(';'))))
    print"saba1**************************"
    print(batchCommandAtx)
    print(envOverriden)
    if len(batchComlaunchList) is not 0 :
        batchComHeadList = filter(lambda str_com:'launchTestBatch' in str_com, batchComlaunchList)
        if len(batchComHeadList) is not 0 :
            batchComHead = batchComHeadList[0]
            #batchComHead = batchComHead.strip('ROBOT:').strip('APME:')
            batchComHead = re.sub(r'^.*?:','',batchComHead)
        else :
            batchComHead = '/repo/atxuser/atc/cm8/auto/tools/pbscript/launchTestBatch' 
        batchComHeadNew = batchComHead
        if envOverriden.get('ANSI',''):
            print"Im here saba"
            batchComHeadNew = '/dslam023/atx/atxuser/.launchTestBatchATX'
        if len(batchComHead) == len('launchTestBatch'):
            if envOverriden.get('MOSWAREPO',''):
                batchComHeadNew = envOverriden['MOSWAREPO'] + '/cm8/auto/tools/pbscript/launchTestBatch'
            elif envOverriden.get('REPO',''):
                batchComHeadNew = envOverriden['REPO'] + '/cm8/auto/tools/pbscript/launchTestBatch'
            else:
                batchComHeadNew = '/repo/atxuser/atc/cm8/auto/tools/pbscript/launchTestBatch' 
         
        runBatchIp = linuxIP
        batchComAtxHead = 'launchTestBatch.' +  timeStampForBatch     
        tempbatchfile = 'launchTestBatchtemp' +  timeStampForBatch 
        print("saba")
        cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:%s %s" %(passwd,linuxPORT,username,linuxIP,batchComHeadNew,tempbatchfile)
        print(cmd)
        db_print(cmd,'debug')
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        updatelauchTesBatchFile(tempbatchfile,batchComAtxHead,timeStampForBatch)
        cmd = "rm -rf %s" % tempbatchfile
        db_print(cmd)
        print(cmd)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        cmd = "chmod +x % s" % batchComAtxHead
        db_print(cmd)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s %s@%s:%s" %(passwd,linuxPORT,batchComAtxHead,username,linuxIP,envOverriden['HOME'] + '/'+batchComAtxHead) 
        db_print(cmd,'debug')
        print(cmd)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        cmd = "rm -rf % s" % batchComAtxHead
        db_print(cmd)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        print"saba2****************"
        print(batchComHead)
        print(batchComAtxHead)
        print(batchCommandAtx)
        batchCommandAtx = batchCommandAtx.replace(batchComHead,envOverriden['HOME'] + '/' + batchComAtxHead)
        print(batchCommandAtx)
    return batchCommandAtx 

def _generateIpAddr(linuxIp):
    '''
    generate Target/Guest IP address pair according to linuxIp
    '''
    ipPrefix = '200.9'
    [ipSuffix1,ipSuffix2] = linuxIp.split('.')[-2:]
    ipSuffix2 = random.randint(1,250)
    guestIp = ipPrefix + '.' + ipSuffix1 + '.' + str(ipSuffix2)
    targetIp = ipPrefix + '.' + ipSuffix1 + '.' + str(ipSuffix2 + 1)
    return [targetIp,guestIp]

def _get_board_from_argument(linuxIP,linuxPORT,username,passwd,batchCommand):
    res = re.search('--argumentFile ([\S]+)',batchCommand)
    argFile = res.group(1)
    try :
        workspace = os.environ['WORKSPACE']
        workspace = re.sub(r'([\(|\)])',r'\\\1',workspace)
    except Exception as inst :
        print 'failure to get workspace'
        workspace = '/tmp' 
    cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:%s %s" %(passwd,linuxPORT,username,linuxIP,argFile,workspace) 
    db_print(cmd,'debug')
    result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
    newArgFile = workspace + '/' + os.path.basename(argFile)
    print 'file is %s' %newArgFile
    board = ''
    with open(newArgFile,'r') as fin:
        lines = fin.readlines()
        for line in lines:
            (key,value) = line.split(' = ')
            if key == 'NT':
                board = value.lower()
                break
    fin.close()
    print 'board is %s' %board
    if board:
        return board[0:4] + '-' + board[4]
    return board

def prepareQemu(linuxIP,user,passwd,linuxPORT,build,build_ip,oam_ip,board):
    try :
        workspace = os.environ['WORKSPACE']
        workspace = re.sub(r'([\(|\)])',r'\\\1',workspace)
    except Exception as inst :
        print 'failure to get workspace'
        workspace = '/tmp' 
    try:
        (p1,p2,p3,p4) = oam_ip.split('.')
        if p4 == '255':
            db_print("wrong oam_ip %s" %oam_ip)
            return False
        guest_ip = '.'.join([p1,p2,p3]) + '.' + str(int(p4)+1)
        timeStamp=time.strftime('%b%d%H%M%S',time.localtime())
        #giciPort = '44' + p3 + p4
        giciPort = int(p3 + p4) % 10000
        if giciPort < 1000:
            giciPort = giciPort + 1000
        giciPort = str(giciPort)[-4:]
        print('parameters are as following:')
        print(oam_ip)
        print(guest_ip)
        print(board)
        print(build + ':' + build_ip)
        print(giciPort[-4:])
        print(timeStamp)
        print(linuxIP)
        print(linuxPORT)
        qemuDict = startHostBySSH(oam_ip,guest_ip,board,build + ':' + build_ip,giciPort[-4:],timeStamp,linuxIP,'atxuser','alcatel01',int(linuxPORT))
    except Exception as inst:
        db_print("qemu start failure %s" %inst)
        return False

    if not qemuDict:
        return False
    db_print('qemu is up with working_dir:%s' %qemuDict['working_dir'])
    db_print('qemu is up with target ip:%s' %qemuDict['network']['interfaces']['management']['guest']['ip'])
    db_print('qemu is up with host ip:%s' %qemuDict['network']['interfaces']['management']['host']['ip'])
    db_print('qemu is up with host tap:%s' %qemuDict['network']['interfaces']['management']['host']['tap'])

    return True

def _set_metrics_user(prerunConfig,metrics_user):
    #prerunConfig = re.sub('export METRICS_USER=[^;]+','',prerunConfig)
    #prerunConfig = prerunConfig.lstrip(';').rstrip(';').replace(';;',';')
    prerunConfig = prerunConfig + ';export METRICS_USER=' + metrics_user if prerunConfig else 'export METRICS_USER=' + metrics_user
    return prerunConfig

def _workaround_ftp_moswa(ftp_host,job_name,build):
    if not '.' in build:
        return ftp_host
    if '_DF8' in job_name and not 'packageme_' in ftp_host:
        tmpList = ftp_host.split(':')
        if len(tmpList) < 2:
            return ftp_host
        #2 means http,3 means ftp
        if len(tmpList) == 2:
            tmpList[1] = os.path.join(tmpList[1],'packageme_' + build)
        else:
            tmpList[2] = os.path.join(tmpList[2], 'packageme_' + build)
        ftp_host = ':'.join(tmpList)
        return ftp_host
    return ftp_host

def start_trace_saver(server_ip,username,passwd,port,trace_server_list,product,domain=True,recover_OAM=False,oam_ip=''):
    if not trace_server_list:
        db_print("no gici trace server defined,skip")
        return
    result_pids = ''
    trace_files = ''
    scriptList = ['traceSaver.py','clearConsolePort.py']
    remotepath = '/tmp/.jenkins'
        
    try:
        cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'ls -d %s'" %(passwd,username,server_ip,remotepath)
        db_print(cmd,'debug')
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        if not remotepath == result.strip():
            cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'mkdir -p %s'" %(passwd,username,server_ip,remotepath)
            db_print(cmd,'debug')
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
    except Exception as inst:
        db_print("mkdir in remote machine fail with :%s" %inst)    
        return False
        
    for aScript in scriptList:
        try:
            localscript = os.path.join(SCRIPT_PATH,aScript)
            remotescript = os.path.join(remotepath,aScript)
            cmd = 'cksum %s' %localscript
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            new_cksum = result.strip().split(' ')[0]
            db_print('cksum:%s' %new_cksum,'debug')
            cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'cksum %s'" %(passwd,username,server_ip,remotescript)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            old_cksum = result.strip().split(' ')[0]
            db_print('cksum:%s' %old_cksum,'debug')

            if new_cksum and not old_cksum == new_cksum:
                cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s %s@%s:%s" %(passwd,localscript,username,server_ip,remotepath)
                db_print(cmd,'debug')
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        except Exception as inst:
            db_print("put script %s failed with exception as inst:%s" %(aScript,inst))

    for trace_server in trace_server_list:
        if not ' ' in trace_server:
            continue
        tmpList = trace_server.split(' ')
        if len(tmpList) < 3:
            continue
        gici_ip = tmpList[0].strip()
        gici_port = tmpList[1].strip()
        slot_pos = tmpList[2].strip()
        if len(tmpList) > 3:
            dut_type = product + ':' + tmpList[3].strip() + ':' + slot_pos
        else:
            dut_type = product
        if not 'NT' in slot_pos:
            prefix = 'LT_' + slot_pos
        else:
            prefix = slot_pos  
        prefix = 'trace_' + prefix
        if not (gici_ip and gici_port):
            db_print("worng NT_gici configured,should be NT-A:<ip> <port>")
            continue

        #only action on NT CORE0
        if recover_OAM and not re.search(r"NT.*0", slot_pos, re.I):
            continue


        db_print("kill dead traceSaver first:")
        cmd1="ps -aef | grep traceSaver.py | grep %s | grep %s | grep -v grep | awk '{print $2}' | tr -s '\n' |xargs kill -9" %(gici_ip,gici_port)
        try:
            ssh2(server_ip, username,passwd,cmd1,'check')
        except Exception as inst:
            db_print("kill dead traceSaver process with exception:%s" %inst)
            
        timestamp=time.strftime('%b%d%H%M%S',time.localtime())
        trace_file = prefix  + '_' + timestamp
        remotepath = '/tmp/.jenkins'
        trace_file = os.path.join(remotepath,trace_file)
        

        try:
            remotescript = '/tmp/.jenkins/traceSaver.py'
            if recover_OAM:
                cmd_pcta = "cd %s && nohup python -u %s --craftIp %s --craftPort %s --cmd reboot --dut_type %s >/dev/null 2>&1 &" % (os.path.dirname(remotescript),remotescript, gici_ip, gici_port, dut_type)
            else:
                cmd_pcta = "cd %s && nohup python -u %s --craftIp %s --craftPort %s --LOG_FILE %s --storeInterval 9999 --dut_type %s >/dev/null 2>&1 &" % (os.path.dirname(remotescript),remotescript, gici_ip, gici_port, trace_file, dut_type)

            ssh2_non_block(server_ip, username,passwd,cmd_pcta,True)
        except Exception as inst:
            db_print("Start trace saver failed:%s" %inst)

        if recover_OAM:
            continue

            
        cmd1="ps -aef | grep traceSaver.py | grep %s | grep %s | grep -v defunct | grep -v grep | awk '{print $2}'" %(gici_ip,gici_port)
        try:
            result_pid =ssh2(server_ip, username,passwd,cmd1,'check')
            result_pid=result_pid.strip("\n")
            if result_pid:
                result_pids += ' %s' %result_pid
                trace_files += ',%s' %trace_file
        except Exception as inst:
            db_print("ssh connect error for cmd:%s" %cmd1)
            db_print("pls platform owner help log on the machine to execute that command and kill the process manually when ssh is restored!!!")

    #### For recover OAM: check reachable ########
    if recover_OAM:
        for trytimes in range(0, 30):
            time.sleep(20)
    
            if pingIp(oam_ip):
                db_print('DUT %s is recovered, continue next steps...' % oam_ip)
                return True
    
            db_print('DUT %s is not reachable, waiting %s/30...' % (oam_ip, trytimes + 1))
            
        return False
    #### For recover OAM: check reachable ########
            
            
    result_pids = result_pids.strip()
    if result_pids:
        trace_files = trace_files.strip(',')
        if domain:
            db_print("START TRACE SAVER:%s for job:%s" %(result_pids,job_name))
            db_print("START TRACE SAVER:file_name is :%s" %(trace_files))
        else:
            db_print("START TRACE SAVER JOB:%s for job:%s" %(result_pids,job_name))
            db_print("START TRACE SAVER JOB:file_name is :%s" %(trace_files))
        time.sleep(5)

def stop_trace_saver(server_ip,username,passwd,port,trace_server_list,domain=True):
    if not trace_server_list:
        db_print("no gici trace server defined,skip")
        return

    for trace_server in trace_server_list:
        if not ' ' in trace_server:
            continue
        tmpList = trace_server.split(' ')
        if len(tmpList) < 3:
            continue
        gici_ip = tmpList[0].strip()
        gici_port = tmpList[1].strip()
        db_print("kill dead traceSaver first:")
        cmd1="ps -aef | grep traceSaver.py | grep %s | grep %s | grep -v grep | awk '{print $2}' | tr -s '\n' |xargs kill -9" %(gici_ip,gici_port)
        try:
            ssh2(server_ip, username,passwd,cmd1,'check')
        except Exception as inst:
            db_print("kill dead traceSaver process with exception:%s" %inst)
    db_print("kill TRACE SAVER process successfully")

def upload_trace_saver(linuxIP,trace_server_list,team,domain=True):
    if not trace_server_list:
        db_print("no gici trace server defined,skip")
        return
    get_url = os.environ['BUILD_URL']
    try:
        trace_file = ""
        trace_file_list=[]
        if domain:
            cmd = "curl -s %sconsoleText |grep -o -a -E 'START TRACE SAVER:file_name is :.*'|uniq |tail -1" %get_url
        else:
            cmd = "curl -s %sconsoleText |grep -o -a -E 'START TRACE SAVER JOB:file_name is :.*'|uniq |tail -1" %get_url
        result = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True).communicate()[0]
        result = result.strip().strip('\n')
        if result:
            if domain:
                nout=re.search('START TRACE SAVER:file_name is :(.*)',result)
            else:
                nout=re.search('START TRACE SAVER JOB:file_name is :(.*)',result)
            trace_files=nout.group(1)
            for trace_file in trace_files.split(','):
                trace_file=os.path.basename(trace_file.strip())
                #trace_file = re.sub(r'([\(|\)])',r'\\\1',trace_file)
                trace_file_list.append(trace_file)
    except Exception as inst:
        db_print("get TRACE SAVER file failure")
    try:
        workspace = os.environ['WORKSPACE']
        job_name = os.environ['JOB_NAME']
        build_id = os.environ['BuildIDNew']
        build_url = os.environ['BUILD_URL']
        build_url = re.sub('/[\d]+/$','/ws/',build_url)
        build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)
    except Exception as inst:
        db_print("get workspace failured")
        workspace = '/tmp'
        job_name = 'SmartlabService'
    new_workspace = re.sub(r'([\(|\)])',r'\\\1',workspace)
    new_job_name = re.sub(r'([\(|\)])',r'\\\1',job_name)
    #logSrv = '135.251.200.212'
    logSrv = LOG_SERVER['IP']
    logSrvFqdn = LOG_SERVER['FQDN']
    traceLogUrl = ''
    logTool = '/root/wwang046/logUpload.py'
    domainDir = ''

    logToolLocal=SCRIPT_PATH+'/logUpload4ant.py'
    if domain:
        db_print("get log dir:")
        domainDir = GetLogDir()
        db_print("log dir is %s" %domainDir)
    if trace_file_list:
        for val in trace_file_list:
            db_print(build_url)
            traceFiles=os.path.join(build_url,val)
            if Site=='Antwerp':
                traceFiles=os.path.join(workspace,val)
            db_print('traceFiles is:%s'%traceFiles)
            if domainDir:
                if Site!='Antwerp':
                    cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --team %s --platform %s --traceFiles %s --domainDir %s --pcta %s'" %(logSrv,logTool,build_id,team,new_job_name,traceFiles,domainDir,linuxIP)
                else:
                    cmd="python -u %s --buildID %s --team %s --platform %s --traceFiles %s --domainDir %s --remote True --pcta %s" %(logToolLocal,build_id,team,new_job_name,traceFiles,domainDir,linuxIP)
                traceLogUrl = os.path.join(logSrvFqdn,team,build_id,job_name,'SB_Logs_' + domainDir,val)
            else:
                if Site!='Antwerp':
                    cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --team %s --platform %s --traceFiles %s --pcta %s'" %(logSrv,logTool,build_id,team,new_job_name,traceFiles,linuxIP)
                else:
                    cmd="python -u %s --buildID %s --team %s --platform %s --traceFiles %s --remote True --pcta %s" %(logToolLocal,build_id,team,new_job_name,traceFiles,linuxIP)
                traceLogUrl = os.path.join(logSrvFqdn,team,build_id,job_name,val)
            result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            db_print("\n%s with output:%s" %(cmd,result))
            db_print("upload TRACE SAVER process successfully")
            db_print("you can click below url for reference:")
            if domainDir:
                db_print("batch level trace file:%s"  %traceLogUrl)
            else:
                db_print("image flash trace file:%s"  %traceLogUrl)

    else:
        db_print("Failed to upload TRACE SAVER log")
        
def _parse_build_server(build_server):
    for item in ['protocol','build_ip','build_dir','build_user','build_pazwd']:
        cmd = "%s=''" %item
        exec(cmd)
    (protocol,load_path) = build_server.strip(' ').split(':',1)
    protocol = protocol.lower()
    try:
        if protocol == 'http' or protocol == 'https':
            tmpList = load_path.split(':')
            build_pazwd = tmpList.pop()
            build_user = tmpList.pop()
            build_dir = tmpList.pop()
            build_ip=':'.join(tmpList)
        else:
            (build_ip,build_dir,build_user,build_pazwd) = load_path.split(':')
    except Exception as inst:
        db_print('aprser build server with exception:%s' %inst)          
    return (protocol,build_ip,build_dir,build_user,build_pazwd)


def start_voice_process(pcta_ip,username,password):
    try:
        try:
            jenkins_home = os.environ['JENKINS_HOME']
            workspace = os.environ['WORKSPACE']
            job_name = os.environ['JOB_NAME']
        except Exception as inst:
            db_print("get workspace failured")
            workspace = '/tmp'
            job_name = 'SmartlabService'
            jenkins_home = '/tmp'
        voiceStart = os.path.join(jenkins_home,'scripts','voice_legacy.py')
        cmd = "python -u %s --linux_ip %s --linuxuser %s --linuxpass %s" %(voiceStart,pcta_ip,username,password)
        result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        db_print("\n%s with output:%s" %(cmd,result))
    except Exception as inst:
        db_print("Voice start function failed:%s" %inst)

def processNonFrameCommonOptions(runType,batchCommand,vlanType,vectValue,standalonecaseList,board,LT_check_list):
    #remove PYTHON: or TCL first
    batchCommand = re.sub('^\S+?:','',batchCommand)
    if runType == 'python':
        if vlanType :
            batchCommand += ' --vlan ' + vlanType
        if vectValue :
            batchCommand += ' --vect_type ' + vectValue
        if standalonecaseList:
            batchCommand += ' --testcase ' + ','.join(standalonecaseList)
        if board :
            batchCommand += ' --NT ' + board
        if LT_check_list:
            non_framework_LT=LT_check_list.replace('"',"").strip("]").strip("[").replace(", ",",")
            batchCommand += ' --LT ' + non_framework_LT
    elif runType == 'tcl':
        db_print("As of now,No arguments supported in tcl script")
    return batchCommand

def processNonFrameBatchCommandFinal(batchCommand,**args):
    try:
        vlanType = args.setdefault("vlanType","")
        vectValue = args.setdefault("vectValue","")
        standalonecaseList = args.setdefault("standalonecaseList",'')
        board = args.setdefault("board",'')
        LT_check_list = args.setdefault("LT_check_list",'')
        if batchCommand.find('python') != -1 :
            runType = 'python'
        elif batchCommand.find('tcl') != -1 :
            runType = 'tcl'
        commandList = []
        if runType == 'python' or runType == 'tcl':
            batchCommandList=batchCommand.split(';')
            for i in range(0,len(batchCommandList)):
                batchCommandList[i] = processNonFrameCommonOptions(runType,batchCommandList[i],vlanType,vectValue,standalonecaseList,board,LT_check_list)
            if len(batchCommandList) > 2:
                print 'for more than 1 CLI commands,return CLI command directly without processing'
                commandList = batchCommandList
                return commandList
            for batchCommand in batchCommandList:
                commandList.append(batchCommand)
        return commandList
    except Exception as inst:
        db_print('runType python or tcl keyword is missing in Batchcommand:%s' %inst)
        sys.exit(1)

def runStandaloneBatch(commandList,prerunConfig,linuxIP,userName,passwd,linuxPORT,dbDict={},storeLog=True):
    #jobname = os.environ['JOB_NAME']
    #jobNum = os.environ['BUILD_NUMBER']
    #reportJobInstantStatus(jobname,jobNum,'061')
    team = dbDict.setdefault('team','')
    build_id = dbDict.setdefault('build','')
    result = True
    if commandList[0].find('python') != -1 :
        runType = 'python'
    elif commandList[0].find('tcl') != -1 :
        runType = 'tcl'
    try :
        orig_workspace = os.environ['WORKSPACE']
        job_name = os.environ['JOB_NAME']
        orig_job_name = job_name
        build_url = os.environ['BUILD_URL']
        job_num = os.environ['BUILD_NUMBER']
        build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)
        workspace = re.sub(r'([\(|\)])',r'\\\1',orig_workspace)
    except Exception as inst :
        db_print("this operation can only run on jenkins server as run python script step:%s" %inst)
        return False
    for batchCommand in commandList:
        domainCommand = prerunConfig + ';' + batchCommand if prerunConfig else batchCommand
        if runType == 'python':
            ssh2(linuxIP, userName,passwd, domainCommand,port=int(linuxPORT))
            ##handlerunresult for python scripts
        elif runType == 'tcl':
            domain=''
            platform=job_name
            load = 'ManualLoad'
            ssh2(linuxIP, userName,passwd, domainCommand,port=int(linuxPORT))
            res,timeStamp=handleRunResult(build_id,domain,platform,runType,linuxIP,linuxPORT,userName,passwd,team,'',load,storeLog)
    return result

def GetNonFrameworkScriptList(batchCommand):
    try:
        if batchCommand.find('python') != -1:
            runType = 'python'
        elif batchCommand.find('tcl') != -1:
            runType = 'tcl'
        scriptList = []
        if runType == 'python' or runType == 'tcl':
            batchCommandList=batchCommand.split(';')
            for i in range(0,len(batchCommandList)):
                batchCommandList[i] = re.sub('^\S+?:','',batchCommandList[i])
                testScript=batchCommandList[i].split(" ")[1]
                scriptList.append(testScript)
        return scriptList
    except Exception as inst:
        db_print("Non-framework script fetching error:%s" %inst)


def NonFrameworkProcessKill(linuxIP,userName,passwd,linuxPORT,scriptList):
    try:
        #To retrieve non-framework script pid
        for script in scriptList:
            script_cmd="ps -aef | grep %s | grep -v defunct | grep -v grep | awk '{print $2}'"%script
            pid=ssh2(linuxIP, userName,passwd,script_cmd,'check',port=int(linuxPORT))
            pid=pid.strip()
            for val in pid.split('\n'):
                if val != '':
                    kill_cmd="sudo /bin/kill -9 %s" %val
                    ssh2(linuxIP, userName,passwd,kill_cmd,port=int(linuxPORT))
                else:
                    db_print("Non-framework script ---> %s process id not exists or killed already" %script)
    except Exception as inst:
        db_print("Non-framework script kill error:%s" %inst)

def voice_process_kill(linuxIP,userName,passwd,linuxPORT):
    try:
        #To retrieve start VOICE process pid#
        pcta_cmd_list=["ps -aef | grep callserver_sim  | grep -v defunct | grep -v grep | awk '{print $2}'",\
        "ps -aef | grep mpp  | grep -v defunct | grep -v grep | awk '{print $2}'"]
        for pcta_cmd in pcta_cmd_list:
            pid=ssh2(linuxIP, userName,passwd,pcta_cmd,'check',port=int(linuxPORT))
            pid=pid.strip()
            for val in pid.split('\r\n'):
                if val != '':
                    kill_cmd="sudo /bin/kill -9 %s" %val
                    ssh2(linuxIP, userName,passwd,kill_cmd,port=int(linuxPORT))
    except Exception as inst:
        db_print("VOICE process kill error:%s" %inst)

def GetSimpcList(batchCommand):
    try:
        IPD_list = []
        res1=re.search(r'--ipd1[\s|\b]+?(\d+\.\d+\.\d+\.\d+)',batchCommand)
        if res1:
            IPD1 = res1.group(1)
            IPD_list.append(IPD1)
        res2=re.search(r'--ipd2[\s|\b]+?(\d+\.\d+\.\d+\.\d+)',batchCommand)
        if res2:
            IPD2 = res2.group(1)
            IPD_list.append(IPD2)
    except Exception as inst:
        db_print("Error in fetching SIMPC details:%s" %inst)
    return IPD_list

def ssh_login_check(ip,username,password):
    ssh_flag=False
    try:
        SSH_CMD='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@' %username
        cli = pexpect.spawn(SSH_CMD+ip) 
        cli.maxread = 6000
        cli.timeout = 60
        cli.logfile = sys.stdout    
        i = cli.expect(['password:', r'\(yes\/no\)',r'Connection refused',pexpect.EOF])
        if i == 0:
            cli.sendline(password)
        elif i == 1:
            cli.sendline("yes")
            ret1 = cli.expect(["password:",pexpect.EOF])
            if ret1 == 0:
                cli.sendline(password)
            else:
                pass
        elif i == 2:
            print "Device is not reachable"
        else:
            print "Timeout : Error in SSH connect"
        if cli.expect(["#","incorrect"],timeout=10):
            print('Unable to login')
        else:
            cli.expect([".*#","$"])
            ssh_flag=True
    except Exception as inst:
        print('Failed to Login %s' %inst)
    cli.close()
    return ssh_flag

def reboot_simpc(ip,connectType='TELNET'):
    db_print('#######Reboot SIMPC#######')
    if connectType == 'TELNET':
        cli = pexpect.spawn('telnet %s' % ip)
    else:
        cli = pexpect.spawn('ssh -o GSSAPIAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o KexAlgorithms=diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-dss admin@'+ip)
        #cli = pexpect.spawn('ssh -o HostKeyAlgorithms=+ssh-dss -o KexAlgorithms=diffie-hellman-group14-sha1 admin@'+ip)
    cli.maxread = 6000
    cli.timeout = 60
    cli.logfile = sys.stdout
    try:
        if connectType == 'TELNET':
            cli.expect("Login:")
            cli.sendline("admin")
            cli.expect('Password:')
            cli.sendline("admin")
        else:
            i = cli.expect(['password:', r'\(yes\/no\)',r'Connection refused',pexpect.EOF])
            if i == 0:
                cli.sendline('admin')
            elif i == 1:
                cli.sendline("yes")
                ret1 = cli.expect(["password:",pexpect.EOF])
                if ret1 == 0:
                        cli.sendline("admin")
                else:
                        pass
            elif i == 2:
                print "Device is not reachable"
            else:
                print "Timeout : Error in SSH connect"     
        if cli.expect(["#","incorrect"],timeout=10):
            db_print('Unable to login to SIMPC')
            return False
        else:
            cli.expect([".*#","$"])
            cli.sendline("admin reboot")
            try:
                ret=cli.expect(['Are you sure you want to reboot (y/n)?',pexpect.EOF,pexpect.TIMEOUT])                
                if connectType == 'TELNET':
                    if ret == 0:
                        cli.sendline("y")
                        time.sleep(60)
                        cli.sendline("\r")
                        if cli.expect(["Connection closed"]) == 0:
                            db_print('SIMPC Rebooted successfully')
                            return True
                        else:
                            db_print('SIMPC not rebooted')
                            return False
                    else:
                        db_print("Error in reboot command")
                        return False
                else:
                    if ret == 0:
                        cli.sendline("y")
                        time.sleep(30)
                        cli.close()
                        if not ssh_login_check(ip,'admin','admin'):
                            db_print('SIMPC Rebooted successfully')
                            return True
                        else:
                            db_print('SIMPC Failed to reboot')
                            return False                        
                    else:
                        db_print("Error in reboot command")
                        return False                   
            except:
                db_print('Failed to reboot')
                return False
    except Exception as inst:
        db_print('Failed to Login %s' %inst) 
        return False
    cli.close()

def check_simpctelnet(oam_ip,connectType='TELNET'):    
    systemup = False
    for trytimes in range (0,10):
        if not pingIp(oam_ip):
            db_print('%s simpc is not reachable, waiting longer...' % oam_ip)
            time.sleep(30)
        else:
            systemup = True
            break
    if systemup == False:
        db_print("5mins passed and SIMPC is not reachable")
        sys.exit(1)
    trytimes = 0
    systemup = False
    while trytimes < 10:
        try:
            if connectType == 'TELNET':
                telnetSp = telnetlib.Telnet(oam_ip)
                telnetSp.open(oam_ip, 23)
                systemup = True
                break
            else:
                if ssh_login_check(oam_ip,'admin','admin'):
                    db_print('SIMPC login successfully')
                    systemup = True
                    break
                else:
                    db_print('SIMPC Failed to login')
        except:
            db_print("telnet/SSH SIMPC exception,wait 15s and continue...")
            time.sleep(30)
            trytimes = trytimes + 1
    if systemup == False:
        db_print("5mins passed and can not open telnet/SSH connection to SIMPC")
        sys.exit(1)
    telnetSp.close()
    return systemup

def pingIp(oam_ip):
    ret = os.system('/bin/ping -c 4 %s 2>&1 >/dev/null' % oam_ip)
    if not ret:
        db_print('%s is reachable' % oam_ip)
        return True
    else:
        db_print('%s is not reachable' % oam_ip)
        return False

def check_active(ip,ind):
    db_print('#######Start to check active staus#######')
    cli = pexpect.spawn('telnet %s' % ip)
    cli.maxread = 6000
    cli.timeout = 180
    cli.logfile = sys.stdout
    try:
        cli.expect("login:")
        cli.sendline(Username)
        db_print('#######Use updated password#######')
        cli.expect('password:')
        cli.sendline(passwd)
        try:
            if cli.expect(["#","incorrect"]) != 0:
                raise Exception("login failed")
        except:
            db_print('login with default password...')
            cli.sendline(Username)
            cli.expect('password:')
            cli.sendline(PasswordDefault)
            cli.expect("new password")
            cli.sendline(passwd)
            cli.expect("re-enter")
            db_print('repeat entering new password!')
            cli.sendline(passwd)
            cli.expect(["#","$"])
    except:
        return False
    cli.sendline("show software-mngt oswp %s" % ind)
    ret = cli.expect(["%s.* active " % ind,"%s.* act-stb-nt " % ind,pexpect.EOF,pexpect.TIMEOUT])
    if ret == 0 or ret == 1:
        db_print("Active new oswp pass")
        return True
    else:
        db_print("Active new oswp fail")
        return False
    cli.close()
    
def tnd_cmd(ip,cmd,traceIp=None,tracePort=None):
    global telnetTn
    if traceIp and tracePort:
        cmd = '\"kill %s\"' % craftPort[2:4]  
        os.system('(sleep 1;echo "root";sleep 1;echo "dbps";sleep 1;echo %s;sleep 1;echo "exit";sleep 1) | telnet %s' % (cmd, craftIp))
        telnetTn.open(traceIp, tracePort)
        db_print("Start to login via port server " + traceIp + " " + tracePort)
        Telnet_send("\r", 0)
        returnTmp = telnetTn.read_until(">",15)
        Telnet_send(cmd)
        returnTmp = telnetTn.read_until(">",15)
        Telnet_send("\x1D", 0) 
        returnTmp = telnetTn.read_until(">",15)    
        Telnet_send("quit", 0) 
        telnetTn.close()
        return returnTmp

    db_print('#######Start to logon tnd via octopus#######')
    out = ''
    tnd_ready = False
    tnd = None
    try:
        tnd_spawn = '/var/jenkins_home/scripts/octopus STDIO %s:udp:23' % ip
        db_print(tnd_spawn)
        tnd = pexpect.spawn(tnd_spawn)
        tnd.maxread = 6000
        tnd.timeout = 10
        tnd.logfile = sys.stdout
        tnd.sendline('\n')
        tnd.expect("ogin:")
        tnd.sendline('shell')
        tnd.expect('assword:')
        tnd.sendline('nt\n')
    except Exception as inst:
        db_print('tnd connect failure:%s' % inst)
        return out
    res = tnd.expect(['[\S]+',pexpect.EOF,pexpect.TIMEOUT],5)
    tnd.sendline('\n')
    for i in xrange(0,1):
        try:
            res = tnd.expect(['>',pexpect.EOF,pexpect.TIMEOUT],5)
            print 'res is %s' %res
            print 'tnd before is %s' %tnd.before
            print 'tnd print finish'
            if res == 0:
                db_print('#######log on tnd successfullly#######')
                tnd_ready = True
                break
            elif res == 2:
                if tnd.before.find('>') == -1:
                    tnd_ready = True
                    break
                db_print('wait for 5 seconds so that tnd give > prompt')
                time.sleep(5)
                tnd.sendline('\n')
                continue
            else:
                db_print('close with eof and retry')
                tnd.close()
                break
                #tnd_spawn = '/var/jenkins_home/scripts/octopus STDIO %s:udp:23' % ip
                #db_print(tnd_spawn)
                #tnd = pexpect.spawn(tnd_spawn)
                #tnd.maxread = 6000
                #tnd.timeout = 10
                #tnd.logfile = sys.stdout
                #tnd.sendline('\n')
                #tnd.expect("ogin:")
                #tnd.sendline('shell')
                #tnd.expect('assword:')
                #tnd.sendline('nt')   
        except Exception as inst:
            db_print('tnd logon failure:%s' % inst)            
    if tnd_ready == False:
        db_print('failure to logon tnd, return')
        return out 
    tnd_ready = False
    try:     
        tnd.sendline(cmd)
        for i in xrange(0,1):
            res = tnd.expect(['>',pexpect.EOF,pexpect.TIMEOUT],5)
            #print 'res is %s' %res
            #print 'tnd before is %s' %tnd.before
            #print 'tnd print finish'
            if res == 0:
                db_print('#######tnd execute cmd:%s successfullly#######' %cmd)
                tnd_ready = True
                out = tnd.before
                break
            elif res == 2:
                out += tnd.before
                if not out.find('>') == -1:
                    tnd_ready = True
                    break
                db_print('wait for 5 seconds so that tnd give > prompt')
                time.sleep(5)
                tnd.sendline('\n')
                continue
            else:
                db_print('return directly with eof')    
                break            
            
        #close_cmds= [{'exit':['Logout .* console.*',pexpect.TIMEOUT]},{'\003':['.*octopus.*',pexpect.TIMEOUT]},{'quit':['quit',pexpect.TIMEOUT]}]

        #for elem in close_cmds:
        #    tnd_cmd = elem.keys()[0]
        #    tnd_exp = elem[tnd_cmd]
        #    tnd.sendline(tnd_cmd)
        #    res = tnd.expect(tnd_exp)
        tnd.sendline('exit')
        res=tnd.expect(['Logout .* console.*',pexpect.TIMEOUT])
        print res
        tnd.sendline('\003')
        res=tnd.expect(['.*octopus.*',pexpect.TIMEOUT])
        print res
        tnd.sendline('quit')
        res=tnd.expect(['quit',pexpect.TIMEOUT])
        print res
        if res == 0:
            db_print('logout tnd via octopus successfully')            
    except Exception as inst:
        db_print('tnd cmd :%s failure:%s' %(cmd,inst))
    tnd.close()
    return out

def compareOSWP(shelfIp,product,build,build_type,connectType='TELNET',password='isamcli!'):
    global exp,loginCmd
    build_check=False
    (oswp_version,i2) = build.split('.')
    i1 = oswp_version[0:2]
    newbuild = i1+"."+i2
    if build_type == 'LIS':
        db_print("this version skip for LIS build types")
        return False
    if product in ['SDFX','SDOLT','NCDPU','NBN-4F']:
        db_print("this version skip")
        return False
    db_print('args are:%s:%s' %(shelfIp,password))
    n = 0
    exp = pexpect.spawn(loginCmd[connectType]+shelfIp)
    exp.timeout = 60
    exp.logfile_read = sys.stdout
    if not login(connectType):
        db_print("########################################")
        db_print("Login OAM failed.Please check your ENV")
        db_print("########################################")
    exp.sendline("show software-mngt oswp")
    time.sleep(3)
    try:
        oswp_match = exp.expect(['1\s{5}(.*?)\r\n2\s{5}(.*?)\r\n',pexpect.EOF])
        if oswp_match == 0:
            tmpList = exp.match.groups()
            tmp1 = re.split('[\s|\b]+',tmpList[0])
            tmp2 = re.split('[\s|\b]+',tmpList[1])
            if tmp1[2] == 'active' and tmp1[0] != 'NO_OSWP':
                if tmp2[1] == 'empty' and tmp2[0] == 'NO_OSWP':
                    db_print("oswp 1 is active and oswp 2 is empty")
                    tmp1[0]=tmp1[0].strip()
                    out=re.match('[A-Z|0-9]{6}(\d+\.\d+)',tmp1[0])
                    oswp_exist = out.group(1)
                elif tmp2[1] == 'enabled' and tmp2[0] != 'NO_OSWP':
                    db_print("oswp 1 is active and oswp 2 is not-active")
                    oswp_exist = ""
            if tmp2[2] == 'active' and tmp2[0] != 'NO_OSWP':
                if tmp1[1] == 'empty' and tmp1[0] == 'NO_OSWP':
                    db_print("oswp 2 is active and oswp 1 is empty")
                    tmp2[0]=tmp2[0].strip()
                    out=re.match('[A-Z|0-9]{6}(\d+\.\d+)',tmp2[0])
                    oswp_exist = out.group(1)
                elif tmp1[1] == 'enabled' and tmp1[0] != 'NO_OSWP':
                    db_print("oswp 2 is active and oswp 1 is not-active")
                    oswp_exist = ""
        if oswp_exist == newbuild:
            build_check=True
        else:
            build_check=False
        print oswp_exist + "," + newbuild
        exp.sendline("exit all")
        time.sleep(3)
        exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
        exp.close()
        del exp
    except Exception as inst:
        db_print("Unable to find a match for oswp version :%s" %inst)
        build_check=False
    return build_check

def returnOswpIndex(oswp_info=[]):
    try :
        oswp_idx=''
        if oswp_info[0]['state'] == 'active':
            oswp_idx=oswp_info[0]['index']
        else:
            oswp_idx=oswp_info[1]['index']
        return oswp_idx
    except Exception as inst:
        db_print("Invalid OSWP index :%s!" % str(inst))
        sys.exit(1)

def init_config(server_ip,craftIp, craftPort, oam_ip, initCommands, extraCommands,product,oam_type = '',redund=False,toolOnly=False):
    if product in ['SDFX','SDOLT','NCDPU']:
        return (True,0) 
    jobname = os.environ['JOB_NAME']
    jobNum = os.environ['BUILD_NUMBER']
    if not tool_only:
        reportJobInstantStatus(jobname,jobNum,'004')
    t0 = time.time()
    ret_val = ''
    try:
        localscript = SCRIPT_PATH + '/initConfigFunc.py'
        remotepath = '/tmp/.jenkins'
        remotescript = '/tmp/.jenkins/initConfigFunc.py'
        cmd = "sshpass -p 'alcatel01' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'ls %s'" %(server_ip,remotescript)        
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        if not result.strip() == remotescript :
            cmd = "sshpass -p 'alcatel01' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'mkdir -p /tmp/.jenkins'" %server_ip
            db_print(cmd,'debug')
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
            db_print(cmd,'debug')
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            localscript = SCRIPT_PATH + '/clearConsolePort.py'
            remotescript = '/tmp/.jenkins/clearConsolePort.py'
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
            db_print(cmd,'debug')
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        remotescript = '/tmp/.jenkins/initConfigFunc.py'
        cmd_init = 'python -u %s --server_ip %s --craft_ip %s --craft_port %s --isam_ip %s --command %s --command_extra %s --product %s --oamtype %s --redund %s --toolonly %s' %(remotescript,server_ip,craftIp,craftPort,oam_ip,initCommands,extraCommands,product,oam_type,redund,toolOnly)
        tmp_res=ssh2(server_ip, 'atxuser','alcatel01',cmd_init,'checkandprint')
        print tmp_res
        if tmp_res.find('Initial config is success in ISAM') == -1:
            ret_val=False
        else:
            ret_val=True
        t1 = time.time()
        if not ret_val and not tool_only:
            jobname = os.environ['JOB_NAME']
            jobNum = os.environ['BUILD_NUMBER']
            errorCode = '506'
            reportJobInstantStatus(jobname,jobNum,'004',errorCode)
        return (ret_val, time.localtime(t1 - t0))    
    except Exception as inst:
        db_print("Initialize function failed:%s" %inst)
        t1 = time.time()
        return (False, time.localtime(t1 - t0))

def prepareOSWP_NBN4F(build,oam_ip,ftpserver,linuxIP,linuxUser,linuxPasswd,linuxPORT,site,csv,toolOnly=False):
    jobname = os.environ['JOB_NAME']
    jobNum = os.environ['BUILD_NUMBER']
    if not toolOnly:
        reportJobInstantStatus(jobname,jobNum,'001')
    t0 = time.time()
    ret_val = ''
    try:
        db_print('put sw_update_nbn4f.py for NBN_4F to PCTA')
        localscript = SCRIPT_PATH + '/sw_update_nbn4f.py'
        remotepath = '/tmp/.jenkins'
        remotescript = '/tmp/.jenkins/sw_update_nbn4f.py'
        cmd = 'cksum %s' %localscript
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        new_cksum = result.strip().split(' ')[0]
        db_print('cksum:%s' %new_cksum)
        cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'cksum %s'" %(linuxPasswd,linuxUser,linuxIP,remotescript)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        old_cksum = result.strip().split(' ')[0]
        db_print('cksum:%s' %old_cksum)
        result=''
        if new_cksum and not old_cksum == new_cksum :
            localscript = SCRIPT_PATH + '/sw_update_nbn4f.py'
            remotescript = '/tmp/.jenkins/sw_update_nbn4f.py'
            cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'mkdir -p /tmp/.jenkins'" %(linuxPasswd,linuxUser,linuxIP)
            db_print(cmd,'debug')
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s %s@%s:%s" %(linuxPasswd,localscript,linuxUser,linuxIP,remotepath)
            db_print(cmd,'debug')
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'chmod -R +x %s'" %(linuxPasswd,linuxUser,linuxIP,remotepath)
        db_print(cmd,'debug')
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        new_build="lightspan-omci_"+build+".tar"
        if csv:
            cmd_init = 'python -u %s --ip %s --logDirectory %s --build %s --ftpserver %s --Site %s --csv %s' %(remotescript,oam_ip,remotepath,new_build,ftpserver,site,csv)
        else:
            cmd_init = 'python -u %s --ip %s --logDirectory %s --build %s --ftpserver %s --Site %s' %(remotescript,oam_ip,remotepath,new_build,ftpserver,site)
        tmp_res=ssh2(linuxIP,linuxUser,linuxPasswd,cmd_init,'check')
        print tmp_res
        if tmp_res.find('Prepare build file successfully') == -1:
            ret_val=False
        else:
            ret_val=True
        t1 = time.time()
        if not ret_val and not tool_only:
            jobname = os.environ['JOB_NAME']
            jobNum = os.environ['BUILD_NUMBER']
            errorCode = '501'
            reportJobInstantStatus(jobname,jobNum,'001',errorCode)
        return (ret_val, time.localtime(t1 - t0))
    except Exception as inst:
        db_print("Prepare build file failed for NBN_4F setup:%s" %inst)
        t1 = time.time()
        return (False, time.localtime(t1 - t0))

def CheckLogMovement():
  try :
      build_url = os.environ['BUILD_URL']
      build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)
  except Exception as inst:
      db_print('Failed in access jenkins URL:%s' %inst)
      return False,''
  try:
      cmd = "curl -s %sconsoleText |grep -o -a -E 'Moving [[:graph:]]+(root|atxuser)-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[0-9]{8} to (.*) in /storage success...'|uniq |tail -1" %build_url
      result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
      result = result.strip()
      if not result:
          db_print("Logs not moved to /storage")
          return False,''
      res_match = re.search('/storage success...',result)
      if res_match:
          db_print("Logs moved to /storage successfully")
          try:
              cmd1 = "curl -s %sconsoleText |grep -o -a -E '(Creating|Updating) [[:graph:]]+(root|atxuser)-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[0-9]{8} directory'|uniq |tail -1" %build_url
              result1=subprocess.Popen(cmd1, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
              result1 = result1.strip()
              if not result1:
                  return False,''
              timeStamp = result1.split(' ')[1].strip()
              return True,timeStamp
          except Exception as inst:
              db_print('Failed to get timestamp:%s' %inst)
              return False,''
  except Exception as inst:
      db_print('Failed to check Logs moved to /storage directory:%s' %inst)
      return False,''

def Delete_timestamp_PCTA(linuxIP,linuxUser,linuxPasswd,timestamp,linuxPORT='22'):
  dir_flag = True
  destDir=timestamp
  ####To check directory exists or not####
  cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'ls -d %s'" %(linuxPasswd,linuxUser,linuxIP,destDir)
  result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
  if result == "":
      print "%s directory not available" %destDir
      print "Skip Delete %s Directory" %destDir
  else:
      print "%s directory already available" %destDir
      cmd1="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'rm -rf %s'" %(linuxPasswd,linuxUser,linuxIP,destDir)
      try:
          result=subprocess.Popen(cmd1, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
          print "%s Directory deleted" %destDir
      except:
          db_print("Unable to Delete directory")
          dir_flag = False
  return dir_flag
  
def clean_lis_dir_process_pcta(linuxIP,linuxUser,linuxPasswd,timestamp,linuxPORT='22'):
    res = True
    ####To check directory exists or not####
    aScript = 'launchTestBatch.' + timestamp
    cmd1="ps -aef | grep %s | grep -v grep | awk '{print $2}' | tr -s '\n' |xargs kill -9" %aScript
    cmd1="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s '%s'" %(linuxPasswd,linuxUser,linuxIP,aScript)
    try:
        result=subprocess.Popen(cmd1, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        print "%s process killed" %aScript
    except:
        db_print("Unable to kill process")
        res=False
    cmd1="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'rm -rf %s'" %(linuxPasswd,linuxUser,linuxIP,aScript)
    try:
        result=subprocess.Popen(cmd1, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        print "%s Directory deleted" %aScript
    except:
        db_print("Unable to Delete directory")
        res=False
    return res

def _get1stsetupfile(batchCommand):
    csvlist = []
    for ltbCommand in batchCommand.split(';'):
        res = re.search(r'-V[\s|\t]([\S]+)',ltbCommand)
        if res:
            voption = res.group(1)
            csv = voption.split(':')[-1]
            if csv.endswith('.csv') or csv.endswith('.yaml') or csv.endswith('.yml'):
                csvlist.append(csv)
    return ','.join(csvlist)

def restore_file_pcta(linuxIP,linuxUser,linuxPasswd,aFile,linuxPORT='22'):
    res = True
    if not aFile:
        return True
    tmpFile = aFile + '.bak'
    cmd1="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s 'cp -rf %s %s'" %(linuxPasswd,linuxUser,linuxIP,tmpFile,aFile)
    try:
        result=subprocess.Popen(cmd1, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        print "copy %s back to %s" %(tmpFile,aFile)
    except Exception as inst:
        db_print("copy %s back to %s with exception:%s" %(tmpFile,aFile,inst))
        res=False
    return res

if __name__ == '__main__':
    SCRIPT_PATH = os.path.split(os.path.realpath(__file__))[0]
    parser = ArgumentParser()
    parser.add_argument("-i","--ip", dest="oam_ip",default='', help="Oam ip (eg. 135.252.245.137)")
    parser.add_argument("--gw", dest="oam_gw", default='',help="Gw ip of Oam")
    parser.add_argument("--prefix", dest="oam_prefix",default='24', help="Prefix of oam ip")
    parser.add_argument("--craftIp", dest="craftIp",default='', help="Port server ip")
    parser.add_argument("--craftPort", dest="craftPort",default='', help="Port server port")
    parser.add_argument("--oamPort", dest="oam_port",default='nt-a:eth:1', help="OAM IP Config Port")
    parser.add_argument("--speedCheck", dest="speedCheck",default='', help="Whether to check max sys speed before download")
    parser.add_argument("--build", dest="build",default="", help="Build version")
    parser.add_argument("--passwd", dest="passwd",default="isamcli!", help="password of Oam")
    parser.add_argument("--dbMode", dest="dbMode",default='default', help="active with DB mode(eg. default/linked)")
    parser.add_argument("--dbBackup", dest="dbBackup",default="false", help="DB backup(eg. True/False)")
    parser.add_argument("--dbServer", dest="dbServer",default="", help="DB backup Server(eg. 135.251.206.149)")
    parser.add_argument("--timeCheck", dest="timeCheck",default=False, help="OSWP download and active time record(eg. True/False)")
    parser.add_argument("--killLTB", dest="killLTB",default=False, help="kill LTB process before atc testing(eg. True/False)")
    parser.add_argument("--action", dest="action",default='', help="action (eg. prepareOSWP/downloadOSWP/activateOSWP,etc)")
    parser.add_argument("--buildServer", dest="buildServer",default='', help="action (eg. 135.251.206.97,etc)")
    parser.add_argument("--ftpServer", dest="ftpServer",default='', help="action (eg. 135.251.206.69)")
    parser.add_argument("--loadinfo", dest="loadinfo",default='', help="noload or ''")
    parser.add_argument("--batchCommand", dest="batchCommand",default='', help="launchTestbatch,etc")
    parser.add_argument("--prerunConfig", dest="prerunConfig",default='', help="export DISPLAY=1.0,etc")
    parser.add_argument("--linuxPORT", dest="linuxPORT",default='22', help="ssh port of linux machine")
    parser.add_argument("--linuxIP", dest="linuxIP",default='', help="ip of machine to run LTB")
    parser.add_argument("--suiteRerun", dest="suiteRerun",default='', help="rerun robot cases after 1st run")
    parser.add_argument("--release", dest="release",default='', help="rerun robot cases after 1st run")
    parser.add_argument("--testRun", dest="testRun",default='', help="whether to run ATC or not")
    parser.add_argument("--domain", dest="domain",default='', help="domainlist")
    parser.add_argument("--domainSplit", dest="domainSplit",default='', help="run batch for each domain one by one")
    parser.add_argument("--defaultDB", dest="defaultDB",default='', help="when domainSplit set True,also want to clean DB after each LTB run")
    parser.add_argument("--robotOptions", dest="robotOptions",default='', help="pass extra robot variable such as LT:FWLT-A")
    parser.add_argument("--platformType", dest="platformType",default='GPON', help="GPON or other")
    parser.add_argument("--coverage", dest="coverage",default='', help="GPON or other")
    parser.add_argument("--robotCaseList", dest="robotCaseList",default='', help="GPON or other")
    parser.add_argument("--updateRepo", dest="updateRepo",default='', help="whether to update repo on PCTA")
    parser.add_argument("--debug", dest="debug",action="store_true",default=False, help="used by dev only to debug this script")
    parser.add_argument("--extraTar", dest="extraTar",default='', help="used to pass -K /tftpboot/atx/loads/5601.472.extra.tar")
    parser.add_argument("--netconfLinuxPort", dest="NetLinuxPort", default=2222,type=int, help="netconf port of Linux")
    parser.add_argument("--netconfOamPort", dest="NetOamPort", default=830,type=int, help="netconf port of Oam")
    parser.add_argument("--index_file", dest="file_index", default='AH', help="index file like AH")
    parser.add_argument("--host", dest="hostFlag", default='target', help="index file like AH")
    parser.add_argument("--cs_tag", dest="cs_tag",default='NONE', help="update repo by CS info")
    parser.add_argument("--extraOptions", dest="ExtraOptions",default='', help="pass extra variable such as NT TYPE NT-A:NANT-A")
    options = parser.parse_args()
    for key in options.__dict__.keys():
        if type(options.__dict__[key]) == 'str':
            options.__dict__[key] = options.__dict__[key].lstrip("'").rstrip("'")
        #print options.__dict__[key]
    HOST = 'ftp:135.251.206.97:/ftpserver/loads:asblab:asblab' if not options.buildServer else options.buildServer
    if BUILD_SOURCE_REPLACEMENT and HOST in BUILD_SOURCE_REPLACEMENT:
        HOST = BUILD_SOURCE_REPLACEMENT[HOST]
    #DIRN = '/ftp'
    #DIRN = '/loads'
    ver2 = ''
    #DIRN = '/ftpserver/loads'
    ProposalBuildFlag = False
    OswpCheckFlag = False
    SERVER_IP = TFTP_SERVER_IP if not options.ftpServer else options.ftpServer
    platformType = options.platformType
    print platformType
    action = options.action
    oam_ip = options.oam_ip
    craftIp = options.craftIp
    oam_gw = options.oam_gw
    build = options.build
    if checkProposalbuild(build):
        ProposalBuildFlag = True
    NetLinuxPort = options.NetLinuxPort
    NetOamPort = options.NetOamPort
    coverage = options.coverage
    release = options.release
    robotCaseList = options.robotCaseList.strip("''").strip()
    robotCaseList = '' if robotCaseList.lower() == 'none' else robotCaseList
    if not release:
        release = build.split(".")[0]
        if len(release) >= 3:
            release = release[0] + '.' + release[1] + '.' + release[2:]
        else:
            release = release[0] + '.' + release[1:]
    passwd = options.passwd
    dbMode = options.dbMode
    dbBackup = options.dbBackup
    dbServer = options.dbServer
    timeCheck = options.timeCheck
    defaultDB = options.defaultDB
    craftPort = options.craftPort
    cs_num = options.cs_tag	

    killLTB = options.killLTB
    suiteRerun = options.suiteRerun
#   using suiteRerun temporarily for rerunFailed
    if suiteRerun == 'true':
        failRerun = True
        suiteRerun = False
    else:
        failRerun = False
    updateRepo = options.updateRepo
    file_index = options.file_index

    ExtraOptions = ''  if options.ExtraOptions.lower() == 'none' else options.ExtraOptions
    #print options.ExtraOptions
    #print "printed extra options"		
    oam_port = options.oam_port
    ExtraOptions=options.ExtraOptions
#moved to buildUtility
#    metrics_user = ''
#    board = ''
#    trace_server_list = []
#    LT_check_list = []
    standalonecaseList = []
    standalonescriptList = []
    Simpc_ip_list = []

#upgrade related
    upgradeDict=extractExtraOptions(ExtraOptions,ProposalBuildFlag)
    repoInfo = upgradeDict.get('repoInfo',{})
    purgeRepo = upgradeDict.get('purgeRepo',False)
    SWMgmt = upgradeDict.get('SWMgmt',False)
    #db_print(str(upgradeDict))
    LTCheck = upgradeDict.get('LTCheck',False)
    LTSWCheck = upgradeDict.get('LTSWCheck',False)
    #'saveTrace', 'caseMode', 'domainMode', 'LTCheck', 'LTSWCheck','redund'
    redund  = upgradeDict.get('redund',False)
    LT_check_list  = upgradeDict.get('ltCheckList',[])
    LT_Dict = upgradeDict.get('ltDict',[])
    board= upgradeDict.get('board','')
    oam_type = upgradeDict.get('oamType','')
    connectType = upgradeDict.get('connectType','TELNET')
#other parameters
    metrics_user = upgradeDict.get('metricUser','')
    Team = upgradeDict.get('Team','Other')
    Site = upgradeDict.get('Site','Other')
    update_build = upgradeDict.get('updateBuild','')
    saveTrace = upgradeDict.get('saveTrace',False)
    #caseMode and domainMode changed to be bool now
    caseMode = upgradeDict.get('caseMode',False)
    #if 'skip_ATCs' in caseMode:
    #    caseMode = 'EXC'
    #else:
    #    caseMode = 'INC'
    if caseMode:
        caseMode = 'INC'
    else:
        caseMode = 'EXC'
    domainMode = upgradeDict.get('domainMode',False)
    #if 'exclude_domain' in domainMode:
    #    domainMode = 'EXC'
    #else:
    #    domainMode = 'INC'
    if domainMode:
        domainMode = 'INC'
    else:
        domainMode = 'EXC'

    vlanType = upgradeDict.get('fwdVlanMode','')
    vectValue = upgradeDict.get('vectorType','')
    batch_type = upgradeDict.get('batchType','')

    standalonecaseList=upgradeDict.get('NonFwCaseList','')
    if standalonecaseList:
        standalonecaseList = standalonecaseList.split(',')
    else:
        standalonecaseList = []
    linuxPctaexe = ''
    PCTA=upgradeDict.get('PCTA','')
    if PCTA:
        pctaServer = PCTA.strip().split(':')
        pctaIPaddr=pctaServer[0]
        pctaPORT = pctaServer[1] if len(pctaServer) > 1 else '22'
        try:
            pctaUser = pctaServer[2]
            pctaPasswd = pctaServer[3]
        except Exception as inst:
            pctaUser = 'atxuser'
            pctaPasswd = 'alcatel01'
            linuxPctaexe = ''
        if len(pctaServer) == 5:
            linuxPctaexe = pctaServer[4]
    else:
        linuxPctaexe = ''
        pctaIPaddr = 'NONE'

    STC=upgradeDict.get('STC','')
    STCServer = ''
    stcVersion = ''      
    stcNetport = ''
    stcCliport = ''
    stcIP = ''
    try:
        STCIpPort = STC.strip().split(':')
        stcIP = STCIpPort[0]   
        if len(STCIpPort) >= 5:
            if 'network' in STCIpPort[1]:
                stcNetport = STCIpPort[2]
            else:
                stcNetport = ''
            if 'client' in STCIpPort[3]:
                stcCliport = STCIpPort[4]
            else:
                stcCliport = ''
            if len(STCIpPort) > 5:
                if STCIpPort[5] == 'version':
                    stcVersion = STCIpPort[6]
                else:
                    stcVersion = ''
            else:
                stcVersion = ''
        elif len(STCIpPort) == 1:
            stcNetport = ''
            stcCliport = ''
            stcVersion = ''
        if stcIP and stcNetport and stcCliport:
            STCServer = ":".join(['STC',stcIP,'networkport',stcNetport,'clientport',stcCliport])
        else:
            STCServer = ''
    except Exception as inst:
        db_print("handle STC information with exception:%s" %inst)
    
    db_print('PCTA:%s' %pctaIPaddr)      
    db_print('STC:%s' %STCServer)     

    avBuild = {'updatePlugin':False,'updateAV':False,'avVersion':''}
    avBuild['updatePlugin'] = upgradeDict.get('updatePlugin',False)
    avBuild['updateAV'] = upgradeDict.get('updateAV',False)
    avBuild['avVersion'] = upgradeDict.get('avVersion','')
    #fallback to old logic before chenlins delivery
    """
    #try:
    #    if ExtraOptions:
    #        extradict=dict(item.split(":") for item in ExtraOptions.split(","))
    #        #'BOARD' is not handled ,must keep here temporarily
    #        if 'BOARD' in extradict:
    #            oam_type=extradict['BOARD'].strip()
    #            board = oam_type.lower()
    #    else:
    #        pass
    #except Exception as inst:
    #    pass
    """
    #try:
    #    if ExtraOptions:
    #        extradict=dict(item.split(":") for item in ExtraOptions.split(","))
    #        #'BOARD' is not handled ,must keep here temporarily
    #        if 'BOARD' in extradict:
    #            oam_type=extradict['BOARD'].strip()
    #            board = oam_type.lower()
    #    else:
    #        pass
    #except Exception as inst:
    #    pass

    ###Create LIS directory
    #for legacy ,use LIS_DIR,for moswa ,use MOSWA_OSWP_NAME and MOSWA_OSWP_URL
    ntimestamp=''
    LIS_DIR = ''
    MOSWA_OSWP_NAME=''
    MOSWA_OSWP_URL = ''
    build_type=upgradeDict.get('buildType','LIS')
    official_build_src_list = ['135.251.206.97',\
                          '172.21.128.21',\
                          'SFTP:135.249.31.144:/tftpboot/atx/loads',\
                          'aww.dsl.alcatel.be/ftp/pub/outgoing/ESAM',\
                          ':aww.dsl.alcatel.be/ftp/pub/outgoing/ESAM/DAILY:',
                          'SFTP:135.252.28.167:/ftpserver/loads']
    if not build_type == 'LIS':
        build_src_check = False
        for build_src in official_build_src_list:
            if not HOST.find(build_src) == -1:
               build_src_check = True 
        if not build_src_check:
            build_type = 'LIS'
    
    #privateNetwork = True if dutList[0].get('DutOamIP','').startswith('192.') else False
    privateNetwork = upgradeDict.get('Inband',False)
    if privateNetwork:
        build_type = 'LIS'
            
    if build_type == 'LIS':
        timestamp=time.strftime('%b%d%H%M%S',time.localtime())
        ntimestamp = oam_ip + '_' + timestamp
        LIS_DIR = '/tftpboot' + '/' + ntimestamp
    if oam_port:
        res = re.findall(':',oam_port)
        if len(res) == 1:
            if oam_port.split(":")[0] == "network":
                db_print('oam port is 0')
            else:
                oam_port = 'nt-a:' + oam_port
    loadinfo = options.loadinfo
    loadinfo = loadinfo.lower()
    batchCommand = options.batchCommand
    linuxIpPort = options.linuxIP.strip().split(':')
    linuxIP = linuxIpPort[0]
    try:
        if ipaddress.ip_address(unicode(linuxIP)).is_private or re.match(r'135.249.11',linuxIP):
            LOG_SERVER={'FQDN':'http://smartlab-service.int.net.nokia.com:9000/log','IP':'135.251.206.149','HTTP':'http://10.131.213.53:9000/log'}
    except Exception as inst:
        db_print('Error :%s' % inst)
    linuxPORT = linuxIpPort[1] if len(linuxIpPort) > 1 else '22'
    #linuxPctaexe = ''
    try:
        linuxUser = linuxIpPort[2]
        linuxPasswd = linuxIpPort[3]
    except Exception as inst:
        linuxUser = 'atxuser'
        linuxPasswd = 'alcatel01'
        #linuxPctaexe = ''
    #if len(linuxIpPort) == 5:
    #    linuxPctaexe = linuxIpPort[4]
    if options.debug:
        storeLog = False
    else:
        storeLog = True
    prerunConfig = options.prerunConfig
    testRun = options.testRun
    domain = options.domain
    tmpDomain = domain.split(',')
    try:
        tmpDomain.remove('NONE')
    except:
        pass
    try:
        tmpDomain.remove('NONE:selected')
    except:
        pass
    try:
        tmpDomain.remove('None')
    except:
        pass
    domain = ','.join(tmpDomain)
    domainSplit = options.domainSplit
    robotOptions = '' if options.robotOptions.lower() == 'none' else options.robotOptions

    #oam_port = "nt-a:eth:1"
    Username = "isadmin" 
    Password1 = "isamcli!" 
    Password2 = "      " 
    PasswordDefault = "i$@mad-"

    extraTar = True if options.extraTar == 'true' else False
    extraTarDir = '/tftpboot/atx/loads'
    #extraTar = options.extraTar
    hostFlag = True if options.hostFlag.lower() == 'host' else False
    #for debug only
    debugOnly = options.debug

    tool_only = False
    if action == 'upgradeDUT':
        tool_only = True
        
    envList = filter(lambda x: re.search(r'export[^=]+=.+',x),prerunConfig.split(';'))
    envOverriden={'HOME':'~','PROGRESS_LINK':'','REPO':'','MOSWAREPO':'','ROBOTREPO':'','DEVTOOLREPO':'','ANSI':''}

    try:
        for item in envOverriden:
            for envItem in envList:
                kvp = envItem.replace('export ','').split('=')
                if item == kvp[0].strip():
                    envOverriden[item] = kvp[1]
                    break
    except Exception as inst:
        db_print("envOverriden with exception:%s" %inst)

    try :
        job_name = os.environ['JOB_NAME'] 
        if not job_name.find('SF8') == -1 or not job_name.find('DF16') == -1:
            platfromType = 'REBORN'
        #ftp:135.251.206.97:/ftpserver/loads:asblab:asblab
        #HOST = _workaround_ftp_moswa(HOST,job_name,build)
            
    except Exception as inst:
        db_print('pls run on jenkins so that JOB_NAME can be got')
        platformType = 'GPON'
    if platformType in ['nothing','',None]:
        platformType = 'GPON'
    elif 'SDDF' in platformType:
        platformType = 'SDOLT'
    elif 'SDMF' in platformType:
        platformType = 'SDFX'
    else:
        pass    
    initCommands = []
    product = platformType
    multidut = upgradeDict.get('multiDut','')
    #db_print(str(multidut))
    dutList = getDutInfo(multidut)
    #db_print(str(dutList))
    if not hostFlag and len(dutList) < 1:
        db_print("wrong shelf info")
        sys.exit(1)

    ##Add traceServer
    trace_server_list=[]
    try:
        for dut in dutList:
            trace_server_list += dut["traceServerList"]
    except Exception as inst:
        db_print("No trace server available")
    db_print("Trace server list : %s"%trace_server_list)
    #fo privateNetwork or NBN-4F,will put scripts to pcta to do upgrade
    if privateNetwork or platformType == 'NBN-4F':
        (tftpserverIp,tftpserverPort,tftpserverUser,tftpserverPasswd) = (linuxIP,linuxPORT,linuxUser,linuxPasswd)
    else:
        (tftpserverIp,tftpserverPort,tftpserverUser,tftpserverPasswd) = (SERVER_IP,'22','atxuser','alcatel01')
    tftpserverInfo = ':'.join((tftpserverIp,tftpserverPort,tftpserverUser,tftpserverPasswd,'/tftpboot'))
    ##Add moswaList
    MOSWA_DICT=getMoswaDict(build,tftpserverInfo,HOST,product,build_type,LIS_DIR,ntimestamp)
    buildinfo = {}
    #handle getAvailableBuild in buildhandling
    buildinfo['buildSource']=HOST
    if action == 'prepareOSWP':
        jks_build_id =os.environ['BuildID']
        if not jks_build_id or jks_build_id == 'latest':
            bServerL=HOST.split(':')
            buildip=getAvailableBuild(bServerL,release,build,RELEASE_MAP,hostFlag,product)
            buildinfo['buildSource']=buildip
            db_print("change build server to be:%s" %buildip)
    buildinfo['buildAgent']=tftpserverInfo
    if action == 'getLatestBuild' or action == 'prepareOSWP':
        buildinfo['buildID']=build
    else:
        buildinfo['buildID']=release.replace('.','') + '.' + build.split('.')[-1]
        build = buildinfo['buildID']
    buildinfo['buildID']=build
    buildinfo['buildType']=build_type
    buildinfo['moswaDict']=MOSWA_DICT
    buildinfo['buildRelease']=release
    cmdLocation = {}
    cmdLocation['linuxIP'] = linuxIP
    cmdLocation['linuxUser'] = linuxUser
    cmdLocation['linuxPasswd'] = linuxPasswd
    cmdLocation['linuxPORT'] = linuxPORT
    buildInstance = BUILD(buildinfo)
    dutInstanceList = []
    firstUpgradeDut = False
    for dutTest in dutList:
        #for currently implementation, product, connectType, redund is platform level instead of shelf level
        dutTest['product'] = product
        dutTest['connectType'] = connectType
        dutTest['redund'] = redund
        #wrap site info for each dut, since used by nbn4f
        if product == "NBN-4F":
            dutInstance = nbn4fDUT(dutTest)
            if not firstUpgradeDut  and dutTest.get('Upgrade',True):
                firstUpgradeDut = True
                oam_ip = dutTest.get('DutOamIP','')
        elif product in ['NCDPU','SDFX','SDOLT']:
            dutInstance = moswaDUT(dutTest)
            dutInstance.setMoswaList(buildInstance=buildInstance,logLocation=cmdLocation)
            extraTar = True
        else:
            dutInstance = snmpDUT(dutTest)
        dutInstanceList.append(dutInstance)
    if product in ['NCDPU','SDFX','SDOLT'] and dutInstanceList:
        #put dut level port/transmode info into buildInstance for prepareOswp
        putMoswaDict(buildInstance,dutInstanceList[0])
        
    dbDict = {}
    dbDict['dutInstanceList'] = dutInstanceList
    dbDict['buildInstance'] = buildInstance
    dbDict['cmdLocation'] = cmdLocation
    dbDict['oam_ip']=oam_ip
    dbDict['craftPort']=craftPort
    dbDict['craftIp']=craftIp
    dbDict['dbMode']=dbMode
    dbDict['defaultDB']=defaultDB
    dbDict['SCRIPT_PATH']=SCRIPT_PATH
    dbDict['dbBackup']=dbBackup
    dbDict['dbServer']=dbServer
    dbDict['product'] = platformType
    dbDict['oam_type'] = oam_type
    dbDict['redund'] = redund
    dbDict['connectType'] = connectType
    dbDict['SERVER_IP'] = tftpserverIp
    dbDict['failRerun'] = failRerun
    dbDict['build']=build

    if oam_ip and craftIp and oam_gw:
        oam_ip_prefix = options.oam_ip + "/" + options.oam_prefix
        if oam_type == 'NANT-A':
            initCommands = [
            "configure system management host-ip-address manual:"+oam_ip_prefix,
            "configure system management default-route "+oam_gw,
            "configure interface shub port 0 port-type network",
            "configure interface shub port 0 admin-status auto-up",
            "configure vlan shub id 4093 egress-port "+oam_port,
            "configure vlan shub id 4093 untag-port "+oam_port,
            "configure bridge shub port 0 pvid 4093",
            "admin software-mngt shub database save",
            "exit all",
            ]
        elif oam_type == 'NRNT-A' or oam_type == 'AGNT-A':
            initCommands = [
            "configure system management host-ip-address manual:"+oam_ip_prefix,
            "configure system management default-route "+oam_gw,
            "configure interface shub port "+oam_port+" port-type network",
            "configure interface shub port "+oam_port+" admin-status auto-up",
            "configure vlan shub id 4093 egress-port "+oam_port,
            "configure vlan shub id 4093 untag-port "+oam_port,
            "configure bridge shub port "+oam_port+" pvid 4093",
            "admin software-mngt shub database save",
            "exit all",
            ]
        elif oam_type == 'CFNT-C' or oam_type == 'CFNT-D' or oam_type == 'CFNT-B':
            initCommands = ["configure system management no default-route"]
            #for DF16, outband not supported
            if not oam_type == 'CFNT-B':
                initCommands.append("configure system mgnt-vlan-mode outband")
            initCommands.append("configure system management host-ip-address manual:"+oam_ip_prefix)
            initCommands.append("configure system management default-route "+oam_gw)
            initCommands.append("configure system management default-ttl 64")
            initCommands.append("exit all")
        else:
            initCommands = [
            "configure port " + oam_port + " no shutdown",
            "configure service ies 2 customer 1 create",
            "configure service ies 2 interface OAM create",
            "configure service ies 2 interface OAM address "+oam_ip_prefix,
            "configure router static-route 0.0.0.0/0 next-hop "+oam_gw,
            "configure service ies 2 interface OAM sap nt:vp:1:4091 create",
            "configure service ies 2  no shutdown",
            "configure service vpls 3 customer 1 v-vpls vlan 4091 create",
            "configure service vpls 3  sap "+oam_port+":0 create",
            "configure service vpls 3 no shutdown",
            "admin save",
            "admin software-mngt ihub database save-protected",
            ]    
        dbDict['initCommands'] = initCommands
    #print 'initCommands is'
    #print initCommands
    #telnetTn = telnetlib.Telnet() 
    #tndTn = telnetlib.Telnet()
    buildRelease = build.split('.')[0]
    batchDict = {'release':release, \
                'suiteRerun':suiteRerun, \
                'domain':domain, \
                'domainSplit':domainSplit, \
                'testRun':testRun, \
                'build':build, \
                'robotOptions':robotOptions, \
                'coverage':coverage, \
                'robotCaseList':robotCaseList, \
                'oamIP':oam_ip, \
                'hostFlag':hostFlag, \
                'caseMode':caseMode, \
                'domainMode':domainMode, \
                'avBuild':avBuild,\
                'product':platformType}
    batchDictStandalone = {'vlanType':vlanType, \
                          'vectValue':vectValue, \
                          'standalonecaseList':standalonecaseList, \
                          'board':board, \
                          'LT_check_list':LT_check_list}
    batchDict['loadinfo'] = loadinfo
    if re.search('/ATX/bin/atx',batchCommand):
        batchDict['updateRepo'] = updateRepo
    #for host only
    if action == 'runBatch':
        if hostFlag:
            db_print('############run host batch################################')
            infoDic=json.loads(ExtraOptions)
            batchForHost=','.join(infoDic.get('Batches',[]))
            boards=','.join(infoDic.get('Boards',[]))
            hostATCOnCloud=infoDic.get('hostATCOnCloud',True)
            PlatformNameForHost=infoDic.get('Platform','')
            buildHost=options.build
            logServerIp=LOG_SERVER['IP']
            logServerUser=LOG_SERVER['USER']
            logServerPwd=LOG_SERVER['PWD']
            logServerDirectory=LOG_SERVER['LOG_PATH']
            if options.buildServer:
                buildResult=options.buildServer
            else:
                buildResult=''
            HOSTBATCH=BUILDDICT['HOSTBATCH']
            batchHostIP=HOSTBATCH['IP']
            batchHostUser=HOSTBATCH['USER']
            batchHostPWD=HOSTBATCH['PWD']
            batchHostRobotPath=HOSTBATCH['ROBOT_PATH']
            userName=infoDic.get('userName','')
            #passWord=infoDic.get('passWord','')
            if userName:
                displayName=userName+'_SmartLabService'
            else:
                displayName=''
            remoteIpForHost=infoDic.get('remoteIpForHost','')
            remoteUserForHost=infoDic.get('remoteUserForHost','')
            remotePwdForHost=infoDic.get('remotePwdForHost','')
            remoteClickTestBinPath=infoDic.get('remoteClickTestBinPath','')
            FRAMEWORK=infoDic.get('FRAMEWORK','')
            TIMESTAMP=infoDic.get('TIMESTAMP','')
            DEVTOOLS_REV=infoDic.get('DEVTOOLS_REV','')
            ATC_REV=infoDic.get('ATC_REV','')
            ROBOT_REV=infoDic.get('ROBOT_REV','')
            TEST_PACKAGES_REV=infoDic.get('TEST_PACKAGES_REV','')
            CS=infoDic.get('CS','')
            SUPPRESSED_TESTBATCHES=infoDic.get('SUPPRESSED_TESTBATCHES','')
            SUSPENDED_TESTBATCHES=infoDic.get('SUSPENDED_TESTBATCHES','')
            REGRESSION_MODE_RUN=infoDic.get('REGRESSION_MODE_RUN','')
            RERUN_TESTBATCHES=infoDic.get('RERUN_TESTBATCHES','')
            TAGS=infoDic.get('TAGS','')
            build_ip=infoDic.get('build_ip','')
            build_port=infoDic.get('build_port','')
            build_user=infoDic.get('build_user','')
            build_passwd=infoDic.get('build_passwd','')
            robot_repo=infoDic.get('robot_repo','')
            area_coverage=infoDic.get('area_coverage',False)

            launchHostOptions={'display_user':displayName,'boards':boards,'Batch':batchForHost,'CSL':userName,'buildResults':buildResult,'release':release,
            'buildID':buildHost,'Platform':PlatformNameForHost,'logServerIp':logServerIp,'logServerUser':logServerUser,'logServerPwd':logServerPwd,'logServerDirectory':logServerDirectory,
            'host_ATC_on_cloud':hostATCOnCloud,'batchHostIP':batchHostIP,'batchHostUser':batchHostUser,'batchHostPWD':batchHostPWD,'batchHostRobotPath':batchHostRobotPath,'remoteIp':remoteIpForHost,
            'remoteUsername':remoteUserForHost,'remotePasswd':remotePwdForHost,'binPath':remoteClickTestBinPath,'FRAMEWORK':FRAMEWORK,'TIMESTAMP':TIMESTAMP,'DEVTOOLS_REV':DEVTOOLS_REV,
            'ATC_REV':ATC_REV,'ROBOT_REV':ROBOT_REV,'TEST_PACKAGES_REV':TEST_PACKAGES_REV,'CS':CS,'SUPPRESSED_TESTBATCHES':SUPPRESSED_TESTBATCHES,'SUSPENDED_TESTBATCHES':SUSPENDED_TESTBATCHES,
            'REGRESSION_MODE_RUN':REGRESSION_MODE_RUN,'RERUN_TESTBATCHES':RERUN_TESTBATCHES,'TAGS':TAGS,'build_ip':build_ip,'build_port':build_port,'build_user':build_user,
            'build_passwd':build_passwd,'robot_repo':robot_repo,'area_coverage':area_coverage}
            
            cmd="python -u /var/jenkins_home/scripts/launchHost.py"
            for launchHostOptionsItem,launchHostOptionsValue in launchHostOptions.items():
                if launchHostOptionsValue!='':
                    cmd+=' -%s %s'%(launchHostOptionsItem,launchHostOptionsValue)
            db_print(cmd)
            result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            db_print("\n%s with output:" % cmd)
            print(result)
            sys.exit()
    if action == 'getLatestBuild':
        #print 'get latest build in certain release and set build environment'
        db_print('STEP:%s' %action)
        getLatestBuildRes=getLatestBuildNew(build,release,HOST,product,hostFlag)
        if not getLatestBuildRes[0]:
            sys.exit(1)
            
        if not build or build=='latest':
            HOST=getLatestBuildRes[2]
            build=getLatestBuildRes[3]
            db_print('latest build is:%s' %build)
            db_print('latest build server is :%s' %HOST)
        #Platform sanity check
        if hostFlag:
            db_print('ignore this action.')
            sys.exit()
        tftp_flag = True
        linux_flag = True
        Device_flag = True
        if not privateNetwork and  not ssh_server_check(SERVER_IP, 'atxuser','alcatel01',timeout=40):
            db_print('Tftpserver %s failed to connect' %SERVER_IP)
            tftp_flag=False
        if not ssh_server_check(linuxIP,linuxUser,linuxPasswd,timeout=40):
            db_print('%s PCTA failed to connect' %linuxIP)
            linux_flag=False
        if product == "NBN-4F" or privateNetwork:
            Device_flag=True
        elif not loadinfo == 'noload' and not DUT.dutPreCheck(dutInstanceList):
            Device_flag=False
            #added by dihongshan to bring up SDFX 1st shelf ...
            if saveTrace and product == 'SDFX' and \
                    start_trace_saver(linuxIP,linuxUser,linuxPasswd,linuxPORT,trace_server_list,product,False,recover_OAM=True,oam_ip=oam_ip):
                Device_flag = True
        if tftp_flag and Device_flag and linux_flag:
            db_print('Connections ok!!!!!!!!')
            DUT.dutPlanLTParallel(dutInstanceList)
        else:
            db_print('Failreason~ TFTPServer/PCTA/DUT is not reachable via Smartserver,please check!!!!')
            sys.exit(1)
        #add security login banner
        if not privateNetwork and DUT.dutPreCheck(dutInstanceList):
            DUT.configDUT(dutInstanceList,cmdType='banner',action='add',platform=job_name,cmdLocation = cmdLocation)
        sys.exit()
    if  action == 'prepareOSWP' or action == 'upgradeDUT':
        db_print('STEP:%s' %action)
        if hostFlag:
            db_print('ignore this action.')
            sys.exit()
            if not prepareQemu(linuxIP,linuxUser,linuxPasswd,linuxPORT,build,HOST,oam_ip,board):
                db_print('start qemu failed')
                sys.exit(1)
            db_print('start qemu host successfully')
            sys.exit()
        if re.search('/ATX/bin/atx',batchCommand):
            db_print("atx server skip step:%s" %action)
            sys.exit()
        if loadinfo =='load' and not build:
            db_print("can not find latst build for %s, skip step:%s" %(buildRelease,action))
            sys.exit()
        elif not extraTar and (loadinfo == 'noload' or loadinfo == 'cleandb'):
            db_print("no need download normal tar or extra tar, skip step:%s" %action)
            sys.exit()
        else:
            pass

        if not privateNetwork :
            res = DUT.compareOSWP(dutInstanceList,buildInstance=buildInstance,build=build)
            if res['res']:
                db_print("Compare OSWP - Build exists in system skip prepareOSWP:%s" %action)
                sys.exit()
        csv = _get1stsetupfile(batchCommand)
        db_print("csv=%s" %csv)

        db_print("prepare OSWP step setups:%s" %action)
        try:
            jks_build_id =os.environ['BuildID']
            jks_build_id_new = os.environ['BuildIDNew']
            jobname = os.environ['JOB_NAME']
            jobNum = os.environ['BUILD_NUMBER']
        except Exception as inst:
            db_print("prepareOSWP failure with missing of jenkins environmental variables")
            jobname = 'smartlabService'
            jobNum = '1'
        #for non nbn 4f
        if product == "NBN-4F":
            build_type = 'official'
        if build_type == 'LIS':
            try:
                lis_build_dir_create(tftpserverIp,LIS_DIR,"create",tftpserverUser,tftpserverPasswd)
            except Exception as inst:
                db_print("create LISDIR with exception:%s" %inst)
                db_print("prepareOSWP failure")
                if not tool_only:
                    errorCode = '501'
                    reportJobInstantStatus(jobname,jobNum,'001',errorCode)
                sys.exit(1)
            buildInstance.destDir=LIS_DIR
            platTimestamp = LIS_DIR.split('/')[2]
            db_print('LIS DIRECTORY: %s' % LIS_DIR)
            db_print('LIS TIMESTAMP: %s' % platTimestamp)
        SCRIPT_PATH='/var/jenkins_home/scripts'
        if not DUT.putScript2Remote(buildInstance=buildInstance,SCRIPT_PATH=SCRIPT_PATH,privateNetwork=privateNetwork,product=platformType):
            db_print("Failure in copying local scripts to tftpserver")
            sys.exit(1)
        else:
            pass
        if not tool_only: 
            reportJobInstantStatus(jobname,jobNum,'001')
        if privateNetwork:
            db_print('STEP: Start Trace collection for private network')
            if saveTrace:
                start_trace_saver(linuxIP,linuxUser,linuxPasswd,linuxPORT,trace_server_list,product,False)
            buildServer = HOST
            #ftpServer = SERVER_IP
            ftpServer = ":".join((linuxIP,linuxPORT,linuxUser,linuxPasswd,LIS_DIR))
            res = prepareOSWP(release,build,buildServer,ftpServer,platformType,ExtraOptions,jks_build_id,jks_build_id_new,jobname,extraTar,defaultDB=defaultDB)
            if saveTrace:
                db_print('STEP: Stop Trace collection')
                stop_trace_saver(linuxIP,linuxUser,linuxPasswd,linuxPORT,trace_server_list,False)
        else:
            if product == "NBN-4F":
                res=DUT.prepareOSWP(dutInstanceList,buildInstance=buildInstance,cmdLocation=cmdLocation,SCRIPT_PATH=SCRIPT_PATH,oam_ip=oam_ip,JKS_BuildID=jks_build_id,JKS_BuildIDNew=jks_build_id_new,site=Site,csv=csv,loadinfo=loadinfo)
            else:
                res=DUT.prepareOSWP(dutInstanceList,buildInstance=buildInstance,extraTar=extraTar,JKS_BuildID=jks_build_id,JKS_BuildIDNew=jks_build_id_new,hostFlag=hostFlag,loadinfo=loadinfo)
        print(res)
        if not res['res']:
            if not privateNetwork:
                db_print("Failreason~ prepareOSWP failure")
            else:
                db_print("Failreason~ image flash failure")
            if not tool_only:
                errors = res['errors']
                error = errors[0]
                errorCode = error.get('error','501')
                reportJobInstantStatus(jobname,jobNum,'001',errorCode)
            sys.exit(1)
        if action == 'prepareOSWP':
            sys.exit()
    if action == 'downloadOSWP' or action == 'upgradeDUT':
        if hostFlag:
            db_print('ignore this action.')
            sys.exit()
        if product == "NBN-4F" or privateNetwork:
            db_print("Skip Download step for NBN_4f setups or private network setups:%s" %action)
            sys.exit()
        if re.search('/ATX/bin/atx',batchCommand):
            db_print("atx server skip step:%s" %action)
            sys.exit()
        if hostFlag:
            db_print("skip STEP:%s for HOST batch" %action)
            sys.exit()
        if loadinfo == 'noload' or loadinfo == 'cleandb':
            db_print("do not need change current oswp, skip step:%s" %action)
            sys.exit()
        elif loadinfo =='load' and not build:
            db_print("can not find latst build for %s, skip step:%s" %(buildRelease,action))
            sys.exit()
        else:
            pass
        if not privateNetwork :
            res = DUT.compareOSWP(dutInstanceList,buildInstance=buildInstance,build=build)
            if res['res']:
                db_print("Compare OSWP - Build exists in system skip downloadOSWP:%s" %action)
                sys.exit()
        db_print('STEP: Start Trace collection')
        if saveTrace:
            DUT.configDUT(dutInstanceList,cmdType='command',action='add',command='configure system security ssh access debugkernel ssh',platform=job_name,cmdLocation = cmdLocation)###thread
            start_trace_saver(linuxIP,linuxUser,linuxPasswd,linuxPORT,trace_server_list,product,False)

        db_print('STEP:%s' %action)
        db_print(build + oam_ip)
        (res,dur) = (True,0)
        if build_type == "LIS":
            if action == 'upgradeDUT':
                newtimestamp = ntimestamp
            else:
                newtimestamp=GetLISTimestamp()
            #newoswp_index = "%s/%s" %(newtimestamp,oswp_index.strip())
            buildInstance.setOswpPrefix(newtimestamp)
        try:
            jobname = os.environ['JOB_NAME']
            jobNum = os.environ['BUILD_NUMBER']
        except Exception as inst:
            db_print("Failreason~ prepareOSWP failure with missing of jenkins environmental variables")
            jobname = 'smartlabService'
            jobNum = '1'
        if not tool_only:
            reportJobInstantStatus(jobname,jobNum,'002')
        res = DUT.downloadParallel(dutInstanceList,buildInstance = buildInstance,cmdLocation = cmdLocation,SWMgmt=SWMgmt)
        print(res)
        if not res['res']:
            db_print("Failreason~ downloadOSWP failure")
            if not tool_only:
                errors = res['errors']
                error = errors[0]
                errorCode = error.get('error','502')
                reportJobInstantStatus(jobname,jobNum,'002',errorCode)
            sys.exit(1)
        if action == 'downloadOSWP':
            sys.exit()
    if  action == 'activateOSWP' or action == 'upgradeDUT':
        if hostFlag:
            db_print('ignore this action.')
            sys.exit()
        (res,dur) = (True, 0)
        if product == "NBN-4F" or privateNetwork:
            db_print("Skip Activation step for NBN_4f setups or private network setups:%s" %action)
            sys.exit()
        if re.search('/ATX/bin/atx',batchCommand):
            db_print("atx server skip step:%s" %action)
            sys.exit()
        if hostFlag:
            db_print("skip STEP:%s for HOST batch" %action)
            sys.exit()
        res = {}
        res['res'] = True
        try:
            jobname = os.environ['JOB_NAME']
            jobNum = os.environ['BUILD_NUMBER']
        except Exception as inst:
            db_print("Failreason~ activateOSWP failure with missing of jenkins environmental variables")
            jobname = 'smartlabService'
            jobNum = '1'
        if not tool_only:
            reportJobInstantStatus(jobname,jobNum,'003')
        if loadinfo == 'load':
            res = DUT.activateParallel(dutInstanceList,defaultDB=defaultDB,buildInstance=buildInstance,mode=dbMode,SWMgmt=SWMgmt)
        elif loadinfo == 'cleandb':
            if product in ['NCDPU','SDFX','SDOLT']:
                res = DUT.cleanDBParallel(dutInstanceList,buildInstance=buildInstance,cmdLocation=cmdLocation,mode=dbMode)
            else:
                res = DUT.activateParallel(dutInstanceList,defaultDB=True,buildInstance=buildInstance,mode=dbMode,active=False)
            #res = DUT.cleanDBParallel(dutInstanceList,buildInstance=buildInstance,cmdLocation=cmdLocation,mode=dbMode)
        else:
            db_print("loadinfo is noload,do not activate oswp")
            res = {'res':True}
        print(res)
        if not res['res']:
            db_print("activation failure")
            if not tool_only:
                errors = res['errors']
                error = errors[0]
                errorCode = error.get('error','503')
                reportJobInstantStatus(jobname,jobNum,'003',errorCode)
            sys.exit(1)
        if action == 'activateOSWP':
            sys.exit()         
    if action == 'initializeDUT' or action == 'upgradeDUT':
        if hostFlag:
            db_print('ignore this action.')
            sys.exit()
        res = {'res':True}
        if product == "NBN-4F" or privateNetwork:
            db_print("Skip initialize step for NBN_4f setups or private network setups:%s" %action)
            sys.exit()
        if re.search('/ATX/bin/atx',batchCommand):
            db_print("atx server skip step:%s" %action)
            sys.exit()
        if hostFlag:
            db_print("skip STEP:%s for HOST batch" %action)
            sys.exit()
        if loadinfo =='load' or loadinfo == 'cleandb':
            if not build:
                db_print("can not find latst build for %s, skip step:%s" %(buildRelease,action))
                sys.exit()
            '''if not craftIp and not product in ['NCDPU','SDFX','SDOLT'] and not check_telnet(oam_ip):
                db_print("Can not telnet oam ip after activateOSWP %s, skip step:%s" %(buildRelease,action))
                sys.exit(1)'''
            db_print('STEP:%s' %action)
            workspace = os.environ['WORKSPACE']
            try:
                jobname = os.environ['JOB_NAME']
                jobNum = os.environ['BUILD_NUMBER']
            except Exception as inst:
                db_print("Failreason~ prepareOSWP failure with missing of jenkins environmental variables")
                jobname = 'smartlabService'
                jobNum = '1'
            if not tool_only:
                reportJobInstantStatus(jobname,jobNum,'004')
            res = DUT.initializeParallel(dutInstanceList,buildInstance=buildInstance,toolOnly=tool_only,SCRIPT_PATH=SCRIPT_PATH,cmdLocation=cmdLocation,workspace=workspace,redund=redund)
            print(res)
            if not res['res']:
                db_print("Failreason~ Initialize failure")
                if not tool_only:
                    errors = res['errors']
                    error = errors[0]
                    errorCode = error.get('error','504')
                    reportJobInstantStatus(jobname,jobNum,'004',errorCode)
                sys.exit(1)
            #skip for MOSWA products
            if not product in ['NCDPU','SDFX','SDOLT'] and loadinfo == 'load':
                res = DUT.dutPostActCheck(dutInstanceList,buildInstance=buildInstance,ltcheck=LTCheck,ltswcheck=LTSWCheck,cmdLocation = cmdLocation,workspace=workspace)
                print(res)
                if not res['res']:
                    db_print("Failreason~ Initialize failure")
                    if not tool_only:
                        errors = res['errors']
                        error = errors[0]
                        errorCode = error.get('error','504')
                        reportJobInstantStatus(jobname,jobNum,'004',errorCode)
                    sys.exit(1)
        #add security login banner after activation
        DUT.configDUT(dutInstanceList,cmdType='banner',action='add',platform=job_name,cmdLocation = cmdLocation)
        if saveTrace:
            db_print('STEP: Stop Trace collection')
            stop_trace_saver(linuxIP,linuxUser,linuxPasswd,linuxPORT,trace_server_list,False)
        if res['res']:
            sys.exit()
        else:
            sys.exit(1)
    if action == 'updateREPO' :
        if hostFlag:
            db_print('ignore this action.')
            sys.exit()
        if re.search('/ATX/bin/atx',batchCommand):
            db_print("atx server skip step:%s" %action)
            sys.exit()
        if loadinfo =='load' and not build:
            db_print("can not find latst build for %s, skip step:%s" %(buildRelease,action))
            sys.exit()
        if batch_type == 'non-framework':
            db_print("STEP:%s skipped for non-framework batch type" %action)
            sys.exit()
        if updateRepo == 'true':
            db_print('STEP:%s' %action)
            updateREPO(linuxIP,linuxUser,linuxPasswd,linuxPORT,cs_num,purgeRepo,repoInfo)
        sys.exit()    
    if action == 'dryRunRobot':
        db_print('skipped for the timebeing')
        sys.exit()
        if hostFlag:
            db_print('ignore this action.')
            sys.exit()
        if not re.search(r'-framework[\s|\b]+?ROBOT',batchCommand) and not re.search('pybot',batchCommand):
            db_print("STEP:%s skipped for apme only batch" %action)
            sys.exit()
        if re.search(';',batchCommand):
            db_print("STEP:%s skipped for more than 1 batch commands" %action)
            sys.exit()
        if re.search('/ATX/bin/atx',batchCommand):
            db_print("STEP:%s skipped for atx" %action)
            sys.exit()
        if hostFlag:
            db_print("STEP:%s skipped for host" %action)
            sys.exit()
        if batch_type == 'non-framework':
            db_print("STEP:%s skipped for non-framework batch type" %action)
            sys.exit()
        ssh2(linuxIP, linuxUser,linuxPasswd, envOverriden['HOME'] + '/configs/prerun_config_cmd',port=int(linuxPORT))
        robotOptions = robotOptions + ',dryrun-enable' if robotOptions else 'dryrun-enable'
        db_print('STEP:%s' %action)
        batchDict['testRun'] = 'true' 
        batchDict['robotOptions'] = robotOptions
        #if extraTar:
        #    batchDict['extraTar'] = '/tftpboot/atx/loads/SD_%s.extra.tar' %build
        if extraTar:
            if build_type == 'LIS':
                nLIS_DIR=GetLISDir()
                ckstatus=copy_extra_tar_to_linux(build,linuxIP,linuxUser,linuxPasswd,SERVER_IP,product,privateNetwork,nLIS_DIR)
                if privateNetwork:
                    extraTarDir = nLIS_DIR
            else:
                ckstatus=copy_extra_tar_to_linux(build,linuxIP,linuxUser,linuxPasswd,SERVER_IP,product,privateNetwork)
            if not ckstatus:
                db_print("Extra.tar download failure")
                if ' -K' in batchCommand:
                    db_print("use -K in original launchTestBatch")
                else:
                    db_print("exit and do not run launchTestBatch")
                    sys.exit(1)
            elif exist_extra_tar(build,linuxIP,linuxUser,linuxPasswd,extraTarDir):
                db_print("Extra.tar is copied successfully")
                if product in ['SDFX','SDOLT','NCDPU']:
                    batchDict['extraTar'] = '%s/lightspan_%s.extra.tar' %(extraTarDir,build)
                else:
                    batchDict['extraTar'] = '%s/SD_%s.extra.tar' %(extraTarDir,build)     
        if not (prerunConfig and 'DISPLAY' in prerunConfig) or hostFlag:
            batchCommand=updatelaunchTestBatchCmd(batchCommand,linuxIP,linuxUser,linuxPasswd,linuxPORT)
        prerunConfig = _set_metrics_user(prerunConfig,'')
        if prerunConfig:
            prerunConfig += ';export NOXTERM=True'
        else:
            prerunConfig = 'export NOXTERM=True'
        (commandList,domainList)=processBatchCommandFinal(batchCommand,**batchDict)
        print(commandList)
        print domainList
        resultDirList = dryrunBatch(commandList,prerunConfig,domainList,linuxIP,linuxUser,linuxPasswd,domainSplit,defaultDB,dbDict,linuxPORT=linuxPORT,traceOnly=debugOnly)  
        casefile = generateCaseList(linuxIP,resultDirList,linuxPORT,linuxUser,linuxPasswd,debug = debugOnly)   
        ssh2(linuxIP, linuxUser,linuxPasswd, envOverriden['HOME'] + '/configs/postrun_config_cmd',port=int(linuxPORT))
        db_print('STEP:%s finished with file:%s' %(action,casefile))
        sys.exit()
    if action == 'runBatch' :
        if hostFlag:
            db_print('ignore this action.')
            sys.exit()
        if loadinfo =='load' and not build:
            db_print("can not find latst build for %s, skip step:%s" %(buildRelease,action))
            sys.exit()
        Simpc_ip_list = GetSimpcList(batchCommand)
        ###Reboot SIMPC#########
        if not Simpc_ip_list:
            db_print("no simpc defined in LTB,skip")
            SimpcFlag = False
        else:
            db_print("simpc available,please reboot it")
            SimpcFlag = True
            for simpc_node in Simpc_ip_list:
                out=reboot_simpc(simpc_node,connectType)
                if out == True:
                    db_print("SIMPC reboot %s success" %simpc_node)
                else:
                    db_print("SIMPC reboot %s failure" %simpc_node)
                    sys.exit(1)
        if batch_type == 'non-framework':
            #db_print("STEP:%s Kill existing Non framework scripts process if any" %action)
            #standalonescriptList = GetNonFrameworkScriptList(batchCommand)
            #NonFrameworkProcessKill(linuxIP,linuxUser,linuxPasswd,linuxPORT,standalonescriptList)
            db_print("STEP:%s Execute scripts for non-framework batch type" %action)
            dbDict['team'] = Team
            commandList=processNonFrameBatchCommandFinal(batchCommand,**batchDictStandalone)
            runStandaloneBatch(commandList,prerunConfig,linuxIP,linuxUser,linuxPasswd,linuxPORT,dbDict,storeLog=storeLog)
            sys.exit()
        db_print('STEP: Processes to be started before LTB')
        if linuxPctaexe != '':
            db_print('STEP: Kill existing PCTA process if any')
            pcta_process_kill(pctaIPaddr,pctaUser,pctaPasswd,pctaPORT)
            db_print('STEP: PCTA process start')
            try:
                directory=linuxPctaexe.strip('pcta.exe')
                exe=linuxPctaexe.strip('/root/PCTA/')
            except Exception as inst:
               directory='/root/PCTA/'
               exe='pcta.exe'
            pcta_exe_cmd="%s -d  > ./PCTA_OPF.txt &" %exe
            ##Start PCTA process
            pcta_start(SERVER_IP,pctaIPaddr,pctaPORT,pctaUser,pctaPasswd,directory,pcta_exe_cmd)
        else:
            db_print('STEP: Skip PCTA process start')

        if platformType in ["Voice","REMOTE"]:
            if redund or coverage.lower() == 'weekly':
                db_print('Skip voice process start/stop for ISAM Voice Redund platforms')
            else:  
                db_print('kill voice process')
                voice_process_kill(linuxIP,linuxUser,linuxPasswd,linuxPORT)
                db_print('start voice process')
                start_voice_process(linuxIP,linuxUser,linuxPasswd)
        ###Check SIMPC telnet connectivity####
        if SimpcFlag:
            for simpc_node in Simpc_ip_list:
                ret=check_simpctelnet(simpc_node)
                if ret == True:
                    db_print("Telnet SIMPC %s success after reboot" %simpc_node)
                else:
                    db_print("Telnet SIMPC %s failure after reboot" %simpc_node)
                    sys.exit(1)
        db_print('STEP:%s' %action)
        if extraTar:
            if build_type == 'LIS':
                nLIS_DIR=GetLISDir()
                ckstatus=copy_extra_tar_to_linux(build,linuxIP,linuxUser,linuxPasswd,SERVER_IP,product,privateNetwork,nLIS_DIR)
                if privateNetwork:
                    extraTarDir = nLIS_DIR
            else:
                ckstatus=copy_extra_tar_to_linux(build,linuxIP,linuxUser,linuxPasswd,SERVER_IP,product,privateNetwork)
            if not ckstatus:
                db_print("Extra.tar download failure")
                db_print("Extra.tar download failure")
                if ' -K' in batchCommand:
                    db_print("use -K in original launchTestBatch")
                else:
                    db_print("exit and do not run launchTestBatch")
                    sys.exit(1)
            elif exist_extra_tar(build,linuxIP,linuxUser,linuxPasswd,extraTarDir):
                db_print("Extra.tar is copied successfully")
                if product in ['SDFX','SDOLT','NCDPU']:
                    batchDict['extraTar'] = '%s/lightspan_%s.extra.tar' %(extraTarDir,build)
                else:
                    batchDict['extraTar'] = '%s/SD_%s.extra.tar' %(extraTarDir,build) 
        #commandList=processBatchCommandFinal(batchCommand,release=release,suiteRerun = suiteRerun,domain=domain,domainSplit=domainSplit,testRun=testRun,build=build,robotOptions=robotOptions,coverage=coverage,robotCaseList=robotCaseList)
        batchDict['update_build']=update_build
        if not product == "NBN-4F" and build_type == 'LIS' and loadinfo == 'load':
            newtimestamp=GetLISTimestamp()
        else:
            newtimestamp = datetime.datetime.now().strftime('%m%d%Y-%H%M%S')
            db_print("noload,but ltb will with timestamp too")
            db_print('LIS TIMESTAMP: %s' % newtimestamp)
        if not (prerunConfig and 'DISPLAY' in prerunConfig) or hostFlag:
            batchCommand=updatelaunchTestBatchCmd(batchCommand,linuxIP,linuxUser,linuxPasswd,linuxPORT,newtimestamp)
            if prerunConfig:
                prerunConfig += ';export NOXTERM=True'
            else:
                prerunConfig = 'export NOXTERM=True'

        batchDict['STCServer'] = STCServer
        batchDict['stcVersion'] = stcVersion
        if pctaIPaddr != 'NONE':
            batchDict['pctaIPaddr'] = pctaIPaddr
        (commandList,domainList)=processBatchCommandFinal(batchCommand,**batchDict)
        print(commandList)
        print domainList
        #sys.exit()
        #whether it is ATX or else, will store active oswp index for cleanDB bwteen two domains
        if defaultDB == 'true':
            oswp_info = _get_oswp_info(oam_ip,product,connectType)
            if oswp_info:
                dbDict['oswpIndex']=oswp_info[0]['index']
        dbDict['saveTrace'] = saveTrace
        dbDict['trace_server_list'] = trace_server_list
        if product in ['SDFX','SDOLT','NCDPU']:
            db_print('preparing moswa update instance for clean db between dbs')
            #MOSWA_UPDATE = sw_update_netconf.Updata_Instance(MOSWA_DICT)
            #moswa_board_list = []
            #for moswa_dict in MOSWA_LIST:
            #    moswa_board = Smartlab_Instance(moswa_dict)
            #    moswa_board_list.append(moswa_board)
            dbDict['MOSWA_LIST'] = MOSWA_LIST
        dbDict['team'] = Team
        if batchCommand.find('/ATX/bin/atx') == -1:        
            #print dbDict
            if craftIp:        
                #if re.search('/ATX/bin/atx',batchCommand):
                #   pctaIP = _get_pcta_info_from_atx(linuxIP, 'atxuser','alcatel01',batchCommand)
                #else:
                #   pctaIP = linuxIP
                pctaIP = linuxIP
                extraCommands = _get_extra_init_commands(linuxIP, linuxUser,linuxPasswd, linuxPORT)
                dbDict['extraCommands'] = extraCommands       
            ssh2(linuxIP, linuxUser,linuxPasswd, envOverriden['HOME'] + '/configs/prerun_config_cmd',port=int(linuxPORT))
            prerunConfig = _set_metrics_user(prerunConfig,metrics_user)
            runBatch(commandList,prerunConfig,domainList,linuxIP,linuxUser,linuxPasswd,domainSplit,defaultDB,dbDict,linuxPORT=linuxPORT,traceOnly=debugOnly,storeLog=storeLog)
        else:
            runBatch(commandList,prerunConfig,domainList,linuxIP,linuxUser,linuxPasswd,domainSplit,defaultDB,dbDict,linuxPORT=linuxPORT,traceOnly=debugOnly,storeLog=storeLog)
        sys.exit()
    #elif action == 'handleRunResult' :
    #    if domainSplit == 'true':
    #        db_print("test logs have been handled when splitDomain set true %s, skip step:%s" %(buildRelease,action))
    #        sys.exit()
    #    if loadinfo =='load' and not build:
    #        db_print("can not find latst build for %s, skip step:%s" %(buildRelease,action))
    #        sys.exit()
    #    handleRunResult()
    if action == 'cleanEnvPostRun' :
        if hostFlag:
            db_print('ignore this action.')
            sys.exit()
        if re.search('/ATX/bin/atx',batchCommand):
            db_print("atx server skip step:%s" %action)
            sys.exit()
        if loadinfo =='load' and not build:
            db_print("can not find latst build for %s, skip step:%s" %(buildRelease,action))
            sys.exit(1)
        db_print('STEP:%s' %action)
        if batchCommand.find('/ATX/bin/atx') == -1:
            db_print('execute postrun_config_cmd')
            ssh2(linuxIP, linuxUser,linuxPasswd, envOverriden['HOME'] + '/configs/postrun_config_cmd',port=int(linuxPORT))
        #remove security login banner after batch finish
        if not privateNetwork and DUT.dutPreCheck(dutInstanceList):
            DUT.configDUT(dutInstanceList,cmdType='banner',action='delete',platform=job_name,cmdLocation = cmdLocation)
        if saveTrace:
            db_print('STEP: Stop Trace collection')
            stop_trace_saver(linuxIP,linuxUser,linuxPasswd,linuxPORT,trace_server_list,False)
            upload_trace_saver(linuxIP,trace_server_list,Team,False)
        if batch_type == 'non-framework':
            db_print("STEP:%s Kill Non framework scripts process id" %action)
            standalonescriptList = GetNonFrameworkScriptList(batchCommand)
            NonFrameworkProcessKill(linuxIP,linuxUser,linuxPasswd,linuxPORT,standalonescriptList)
            jobname = os.environ['JOB_NAME']
            jobNum = os.environ['BUILD_NUMBER']
            reportJobInstantStatus(jobname,jobNum,'000')
            sys.exit()
        else:
            #remove timestamp directory in PCTA
            result,timestamp=CheckLogMovement()
            if result:
                Delete_timestamp_PCTA(linuxIP,linuxUser,linuxPasswd,timestamp,linuxPORT=linuxPORT)
        cleanEnvPostRun(linuxIP,linuxUser,linuxPasswd,oam_ip,linuxPctaexe,hostFlag,linuxPORT=linuxPORT)
        if build_type == 'LIS':
            nLIS_DIR=GetLISDir()
            db_print('Delete LIS build directory')
            if nLIS_DIR:
                if privateNetwork:
            #for privateNetwork,LIS DIR is on linux server...
                    lis_build_dir_create(linuxIP,nLIS_DIR,"delete",linuxUser,linuxPasswd)
                else:
                    lis_build_dir_create(SERVER_IP,nLIS_DIR,"delete")
                newtimestamp=GetLISTimestamp()
                clean_lis_dir_process_pcta(linuxIP,linuxUser,linuxPasswd,newtimestamp,linuxPORT=linuxPORT)
        if product == "NBN-4F":
            csv = _get1stsetupfile(batchCommand)
            db_print("csv=%s" %csv)
            restore_file_pcta(linuxIP,linuxUser,linuxPasswd,csv,linuxPORT=linuxPORT)
        db_print('cleanEnvPostRun')
        jobname = os.environ['JOB_NAME']
        jobNum = os.environ['BUILD_NUMBER']
        reportJobInstantStatus(jobname,jobNum,'000')
        sys.exit()
    #other action,will go this branch
    db_print("wrong operation")
    sys.exit(1)


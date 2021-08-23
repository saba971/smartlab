#! /usr/bin/python                                                                                                      
#coding:utf-8
# Author: Wang Weiwei <Weiwei.Wang@alcatel-sbell.com.cn>

import ftplib
import socket
import tarfile,random
import pexpect
import copy
import logging,socket,paramiko
import telnetlib, time, re, os, ConfigParser, sys, inspect, subprocess,datetime
from lxml import etree
from argparse import ArgumentParser
import oswpUtility
from qemuUtility import startHostBySSH
ddir='/root/pylib'
sys.path.append(ddir)
from urlDaily import *
from sshClient import ssh2,ssh_scp_get,ssh2_non_block
import yaml
#import sw_update_netconf
#from sw_update_netconf import Smartlab_Instance
from sw_update_netconf import Smartlab_Instance
import json,requests
import com_tnd
import ipaddress
TND_SESSION={}
#HOST = '135.252.245.46'
LOCAL_LOAD_PATH='/tftpboot/atx/loads'
#DIRN = '/ftp'
LOCAL_LOAD_PATH='/tftpboot/atx/loads'
BUILD_ID_MAP_FILE = 'BuildIDMapping.yaml'
DIRN = '/loads'
ver2 = ''
#DIRN = '/ftpserver/loads'
#SERVER_IP = '135.252.245.44'
REMOTEHOST='172.21.128.21'
VERSION_DICT = {'58':'499','5701':'499','5801':'599'}
JENKINS_FILE_DIR = '/var/www/html/repo/atxuser/cases'
SCRIPT_PATH = ''
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
SMARTLAB_SERVER='http://smartservice.int.nokia-sbell.com'
LOG_SERVER={'FQDN':'http://smartlab-service.int.net.nokia.com:9000/log','IP':'10.131.213.53','HTTP':'http://10.131.213.53:9000/log'}
dict_m_d_map = {'Jan':'01','Feb':'02','Mar':'03','Apr':'04','May':'05','Jun':'06','Jul':'07','Aug':'08','Sep':'09','Oct':'10',\
                'Nov':'11','Dec':'12'}
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
        pcta_cmd="ps -aef | grep pcta.exe | grep -v defunct | grep -v grep | awk '{print $2}'"
        pid=ssh2(linuxIP, userName,passwd,pcta_cmd,True ,port=int(linuxPORT))
        pid=pid.strip()
        for val in pid.split('\n'):
            if val != '':
                kill_cmd="sudo /bin/kill -9 %s" %val
                ssh2(linuxIP, userName,passwd,kill_cmd,port=int(linuxPORT))
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
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        cmd_pcta = '%s --linux_ip %s --port %s --linuxuser %s --linuxpass %s --directory \'%s\' --command \'%s\' --prompt %s' %(remotescript,linuxIP,linuxPORT,linuxUser,linuxPasswd,directory,pcta_exe_cmd,'%')
        ssh2(server_ip, 'atxuser','alcatel01',cmd_pcta,True)
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
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            localscript = SCRIPT_PATH + '/com_tnd.py'
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            cmd = 'ls %s/octopus' %remotepath
            tmp_res=ssh2(server_ip, 'atxuser','alcatel01',cmd,True)
            if re.search('No such',tmp_res):
                cmd = 'uname -a'
                tmp_res=ssh2(server_ip, 'atxuser','alcatel01',cmd,True)
                if re.search('el[\d]\.i686',tmp_res):
                    localscript = SCRIPT_PATH + '/octopus32'
                    remotepath = remotepath + '/octopus'
                else:
                    localscript = SCRIPT_PATH + '/octopus'
                    remotepath = remotepath + '/octopus'
                cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
                db_print(cmd)
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        cmd_octopus = '%s --isam_ip %s --cmd %s' %(remotescript,isamIP,tnd_cmd)
        tmp_res=ssh2(server_ip, 'atxuser','alcatel01',cmd_octopus,True)
        print tmp_res
        if tmp_res.find('diskSync finished successfully') == -1:
            result = False
        else:
            result = True
        return result
    except Exception as inst:
        db_print("Octopus function failed:%s" %inst)
        return False


def check_nt_type(ip):
    db_print('#######Start to check nt type#######')
    cli = pexpect.spawn('telnet %s' % ip)
    cli.maxread = 6000
    cli.timeout = 180
    cli.logfile = sys.stdout
    try:
        cli.expect("login:")
        cli.sendline("isadmin")
        db_print('#######Use updated password#######')
        cli.expect('password:')
        cli.sendline("isamcli!")
        try:
            if cli.expect(["#","incorrect"]) != 0:
                raise Exception("login failed")
        except:
            db_print('login with default password...')
            cli.sendline("isadmin")
            cli.expect('password:')
            cli.sendline("i$@mad-")
            cli.expect("new password")
            cli.sendline("isamcli!")
            cli.expect("re-enter")
            db_print('repeat entering new password!')
            cli.sendline("isamcli!")
        cli.expect(["#","$"])
        cli.sendline("show equipment slot")
        try:
            ret=cli.expect(['fant-f','fant-g','fant-h',pexpect.EOF,pexpect.TIMEOUT])
            if ret == 0 or ret == 1 or ret == 2:
                time.sleep(300)
                for trytimes in range (0,20):
                  if not pingIp(ip):
                      db_print('%s is not reachable, waiting longer...' % ip)
                      time.sleep(30)
                  else:
                      break
                return False
        except:
            time.sleep(300)
            return True
    except:
        db_print('#######Failed to Login#######')
        for trytimes in range (0,10):
          if not pingIp(ip):
              db_print('%s is not reachable, waiting longer...' % ip)
              time.sleep(30)
          else:
              break
        return False
    cli.close()

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

def copy_extra_tar_to_linux(buildID,linuxip,linux_user,linux_pass,tftpserverip,srcDir='/tftpboot',pcta_folder="/tftpboot/atx/loads"):
    dir_flag="False"
    orig_result = True
    ver_build='SD_' + buildID + '.extra.tar'
    ####To check directory exists or not####
    cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'ls -d %s'" %(linux_pass,linuxip,pcta_folder)
    result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
    if result == "":
        print "%s directory not available" %pcta_folder
        cmd1="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'mkdir -p %s'" %(linux_pass,linuxip,pcta_folder)
        cmd1a="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'chmod -R +x %s'" %(linux_pass,linuxip,pcta_folder)
        try:
            result=subprocess.Popen(cmd1, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            print "%s directory created" %pcta_folder
            res1=subprocess.Popen(cmd1a, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            #check whether directory created successfuly
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            if result:    
                dir_flag="True"
        except:
            db_print("Unable to create directory")
            sys.exit(1)	
    else:
        print "%s directory already available" %pcta_folder
        dir_flag="True"
    ####To copy extra_tar from tftpserver to linux machine####
    if dir_flag == "True":
       print "To check %s is available in %s" %(ver_build,pcta_folder)
       cmd2="sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'ls %s | grep %s'" %(linux_pass,linuxip,pcta_folder,ver_build)
       result=subprocess.Popen(cmd2, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
       if result != "":
           print "%s available in %s" %(ver_build,pcta_folder)
       else:
           print "Copy %s from tftpserver to PCTA machine" %ver_build
           cmd3="sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s/%s  atxuser@%s:%s" %(linux_pass,srcDir,ver_build,linuxip,pcta_folder)
           val_out=ssh2(tftpserverip,'atxuser','alcatel01',cmd3,True)
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
  return dir_flag     

def GetLISDir():
  try :
      build_url = os.environ['BUILD_URL']
      build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)
  except Exception as inst:
      db_print('Failed to get LIS  directory:%s' %inst)
      return
  try:
      cmd = "curl -s %sconsoleText |grep -o -a -E 'LIS DIRECTORY: .*'" %build_url
      db_print(cmd)
      result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
      result=result.rstrip('\n')
      nout=re.search('LIS DIRECTORY: (.*)',result)
      lis_dir=nout.group(1)
      lis_dir=lis_dir.strip()
      print lis_dir
  except Exception as inst:
      db_print('Failure in access LIS directory:%s' %inst)
      sys.exit(1)
  return lis_dir

def GetLISTimestamp():
  try :
      build_url = os.environ['BUILD_URL']
      build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)
  except Exception as inst:
      db_print('Failed to get LIS timestamp:%s' %inst)
      return
  try:
      cmd = "curl -s %sconsoleText |grep -o -a -E 'LIS TIMESTAMP: .*'" %build_url
      db_print(cmd)
      result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
      result=result.rstrip('\n')
      nout=re.search('LIS TIMESTAMP: (.*)',result)
      lis_timestamp=nout.group(1)
      lis_timestamp=lis_timestamp.strip()
      print lis_timestamp
  except Exception as inst:
      db_print('Failure in access LIS timestamp:%s' %inst)
      sys.exit(1)
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
  db_print("OSWP_NAME:%s" %MOSWA_OSWP_NAME)
  if MOSWA_OSWP_NAME:
      return MOSWA_OSWP_NAME
  try :
      build_url = os.environ['BUILD_URL']
      build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)
  except Exception as inst:
      db_print('Failed to get LIS  directory:%s' %inst)
      return
  try:
      cmd = "curl -s %sconsoleText |grep -o -a -E 'MOSWA OSWP NAME: .*'" %build_url
      db_print(cmd)
      result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
      result=result.rstrip('\n')
      nout=re.search('MOSWA OSWP NAME: (.*)',result)
      moswa_name=nout.group(1)
      moswa_name=moswa_name.strip()
      print moswa_name
  except Exception as inst:
      db_print('Failure in access MOSWA OSWP NAME:%s' %inst)
      sys.exit(1)
  return moswa_name
  
def Get_MOSWA_URL():
  global MOSWA_OSWP_URL
  db_print("OSWP_URL:%s" %MOSWA_OSWP_URL)
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

def check_lt_status(oam_ip,complete_list):
    global exp
    syncCheck = False
    syncComplete= False
    LT_list=[]
    if not complete_list:
        db_print("no LT details defined,skip")
        return True
    exp = pexpect.spawn('telnet %s' % oam_ip)
    exp.timeout = 60
    exp.logfile_read = sys.stdout
    if not login():
        db_print("########################################")
        db_print("Login OAM failed.Please check your ENV")
        db_print("########################################")
        syncCheck = False
        return syncCheck
    exp.sendline("show equipment slot | match exact:available | match skip exact:acu")
    res = exp.expect(["#",pexpect.EOF,pexpect.TIMEOUT])
    if res == 0:
        test_out=exp.before
        for line in test_out.split('\n'):
            if re.search('lt:\d\/\d\/\d+\s+(.*)\s+\w+\s+(.*)\s+available\s+\d+',line):
                var=re.search('lt:\d\/\d\/\d+\s+(.*)\s+\w+\s+(.*)\s+available\s+\d+',line)
                nVal=var.group(1).strip(" ")
                nVal=nVal.upper()
                LT_list.append(nVal) 
    if len(LT_list)==len(complete_list) and all(LT_list.count(i)==complete_list.count(i) for i in LT_list):
        syncComplete = False
    else:
        syncComplete = True
    if syncComplete:
        db_print("LT is available after OSWP upgrade")
        print("Total available LT is %s")%LT_list
    else:
        db_print('LT is not available after OSWP upgrade')
    return syncComplete

def check_lt_sw(server_ip,isamIP,LT_list,build):
    try:
        localscript = SCRIPT_PATH + '/lt_swcheck.py'
        remotepath = '/tmp/.jenkins'
        remotescript = '/tmp/.jenkins/lt_swcheck.py'
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
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            localscript = SCRIPT_PATH + '/com_tnd.py'
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            localscript = SCRIPT_PATH + '/octopus'
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        cmd_octopus = '%s --isam_ip %s --lt_list %s --build %s' %(remotescript,isamIP,LT_list,build)
        #tmp_res=ssh2(server_ip, 'atxuser','alcatel01',cmd_octopus,True)
        #print tmp_res
        final_res = False
        for trytimes in range (0,5):
            tmp_res=ssh2(server_ip, 'atxuser','alcatel01',cmd_octopus,True)
            print tmp_res
            if tmp_res.find('LT SW check is successfull') == -1:
                db_print("wait for 60 seconds and retry")
                time.sleep(60)
            else:
                final_res = True
                break
        return final_res
    except Exception as inst:
        db_print("LT SW check is failed:%s" %inst)
        return False
  

def config_shelf(shelfIp,commands):
    global exp
    db_print('Shelf configuration before LT availability check')
    n = 0
    exp = pexpect.spawn('telnet %s' % shelfIp)
    exp.timeout = 10
    exp.logfile_read = sys.stdout
    if not login():
        db_print("########################################")
        db_print("Login OAM failed.Please check your ENV")
        db_print("########################################")
        return False
    for line in commands:
        exp.sendline(line)
        db_print(line)
        time.sleep(4)
        try:
            exp.expect(["#","$"])
        except:
            db_print("Warning, no prompt retrieve")
            db_print(str(exp.eof()))
    exp.sendline("exit all")
    db_print("exit all")
    time.sleep(10)
    exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])

def _get_extra_shelf_commands(linux_ip,user,passwd, port,action):
    try :
        workspace = os.environ['WORKSPACE']
        workspace = re.sub(r'([\(|\)])',r'\\\1',workspace)
    except Exception as inst:
        print 'failure to get workspace'
        workspace = '/tmp'
    lines=[]
    try:
        if action == 'config':
            cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:~/configs/pre_shelf_config_command %s" %(passwd,port,user,linux_ip,workspace)
        else:
            cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:~/configs/post_shelf_unconfig_command %s" %(passwd,port,user,linux_ip,workspace)
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

def check_lt_sw1(server_ip,isamIP,lt_list,build):
    try:
        localscript = SCRIPT_PATH + '/com_tnd.py'
        remotepath = '/tmp/.jenkins'
        remotescript = '/tmp/.jenkins/com_tnd.py'
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
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            localscript = SCRIPT_PATH + '/octopus'
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        LT_list=list(lt_list.split(','))
        print LT_list
        nbuild=build.split('.')
        test_bld0=nbuild[0]
        test_bld1=nbuild[1]
        test_bld=test_bld0[0]+test_bld0[1]+'.'+test_bld1
        print test_bld
        Board_list=[]
        lt_ret_flag=False
        cmd="eqpt displayAsam -s"
        cmdb="cmd buildVersion"
        ###Connect TND
        tnd_obj=connect_tnd(isamIP)
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
            lt_ret_flag=True
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
                    lt_ret_flag=False
        except Exception as inst:
            print "Error in accessing board: %s" %inst
            lt_ret_flag=False
        disconnect_tnd()
        if lt_ret_flag:
            print "LT SW check is successfull"
        else:
             print "LT SW check is not successfull"
        return lt_ret_flag
    except Exception as inst:
        db_print("LT SW check is failed:%s" %inst)
        return False

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
    
def getLatestBuildNew(ver):
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
        latest_ver = getLatestBuildURL(ver)
    except Exception as inst:
        db_print("getlatest build exception:%s" %inst)
        return (False,0)     
    if latest_ver:
        db_print("find build:%s" %latest_ver)
    	try:
            os.chdir(workspace)
            fd=open('job_env.prop',"w+")
            latest_ver = latest_ver[3:-4]
            fd.writelines('BuildIDNew=%s' %latest_ver)
        except Exception as inst:
            db_print("file operation failure %s" %inst)
            return (False,0)
        fd.close()
    else:
        if not getLatestBuild(ver):
            return (False,0)
    t1 = time.time()
    return (True,time.localtime(t1 - t0))

def prepareOSWP(ver,serverip,product,buildip='135.251.206.97',moswa_list=[],toolOnly =False, destDir='/tftpboot',build_type='official',extraTar = False,debug=False):
    global MOSWA_OSWP_NAME,MOSWA_OSWP_URL
    #jobname = os.environ['JOB_NAME'] /* Commented for Tools Upgrade */
    #jobNum = os.environ['BUILD_NUMBER']
    #if not toolOnly:
    #    reportJobInstantStatus(jobname,jobNum,'001')
    t0 = time.time()
    if product in ['SDFX','SDOLT','NCDPU']:
        db_print('put packagemeUtility.py for moswa to tftp server')
        #localscript = SCRIPT_PATH + '/packagemeUtility.py'
        localscript = SCRIPT_PATH + '/sw_update_netconf.py'
        remotepath = '/tmp/.jenkins'
        #remotescript = '/tmp/.jenkins/packagemeUtility.py'
        remotescript = '/tmp/.jenkins/sw_update_netconf.py'
        cmd = 'cksum %s' %localscript
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        new_cksum = result.strip().split(' ')[0]
        db_print('cksum:%s' %new_cksum)
        cmd = "sshpass -p 'alcatel01' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'cksum %s'" %(serverip,remotescript)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        old_cksum = result.strip().split(' ')[0]
        db_print('cksum:%s' %old_cksum)
        result=''
        if new_cksum and not old_cksum == new_cksum :
            localscript = SCRIPT_PATH + '/packagemeUtility.py'
            remotescript = '/tmp/.jenkins/packagemeUtility.py'
            cmd = "sshpass -p 'alcatel01' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'mkdir -p /tmp/.jenkins'" %serverip
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,serverip,remotepath)
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            #localscript = SCRIPT_PATH + '/sw_update_netconf.py'
            localscript = SCRIPT_PATH + '/sw_update_netconf.py'
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,serverip,remotepath)
            db_print(cmd)
            
        cmd = "sshpass -p 'alcatel01' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'chmod -R +x %s'" %(serverip,remotepath)
        db_print(cmd)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        moswa_dict = moswa_list[0]
        db_print('MOSWA PREP')
        db_print(str(moswa_dict))
        result = True
        try:
            lead_board = Smartlab_Instance(moswa_dict)
            lead_board.build_id_guess()
            lead_board.build_to_update()
            lead_board.gen_index_url()
            MOSWA_OSWP_NAME = lead_board.NAME
            MOSWA_OSWP_URL = lead_board.URL
            db_print('MOSWA OSWP NAME: %s' % lead_board.NAME)
            db_print('MOSWA OSWP URL: %s' % lead_board.URL)
            db_print('MOSWA OSWP NAME: %s' % MOSWA_OSWP_NAME)
            db_print('MOSWA OSWP URL: %s' % MOSWA_OSWP_URL)
        except Exception as inst:
            db_print("moswa prepare oswp with exception as inst:%s" %inst)
            result = False
        t1 = time.time()
        #501 means prepare oswp failure
        #if not result and not toolOnly:/* Commented for Tools Upgrade */
        #    reportJobInstantStatus(jobname,jobNum,'001','501')
        return (result, time.localtime(t1 - t0))
    result = True
    #if debug:
    #    SCRIPT_PATH = '/tftpboot/atx/atxuser/jenkins/latest'
    ##To Check & Create timestamp_directory in tftpserver
    if build_type == 'LIS':
        lis_build_dir_create(serverip,destDir,"create")
        platTimestamp = destDir.split('/')[2]
        db_print('LIS DIRECTORY: %s' % destDir)
        db_print('LIS TIMESTAMP: %s' % platTimestamp)
        dr4Flag = False
    else:
        dr4Flag = _check_build_dr4(ver)
    if os.path.exists(LOCAL_LOAD_PATH):
        db_print('jenkins/load server colocation,prepare oswp locally')
        if build_type == 'LIS':
            result = oswpUtility.prepareOSWP(ver,serverip,destDir,False,buildip,build_type)
        else:  
            result = oswpUtility.prepareOSWP(ver,serverip,destDir,False,buildip)
    else:
        db_print('jenkins server do not have loads directory,prepare oswp by ssh load server')
        localscript = SCRIPT_PATH + '/oswpUtility.py'
        remotepath = '/tmp/.jenkins'
        remotescript = '/tmp/.jenkins/oswpUtility.py'
        cmd = 'cksum %s' %localscript
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        new_cksum = result.strip().split(' ')[0]
        db_print('cksum:%s' %new_cksum)
        cmd = "sshpass -p 'alcatel01' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'cksum %s'" %(serverip,remotescript)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        old_cksum = result.strip().split(' ')[0]
        db_print('cksum:%s' %old_cksum)
        result=''
        if new_cksum and not old_cksum == new_cksum :
            cmd = "sshpass -p 'alcatel01' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'mkdir -p /tmp/.jenkins'" %serverip
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,serverip,remotepath)
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            localscript = SCRIPT_PATH + '/urlDaily.py'
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,serverip,remotepath)
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            localscript = SCRIPT_PATH + '/paxel.py'
            cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,serverip,remotepath)
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            cmd = "sshpass -p 'alcatel01' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'chmod -R +x %s'" %(serverip,remotepath)
            db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        #cmd = '%s --action prepareOSWP --build %s --serverip %s --Host %s' %(remotescript,ver,serverip,HOST)
        cmd = "%s --action prepareOSWP --build %s --serverip %s --Host %s" %(remotescript,ver,serverip,buildip)
        cmd = cmd + ' --destDir %s' %destDir
        ##LIS build check
        if build_type == 'LIS':
            cmd = cmd + ' --build_type %s' %build_type
        if dr4Flag:
            cmd = cmd + ' --dr4'
	      ##Download normal tar by default
        #db_print("Download normal tar")
        #cmd = cmd + ' --extraTar'
        #tmpRes = ssh2(serverip, 'atxuser','alcatel01',cmd,True)
        #print tmpRes
	      ##Download normal & extra tar for ISAM
        if extraTar:
            db_print("Download extra tar")
            cmd1 = cmd + ' --extraTar' %extraTar
            cmd1=str(cmd1)
            tmpRes1 = ssh2(serverip, 'atxuser','alcatel01',cmd1,True)
            print tmpRes1
        else:
            db_print("Download normal tar")
            cmd=str(cmd)
            tmpRes = ssh2(serverip, 'atxuser','alcatel01',cmd,True)
            print tmpRes
        if tmpRes.find('download failure') == -1:
            result = True
        else:
            result = False
    t1 = time.time()
    #501 means prepare oswp failure
    #if not result and not toolOnly:/* Commented for Tools Upgrade */
    #    reportJobInstantStatus(jobname,jobNum,'001','501')
    return (result, time.localtime(t1 - t0))

def _check_build_dr4(ver):
    try:
        jenkins_home = os.environ['JENKINS_HOME']
        fd = open(os.path.join(jenkins_home,'scripts',BUILD_ID_MAP_FILE), 'rb')
        buildIdMap = yaml.load(fd)
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

def downloadOSWP(oswp, serverip, shelfIp, oswpIndex,product,toolOnly = False,moswa_list=[],build_type='official'):
    #jobname = os.environ['JOB_NAME']/* Commented for Tools Upgrade */
    #jobNum = os.environ['BUILD_NUMBER']
    #if not toolOnly:
    #    reportJobInstantStatus(jobname,jobNum,'002')
    t0 = time.time()
    global exp
    result = True
    errorCode = '502'
    if product in ['SDFX','SDOLT','NCDPU']:
        try:
            board_arg_list = copy.deepcopy(moswa_list)
            download_list = []
            for moswa_dict in board_arg_list:
                moswa_dict.pop('role','SINGLE')
                moswa_board = Smartlab_Instance(moswa_dict)
                moswa_board.NAME = Get_MOSWA_NAME()
                moswa_board.URL = Get_MOSWA_URL()
                
                active_name = moswa_board._get_active_name(getlist=moswa_board.check_state())
                
                if not moswa_board.NAME == active_name :
                    download_list.append(moswa_board)

            Smartlab_Instance.board_event_loop('download_build_parallel',download_list)
                
        except Exception as inst:
            db_print("moswa download with exception:%s" %inst)
            result = False
            errorCode = '502'
        result = True
    else:       

        exp = pexpect.spawn('telnet %s' % shelfIp)
        exp.timeout = 60
        exp.logfile_read = sys.stdout
        if not login():
            db_print("########################################")
            db_print("Login OAM failed.Please check your ENV")
            db_print("########################################")
        active_oswp = '1' if oswp == '2' else '2'
        Commands = [
            "exit all",\
            "admin software-mngt oswp " + active_oswp + " commit",\
            "admin software-mngt oswp " + oswp + " abort-download",\
            "configure system security filetransfer protocol tftp",\
            "configure system security profile isadmin terminal-timeout 120",\
            "configure software-mngt oswp " + oswp + " primary-file-server-id " + serverip ,\
            "exit all"
        ]
        print Commands
        for command in Commands:
            exp.sendline(command)
            time.sleep(4)
            try:
                exp.expect(["#","$"])
            except:
                db_print("Warning, no prompt retrieve")
                db_print(str(exp.eof()))
        time.sleep(5)
        while True:
            exp.sendline("admin software-mngt oswp %s download %s" % (oswp, oswpIndex))
            #t0 = time.time()

            try:
                ret = exp.expect(["SWDB MGT error 22", "SWDB MGT error 18"], timeout=10)
            except:
                db_print("Download CLI command is OK")
                break
            if ret:
                time.sleep(30)
                exp.sendline("admin software-mngt oswp %s abort-download" % oswp)
            time.sleep(15)
        exp.sendline("show software-mngt oswp %s" % oswp)
        trycounts = 0
        while True:
            try:
                ret = 10
                ret = exp.expect(["%s.*enabled " % oswp,"%s.*disabled " % oswp,"%s.*empty " % oswp], timeout = 60)
            except Exception as inst:
                trycounts += 1
                #db_print("Enabled or Disabled or Empty can not match:%s" %inst)
            if ret == 2:
                db_print("Download state is empty, result is %s" % ret)
                break 
            if ret == 0 or ret == 1:
                db_print("Download finished, result is %s" % ret)
                break
            else:
                if trycounts > 360:
                    db_print("60 mins passed. downloading still not completed.Skip this download")
                    break
                time.sleep(10)
                exp.sendline("show software-mngt oswp %s" % oswp)
        exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
        exp.close()
        del exp
        if ret == 0:
            result = True
        else:
            result = False
        if ret ==1:
            errorCode = '503'
        if ret ==2:
            errorCode = '504'
    t1 = time.time()
    if result:
        db_print("Download success")
        return (True, time.localtime(t1 - t0))
    else:
        db_print("Download fail")
        # 502 means download failure
        #if not toolOnly:/* Commented for Tools Upgrade */
        #    reportJobInstantStatus(jobname,jobNum,'002',errorCode)
        return (False, time.localtime(t1 - t0))


def activateOSWP(shelfIp,oswp,product,toolOnly = False,moswa_list=[],password='isamcli!',mode='default'):
    #jobname = os.environ['JOB_NAME'] /* Commented for Tools Upgrade */
    #jobNum = os.environ['BUILD_NUMBER']
    #if not toolOnly:
    #    reportJobInstantStatus(jobname,jobNum,'003')
    global exp
    result = True
    errorCode = '505'
    t0 = time.time()
    if product in ['SDFX','SDOLT','NCDPU']:
        if not moswa_list:
            result = True
            return(result,0)
        try:
            board_arg_list = copy.deepcopy(moswa_list)
            if len(board_arg_list) == 1:
                moswa_dict = board_arg_list[0]
                moswa_dict.pop('role','SINGLE')
                moswa_board = Smartlab_Instance(moswa_dict)
                moswa_board.NAME = Get_MOSWA_NAME()
                moswa_board.URL = Get_MOSWA_URL()
                active_name = moswa_board._get_active_name(getlist=moswa_board.check_state())
                if not moswa_board.NAME == active_name:
                    moswa_board.active_build()
                    moswa_board.commit_build()
                    moswa_board.clean_env()
            else:
                nt_active_list = []
                lt_active_list = []
                lt_keep_list = []
                loop_mode = 'abort'
                for moswa_dict in board_arg_list:
                    board_role = moswa_dict.pop('role','SINGLE')
                    moswa_board = Smartlab_Instance(moswa_dict)
                    moswa_board.NAME = Get_MOSWA_NAME()
                    moswa_board.URL = Get_MOSWA_URL()
                    active_name = moswa_board._get_active_name(getlist=moswa_board.check_state())
                    
                    if board_role == 'NT':
                        if not moswa_board.NAME == active_name:
                            nt_active_list.append(moswa_board)
                    else:
                        lt_keep_list.append(moswa_board)
                        if not moswa_board.NAME == active_name:
                            lt_active_list.append(moswa_board)
                if nt_active_list and len(lt_active_list) >= 2:
                    loop_mode = 'continue'
                Smartlab_Instance.board_event_loop('active_build_parallel',lt_active_list,loop_mode=loop_mode)
                if nt_active_list:
                    for nt_upd in nt_active_list:
                        nt_upd.active_build()
                    for lt_plan in lt_keep_list:
                        nt_upd.plan_sub_board(lt_plan.plan_rpc)
                Smartlab_Instance.board_event_loop('commit_build_parallel',nt_active_list + lt_keep_list,loop_mode=loop_mode)    
                if nt_active_list:
                    for nt_upd in nt_active_list:        
                        nt_upd._draw_attention(statement="Additional Step 'reboot LT board' For work around FR ALU02604280")
                    Smartlab_Instance.board_event_loop('reboot_board_parallel',lt_keep_list,loop_mode=loop_mode)
                    
                for moswa_board in nt_active_list + lt_keep_list:
                    moswa_board.clean_env()
        except Exception as inst:
            db_print("activate moswa with exception:%s" %inst)
            result = False
    else:
        exp = pexpect.spawn('telnet %s' % shelfIp)
        exp.timeout = 60
        exp.logfile_read = sys.stdout
        if not login():
            db_print("########################################")
            db_print("Login OAM failed.Please check your ENV")
            db_print("########################################")
        #based on different nt type, wait more time for delayed restart
        max_sleep_time = 120
        exp.sendline("show equipment slot")
        try:
            ret=exp.expect(['fant-f','fant-g','fant-h',pexpect.EOF,pexpect.TIMEOUT])
            if ret == 0 or ret == 1 or ret == 2:
                max_sleep_time = 420
        except:
            pass

        retryTimes = 0
        maxRetryTime = 30
        exp.sendline("\r")
        db_print("acitve oswp %s" % oswp)
        db_print("count:%s" %retryTimes)
        while retryTimes < maxRetryTime:
            if mode == 'default':
                exp.sendline("admin software-mngt oswp %s activate with-default-db" % oswp)
                db_print("acitve with default DB")
            elif mode == 'linked':
                exp.sendline("admin software-mngt oswp %s activate with-linked-db" % oswp)
                db_print("acitve with linked DB")
            else:
                db_print("Nothing done")
                sys.exit(0)

            try:
                #exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
                ret = exp.expect(["SWDB MGT error 25","Error : resource is currently held by one manager"])
                print 'expect end with %d' %ret
            except :
                db_print("count:%s" %retryTimes)
                db_print("activate executed successfully!")
                break
            db_print("count:%s" %retryTimes)
            retryTimes = retryTimes + 1
            time.sleep(15)
        exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
        #db_print('wait for 4 seconds for oswp activation')
        #time.sleep(4)
        db_print('wait for %s seconds for oswp activation' %max_sleep_time)
        time.sleep(max_sleep_time)
        #_get_oswp_info(shelfIp,oswp,product)
        exp.close()
        del exp
        result = True
    t1 = time.time()
    db_print("ISAM oswp activate finished")
    #if not result and not toolOnly:/* Commented for Tools Upgrade */
    #    reportJobInstantStatus(jobname,jobNum,'003',errorCode)
    return (result, time.localtime(t1 - t0))

def checkDiskSyncForRedundancy(server_ip,oam_ip):
    global exp
    cmd="\"inic showStates\""
    syncCheck = False
    syncComplete = False
    exp = pexpect.spawn('telnet %s' % oam_ip)
    exp.timeout = 60
    exp.logfile_read = sys.stdout
    if not login():
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

def initializeDUT(craftIp, craftPort, oam_ip, initCommands, extraCommands,product,toolOnly=False): 
    #jobname = os.environ['JOB_NAME']
    #jobNum = os.environ['BUILD_NUMBER']
    #if not toolOnly:
    #    reportJobInstantStatus(jobname,jobNum,'004')
    global telnetTn
    result = True
    errorCode = '506'
    if not check_nt_type(oam_ip):
        db_print("10mins passed and OAM is not reachable and try logging on craft port server")
        #if not toolOnly:
        #     errorCode = '509'
        #     reportJobInstantStatus(jobname,jobNum,'004',errorCode)
    if product in ['SDFX','SDOLT','NCDPU']:
        return True 
    if not pingIp(oam_ip):
        if craftIp.strip():
            configoam = True
            if len(craftPort) == 5:
                db_print("LANTRONICS GICI")
                lant_cmd(craftIp,craftPort)
            else:
                db_print("DIGI GICI")
                #cmd = '\"kill %s\"' % craftPort[2:4]  
                #os.system('(sleep 1;echo "root";sleep 1;echo "dbps";sleep 1;echo %s;sleep 1;echo "exit";sleep 1) | telnet %s' % (cmd, craftIp))
                cmd = 'python -u %s/clearConsolePort.py --serverip %s --port %s' %(SCRIPT_PATH,craftIp,craftPort)
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                db_print(result)   
        else :
            configoam = False
            db_print("30mins passed and OAM is not reachable and no craft port provided for oam configuration!")
            #if not toolOnly:/* Commented for Tools Upgrade */
            #    reportJobInstantStatus(jobname,jobNum,'004',errorCode)
            return False
    else:  
        configoam = False
    #now change default passwd
    retryTimes = 0
    systemReady = False

    while True and retryTimes < 40:
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
            time.sleep(15)
            retryTimes = retryTimes + 1
    if not systemReady:
        db_print("10mins passed and can not log on system with login prompt!")
        #if not toolOnly:/* Commented for Tools Upgrade */
        #    reportJobInstantStatus(jobname,jobNum,'004',errorCode)
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
                Telnet_send(Username)
                returnTmp = telnetTn.read_until("password:",3)              
                continue
            elif "enter new password:" in returnTmp:
                Telnet_send(passwd)
                returnTmp = telnetTn.read_until("*",3)
                db_print(returnTmp, "recv")
                continue
            elif "re-enter  password:" in returnTmp:
                Telnet_send(passwd)
                returnTmp = telnetTn.read_until("*",3)
                db_print(returnTmp, "recv")             
                continue
            elif "password:" in returnTmp:
                if passwd_count == 0:
                    Telnet_send(PasswordDefault)
                else:
                    Telnet_send(passwd)
                returnTmp = telnetTn.read_until("*",3)
                if "Login incorrect" in returnTmp:
                    db_print(returnTmp, "recv")
                    db_print("login with cli password")
                    passwd_count = passwd_count + 1
                    Telnet_send(Username)
                    returnTmp = telnetTn.read_until("*",1)
                    db_print(returnTmp, "recv")
                    if passwd_count > 1:
                        raise Exception()
                if "enter new password:" in returnTmp:
                    Telnet_send(passwd)
                    returnTmp = telnetTn.read_until("*",3)
                    db_print(returnTmp, "recv")
                if "re-enter  password:" in returnTmp:
                    Telnet_send(passwd)
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
                db_print("Warnning : The abnormal scenario in openCli():%s" % returnTmp)
                retryTimes = retryTimes + 1
                if (retryTimes  >= 25):
                    telnetTn.close()
                    #if not toolOnly:/* Commented for Tools Upgrade */
                    #    reportJobInstantStatus(jobname,jobNum,'004',errorCode)
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
                #if not toolOnly:/* Commented for Tools Upgrade */
                #    reportJobInstantStatus(jobname,jobNum,'004',errorCode)
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
    db_print("Telent CLI success with password changed")
    t3 = time.time()

    if configoam:
        cliOut = ''
        for command in initCommands:
            cliOut = sendCliCmd(command)
            if 'admin save' in command and not 'Completed' in cliOut:
                time.sleep(5)
            elif 'admin software-mngt ihub database save-protected' in command and 'SWDB MGT error' in cliOut:
                time.sleep(10)
            else:
                time.sleep(3)
    db_print('extra config commands')
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
            db_print("DIGI GICI")
            cmd = 'python -u %s/clearConsolePort.py --serverip %s --port %s' %(SCRIPT_PATH,craftIp,craftPort)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            db_print(result)
    time.sleep(60)
    if not pingIp(oam_ip):
        db_print('%s is not reachable after oam config, so check the env!' % oam_ip)
        #if not toolOnly:
        #    reportJobInstantStatus(jobname,jobNum,'004',errorCode)
        return False
  

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

def db_print(printStr, debugType="normal"):
    if debugType=="recv" :
        print  ("<<<" + printStr)
    elif debugType=="send" :
        print  (">>>" + printStr)
    else:
        print  ("---" + printStr)

def login(Username='isadmin',passwd='isamcli!',Password2="      " ,PasswordDefault="i$@mad-"):
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
        db_print('login successfully')
        return True
    except:
        return False

def sendCliCmd(cmd):
  retBuf = send_telCmd(cmd)
  db_print(retBuf, "recv")
  return retBuf

def _adjust_link_speed(oam_ip,product):
    global exp
    if product in ['SDFX','SDOLT','NCDPU']:
        return True
    systemup = True
    exp = pexpect.spawn('telnet %s' % oam_ip)
    exp.timeout = 60
    exp.logfile_read = sys.stdout
    if not login():
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
                exp = pexpect.spawn('telnet %s' % oam_ip)
                exp.timeout = 60
                exp.logfile_read = sys.stdout
                if not login():
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

def _backup_db_before_activation(build,shelfIp,dbBackup,dbServer,product):
    global exp
    if product in ['SDFX','SDOLT','NCDPU']:
        return
    exp = pexpect.spawn('telnet %s' % shelfIp)
    exp.timeout = 60
    exp.logfile_read = sys.stdout
    if not login():
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
            exp.sendline("admin software-mngt database upload actual-active:135.252.245.44:dm_%s.tar" % db)
        time.sleep(180)
        db_print("Actual database backup as dm_%s.tar" %db)
    exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
    exp.close()
    del exp

def _get_oswp_index(build,shelfIp,product,password='isamcli!'):
    global exp
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
    oswpIndex = 'L6GPAA' + i1 + '.' + i2
    oswpIndex1 = 'l6gpaa' + i1 + '.' + i2
    oswpIndex2 = 'L6GPAA' + i1 + '.' + i2
    oswpIndex3 = 'L6GPAB' + i1 + '.' + i2
    oswpIndex4 = 'L6GPAC' + i1 + '.' + i2
    oswpIndex5 = 'L6GPAE' + i1 + '.' + i2
    oswpIndex6 = 'L6GPAH' + i1 + '.' + i2
    oswpIndex7 = 'L6GPAD' + i1 + '.' + i2
    oswpIndex8 = 'L6GPAI' + i1 + '.' + i2

    exp = pexpect.spawn('telnet %s' % shelfIp)
    exp.timeout = 60
    exp.logfile_read = sys.stdout
    if not login():
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

  
def _get_oswp_info(shelfIp,product,password='isamcli!'):
    global exp
    if product in ['SDFX','SDOLT','NCDPU']:
        return []
    db_print('args are:%s:%s' %(shelfIp,password))
    n = 0
    exp = pexpect.spawn('telnet %s' % shelfIp)
    exp.timeout = 60
    exp.logfile_read = sys.stdout
    if not login():
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
                stdby_index = '2'
                stdby_oswp = ''
                stdby_status = 'enabled'
                #if not (tmp1[2] == 'active' or tmp2[2] == 'active'):
                #    db_print("oswp status not stable yet:%s:%s" %(tmpList[0],tmpList[1]))
                #    time.sleep(10)
                #    num_try = num_try + 1
                #    continue
                #check act-act-nt
                if tmp1[2] == 'act-act-nt' or tmp2[2] == 'act-act-nt':
                    db_print("oswp status not stable yet:%s:%s" %(tmpList[0],tmpList[1]))
                    time.sleep(10)
                    num_try = num_try + 1
                    continue
                if tmp1[2] == 'active':
                    active_oswp = tmp1[0]
                    active_status = tmp1[1]
                    stdby_oswp = stdby_oswp if tmp2[0] == 'NO_OSWP' else tmp2[0]
                    stdby_status = tmp2[1]
                else :
                    active_index = '2'
                    active_oswp = tmp2[0]
                    active_status = tmp2[1]
                    stdby_index = '1'
                    stdby_oswp = stdby_oswp if tmp1[0] == 'NO_OSWP' else tmp1[0]
                    stdby_status = tmp1[1]

                
                oswp_entry={}                 
                oswp_entry['index'] = active_index
                oswp_entry['oswpIndex'] = active_oswp
                oswp_entry['status'] = active_status
                oswp_info.append(oswp_entry)
                oswp_entry={}
                oswp_entry['index'] = stdby_index
                oswp_entry['oswpIndex'] = stdby_oswp
                oswp_entry['status'] = stdby_status
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
            stdby_index = '2'
            stdby_oswp = ''
            stdby_status = 'enabled'
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
                stdby_oswp = stdby_oswp if tmp2[0] == 'NO_OSWP' else tmp2[0]
                stdby_status = tmp2[1]
            else:
                active_index = '2'
                active_oswp = tmp2[0]
                active_status = tmp2[1]
                stdby_index = '1'
                stdby_oswp = stdby_oswp if tmp1[0] == 'NO_OSWP' else tmp1[0]
                stdby_status = tmp1[1]   
            oswp_entry={}                 
            oswp_entry['index'] = active_index
            oswp_entry['oswpIndex'] = active_oswp
            oswp_entry['status'] = active_status
            oswp_info.append(oswp_entry)
            oswp_entry={}
            oswp_entry['index'] = stdby_index
            oswp_entry['oswpIndex'] = stdby_oswp
            oswp_entry['status'] = stdby_status
            oswp_info.append(oswp_entry)    
        except Exception as inst:
            pass    
    return oswp_info

def clearOSWP(shelfIp,product,password='isamcli!'):
    global exp
    if product in ['SDFX','SDOLT','NCDPU']:
        db_print("this version skip")
        return [True,0]
    db_print('args are:%s:%s' %(shelfIp,password))
    n = 0
    exp = pexpect.spawn('telnet %s' % shelfIp)
    exp.timeout = 60
    exp.logfile_read = sys.stdout
    if not login():
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

def configDUT(shelfIp,commandType,product,action='add',linux_ip=None,username='atxuser',passwd='alcatel01',port='22'):
    if product in ['SDFX','SDOLT','NCDPU']:
        return
    lines=[]
    if commandType == 'banner':
        try:
            jobname = os.environ['JOB_NAME']
        except Exception as inst:
            print 'failure to get jobname'
            jobname = 'smartservice'
        if action == 'add':
            lines.append('configure system id %s' %jobname)
            lines.append('configure system security login-banner \"+++++ %s - %s +++++\"' %(jobname,jobname))
            lines.append('configure system security welcome-banner \"+++++ This platform is restricted for smart service usage, unprivileged login should be forbidden!+++++\"')
        else:
            lines.append('configure system no id')
            lines.append('configure system security no login-banner')
            lines.append('configure system security no welcome-banner') 
    else:
        try :
            old_workspace = os.environ['WORKSPACE']
            workspace = re.sub(r'([\(|\)])',r'\\\1',workspace)
        except Exception as inst:
            print 'failure to get workspace'
            workspace = '/tmp'
        
        cmd_file = '%s_commands' %commandType
        try:
            cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:~/configs/%s %s" %(passwd,port,username,linux_ip,cmd_file,workspace)
            result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            db_print("\n%s with output:%s" %(cmd,result))
            #ssh_scp_get(ip=linux_ip,username=username,password=passwd,port=int(port),local=jenkins_summary,remote=os.path.join('~',timeStamp,'testsummary.log'))
            aFile = open(os.path.join(old_workspace,cmd_file),'r')
            lines = aFile.readlines()
            for idx in xrange(0,len(lines)):
                lines[idx] = lines[idx].strip('\n')
        except Exception as inst:
            print "did not get configuration commands from pcta machine"
    if not lines:
        return

    global exp
    db_print('equipment configuration before download oswp')
    n = 0
    exp = pexpect.spawn('telnet %s' % shelfIp)
    exp.timeout = 10
    exp.logfile_read = sys.stdout
    if not login():
        db_print("########################################")
        db_print("Login OAM failed.Please check your ENV")
        db_print("########################################")
        return False
    for line in lines:
        exp.sendline(line)
        db_print(line)
        time.sleep(4)
        try:
            exp.expect(["#","$"])
        except:
            db_print("Warning, no prompt retrieve")
            db_print(str(exp.eof()))

    exp.sendline("exit all")
    db_print("exit all")
    time.sleep(10)
    exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
    #time.sleep(30)
    exp.close()
    del exp


def processBatchCommandSimple(batchCommand,**args):
    #print args
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
    if batchCommand.find('/ATX/bin/atx') != -1 :
        runType = 'ATX' 
    elif batchCommand.find('pybot') != -1 :
        runType = 'PYBOT'
    else:
        runType = 'LTB'
    commandList = []
    #print 'suiteRerun is %s' %suiteRerun
    if runType == 'ATX':
        #observing atx script,only with two branches, either robot only or apme only
        if re.search(r'[\s|\b]+-framework[\s|\b]+?ROBOT',batchCommand) :
            robotRun = True
            apmeRun = False
        else:
            robotRun = False
            apmeRun = True
        batchCommandList=batchCommand.split(';')
        for i in range(0,len(batchCommandList)):
            if release :
                batchCommandList[i] = re.sub(r'-release[\s|\b]+?[\d|\.]{3,6}','-release ' + release,batchCommandList[i])
            #if domain :
            #    batchCommandList[i] = re.sub(r'-domainlist[\s|\b]+?[\S]+','-domainlist ' + domain,batchCommandList[i])
            #if loadinfo == 'load' :
            #    batchCommandList[i] = re.sub(r'-load[\s|\b]+?[\S]+','-load SD_' + build + '.tar',batchCommandList[i])
            #else:
            #    batchCommandList[i] = re.sub(r'-load[\s|\b]+?[\S]+','-noload',batchCommandList[i])
            if testRun == 'true' :
                batchCommandList[i] = batchCommandList[i] + ' -testrun'
            else :
                batchCommandList[i] = batchCommandList[i] + ' -updateid %s' %build
            batchCommandList[i] = batchCommandList[i] + ' -noload'
        #if domain is empty,return command list directly
        if not domain :
            commandList = batchCommandList
            return commandList
        domainList = domain.split(',')
        #if domain is not empty and command list is more than 2, return directly
        if len(batchCommandList) >= 2:
            commandList = batchCommandList
            return commandList
        #precondition is that if multiple domain,only 1 command
        #if domainSplit == 'true':
        #    for item in domainList:
        #        commandList.append(batchCommand[-1] + ' -domainlist ' + item)
        #    return commandList
        #else :
        #    commandList.append(batchCommand[-1] + ' -domainlist ' + domain)
        #    return commandList
        robotVarList = []
        domainRobotList = []
        domainOtherList = []
        #print domainList
        #print 'robotRun is ' + str(robotRun)
        #print 'apmeRun is ' + str(apmeRun)
        if domainSplit == 'true' :
            for item in domainList:
                splitdomainRobotList=[]
                splitdomainOtherList=[]
                if robotRun :
                    splitdomainRobotList.append(item)
                else:
                    splitdomainOtherList.append(item)
                domainCommand = _getdomainCommand(batchCommandList[0],runType,splitdomainRobotList,splitdomainOtherList,robotVarList)
                commandList.append(domainCommand)
               
        else:
            if robotRun:
                domainRobotList = domainList
            else:
                domainOtherList = domainList
            domainCommand = _getdomainCommand(batchCommandList[0],runType,domainRobotList,domainOtherList,robotVarList)
            commandList.append(domainCommand)        
    elif runType == 'PYBOT':
        robotVarList = []
        domainRobotList = []
        if robotOptions :
            varList = robotOptions.split(',')
            for item in varList:
                tmpList1 = item.split('-',1)
                if tmpList1[0] in ['dryrun'] :
                    if tmpList1[1] == 'enable':
                        itemArg = '--' + tmpList1[0]
                else :
                    itemArg = '--' + tmpList1[0] + ' ' + tmpList1[1]
                    
                robotVarList.append(itemArg)
        if suiteRerun == 'true':
            robotVarList.append('--rerunfailed')
        if robotCaseList:
            robotVarList.append('--argumentfile ' + robotCaseList)
        for item in domainList:
            domainRobotList.append('--include ' + item)
        domainCommand = _getdomainCommand(batchCommand,runType,domainRobotList,domainOtherList,robotVarList)
        commandList.append(domainCommand)
    else:
        batchCommandList=batchCommand.split(';')
        for i in range(0,len(batchCommandList)):
            if release :
                batchCommandList[i] = re.sub(r'-R[\s|\b]+?[\d|\.]{3,6}','-R ' + release,batchCommandList[i])
            if coverage in ['Smoke','Daily','Weekly'] :
                batchCommand = re.sub(r'-T[\s|\b]+?[\w]{5,6}','-T ' + coverage,batchCommand)
                if not re.search('-T[\s|\b]+?',batchCommand):
                    batchCommand += ' -T ' + coverage
            if not testRun == 'true':
                batchCommandList[i] = batchCommandList[i] + ' -b ' + build
        if len(batchCommandList) >= 2:
            #if there are more than 3 LTB commands, means do not process the LTB command
            print 'for more than 1 LTB commands,return LTB command directly without processing'
            return batchCommandList
        #if domain:
        #    res = re.search(r'(-d[\s|\b]+?([\S]+))',batchCommand)
        #    domain_is_robot = True if domain.find(
        #    if not res:
        #        batchCommand = batchCommand + ' -d %s' %domain
        #    else:
        #        res1 = re.search(r'(ROBOT:[^,]+)',res.group(1))
        #        batchCommand = batchCommand.replace(res.group(1), '-d ' + domain + ',' + res1.group(1)) if res else batchCommand.replace(res.group(1), '-d ' + domain)
        #below only support one command list
        apmeRun = False if re.search(r'[\s|\b]+-a',batchCommand) else True
        robotRun = True if re.search(r'[\s|\b]+--framework[\s|\b]+?ROBOT',batchCommand) else False
        #print 'apmeRun is %s' %apmeRun
        #print 'robotRun is %s' %robotRun
 
        domainRobotList=[]
        domainOtherList=[]
        domainList=[]

        if domain :
            domainList = domain.split(',')
            if robotRun :
                #robot only or robot/apme mixed run(not supported now)
                domainRobotList = domainList
            elif apmeRun:
                #apme only
                domainOtherList = domainList
            else:
                print 'Sorry wrong combination, return directly'
                return []
                

        robotVarList = []
        #if robot run robotVarlist will be handled else empty
        if robotRun:
            if robotOptions :
                varList = robotOptions.split(',')
                for item in varList:
                    robotVarList.append(item)
            if suiteRerun == 'true':
                robotVarList.append('rerunfailed-enable')
            if robotCaseList:
                robotVarList.append('argumentfile-' + robotCaseList)

        for batchCommand in batchCommandList:
            if not domainList:
                domainCommand = _getdomainCommand(batchCommand,runType,domainRobotList,domainOtherList,robotVarList)
                commandList.append(domainCommand)
                continue
            if domainSplit == 'true' :
                for item in domainList:
                    splitdomainRobotList=[]
                    splitdomainOtherList=[]
                    if robotRun :
                        splitdomainRobotList.append(item)
                    else:
                        splitdomainOtherList.append(item)
                    domainCommand = _getdomainCommand(batchCommand,runType,splitdomainRobotList,splitdomainOtherList,robotVarList)
                    commandList.append(domainCommand)
               
            else:
                domainCommand = _getdomainCommand(batchCommand,runType,domainRobotList,domainOtherList,robotVarList)
                commandList.append(domainCommand)
    return commandList 

def processCommonOptions(runType,batchCommand,release,coverage,testRun,build,extraTar=''):
    #remove APME: or ROBOT first
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
        else:
            batchCommand = re.sub(r'-T[\s|\b]+?[\w]{5,6}','',batchCommand)
        if not testRun == 'true':
            batchCommand = batchCommand + ' -b ' + build + ' -u ' + "smartlab"
        if extraTar and not re.search('--framework[\s\t]+ROBOT',batchCommand):
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
    if batchCommand.find('/ATX/bin/atx') != -1 :
        runType = 'ATX' 
    elif batchCommand.find('pybot_launcher') != -1 :
        runType = 'PYBOT_LAUNCHER'
    elif batchCommand.find('pybot') != -1 :
        runType = 'PYBOT'
    else:
        runType = 'LTB'
    #domainMode = 'INC'
    #caseMode = 'INC'
    commandList = []
    commandDomainList = []
    if update_build !='NONE':
        build=update_build
    print 'suiteRerun is %s' %suiteRerun
    if runType == 'ATX':
        batchCommandList=batchCommand.split(';')
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
        domainList = domain.split(',')
        #if domain is not empty and command list is more than 2, return directly
        if len(batchCommandList) > 2:
            commandList = batchCommandList
            return (commandList,commandDomainList)

        robotVarList = []
        domainRobotList = []
        domainOtherList = []
        for batchCommand in batchCommandList:
            #observing atx script,only with two branches, either robot only or apme only
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
        batchCommandList=batchCommand.split(';')
        
        for i in range(0,len(batchCommandList)):
            batchCommandList[i] = processCommonOptions(runType,batchCommandList[i],release,coverage,testRun,build,extraTar)
            #process -G in LTB
            if oamIP and hostFlag:
                batchCommandList[i] = re.sub(r'-G[\s|\b]+?[\S]+','-G ' + oamIP,batchCommandList[i])
            #for -v handling,only with -v, then we have Creating/Updating /tftpboot/atx/atxuser/....
            if not re.search('-v',batchCommandList[i]):
                batchCommandList[i] += ' -v'
        #from Smartlab Service 2.1,remove
        if len(batchCommandList) > 2:
            #if there are more than 3 LTB commands, means do not process the LTB command
            print 'for more than 1 LTB commands,return LTB command directly without processing'
            return (batchCommandList,commandDomainList)

        domainList=[]

        if domain :
            domainList = domain.split(',')   

        for batchCommand in batchCommandList:
            domainRobotList=[]
            domainOtherList=[]
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
                robotVarList = _map_jenkins_var_to_robot_options(runType,suiteRerun,robotCaseList,caseMode,robotOptions)
                
            if not domainList:
                domainCommand = _getdomainCommand(batchCommand,runType,domainRobotList,domainOtherList,robotVarList)
                commandList.append(domainCommand)
                continue
            if domainList and not domainMode == 'INC':
                for item in domainList:
                    robotVarList.append('exclude-' + item)
                domainCommand = _getdomainCommand(batchCommand,runType,[],domainOtherList,robotVarList)
                commandList.append(domainCommand)
                continue
            if domainSplit == 'true' :
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
                domainCommand = _getdomainCommand(batchCommand,runType,domainRobotList,domainOtherList,robotVarList)
                commandList.append(domainCommand)
    return (commandList,commandDomainList)

def processBatchCommand(batchCommand,**args):
    #print args
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
    if batchCommand.find('/ATX/bin/atx') != -1 :
        runType = 'ATX' 
    elif batchCommand.find('pybot') != -1 :
        runType = 'PYBOT'
    else:
        runType = 'LTB'
    commandList = []
    print 'suiteRerun is %s' %suiteRerun
    if runType == 'ATX':
        if release :
            batchCommand = re.sub(r'-release[\s|\b]+?[\d|\.]{3,6}','-release ' + release,batchCommand)
        if domain :
            batchCommand = re.sub(r'-domainlist[\s|\b]+?[\S]+','-domainlist ' + domain,batchCommand)
        if loadinfo == 'load' :
            batchCommand = re.sub(r'-load[\s|\b]+?[\S]+','-load SD_' + build + '.tar',batchCommand)
        else:
            batchCommand = re.sub(r'-load[\s|\b]+?[\S]+','-noload',batchCommand)
        if testRun == 'true' :
            batchCommand = batchCommand + ' -testrun'
        else :
            batchCommand = batchCommand + ' -updateid %s' %build
    else:
        batchCommandList=batchCommand.split(';')
        for i in range(0,len(batchCommandList)):
            if release :
                batchCommandList[i] = re.sub(r'-R[\s|\b]+?[\d|\.]{3,6}','-R ' + release,batchCommandList[i])
            if coverage :
                batchCommandList[i] = re.sub(r'-T[\s|\b]+?[\w]{5,6}','-T ' + coverage,batchCommandList[i])
            if not testRun == 'true':
                batchCommandList[i] = batchCommandList[i] + ' -b ' + build
        if len(batchCommandList) >= 3:
            #if there are more than 3 LTB commands, means do not process the LTB command
            print 'return LTB command directly'
            return batchCommandList
        #if domain:
        #    res = re.search(r'(-d[\s|\b]+?([\S]+))',batchCommand)
        #    domain_is_robot = True if domain.find(
        #    if not res:
        #        batchCommand = batchCommand + ' -d %s' %domain
        #    else:
        #        res1 = re.search(r'(ROBOT:[^,]+)',res.group(1))
        #        batchCommand = batchCommand.replace(res.group(1), '-d ' + domain + ',' + res1.group(1)) if res else batchCommand.replace(res.group(1), '-d ' + domain)
        domainRobotList=[]
        domainOtherList=[]
        domainList=[]
        if domain :
            domainList = domain.split(',')
            for item in domainList:
                res = re.search(r'ROBOT:([\S]+)',item)
                if res :
                    domainRobotList.append(res.group(1))
                else:
                    domainOtherList.append(item)

        robotVarList = []
        if robotOptions :
            varList = robotOptions.split(',')
            for item in varList:
                robotVarList.append(item)
        if suiteRerun == 'true':
            robotVarList.append('rerunfailed-enable')
        if robotCaseList:
            robotVarList.append('argumentfile-' + robotCaseList)

        if len(batchCommandList) == 2:
            for batchCommand in batchCommandList:
                res = re.search('--framework[\s]+ROBOT',batchCommand)
                if res:
                    #if no robot Domain,use one LTB command without -d option
                    if not domainRobotList:
                        domainCommand = _getdomainCommand(batchCommand,[],[],robotVarList)
                        commandList.append(domainCommand)
                        continue
                    #if with ROBOT:NOTRUN,do not run robot LTB
                    if domainRobotList.count('NOTRUN') != 0:
                        db_print('Do not run this command for ROBOT:%s' %batchCommand)
                        continue
                    #with robot Domain, also no NOTRUN option
                    if domainSplit == 'true' :
                        for item in domainRobotList:
                            splitdomainRobotList=[item]
                            domainCommand = _getdomainCommand(batchCommand,splitdomainRobotList,[],robotVarList)
                            #print domainCommand
                            commandList.append(domainCommand)
                    else:
                        domainCommand = _getdomainCommand(batchCommand,domainRobotList,[],robotVarList)
                        commandList.append(domainCommand)
                else:
                    if not domainOtherList:
                        domainCommand = _getdomainCommand(batchCommand,[],[],[])
                        commandList.append(domainCommand)
                        continue
                    #if with NOTRUN,do not run robot LTB
                    if domainOtherList.count('NOTRUN') != 0:
                        db_print('Do not run this command for APME:%s' %batchCommand)
                        continue
                    #with apme Domain, also no NOTRUN option
                    if domainSplit == 'true' :
                        for item in domainOtherList:
                            splitdomainOtherList=[item]
                            domainCommand = _getdomainCommand(batchCommand,[],splitdomainOtherList,[])
                            commandList.append(domainCommand)
                    else:
                        domainCommand = _getdomainCommand(batchCommand,[],domainOtherList,[])
                        commandList.append(domainCommand)
        else:
            #one LTB command
            for batchCommand in batchCommandList:
                if not domainList:
                    domainCommand = _getdomainCommand(batchCommand,domainRobotList,domainOtherList,robotVarList)
                    commandList.append(domainCommand)
                    continue
                if domainOtherList.count('NOTRUN') != 0 and domainRobotList.count('NOTRUN') != 0:
                    db_print('Do not run this command for APME and ROBOT:%s' % batchCommand)
                    continue
                elif domainOtherList.count('NOTRUN') != 0:
                    db_print('Do not run this command for APME:%s' % batchCommand)
                    domainOtherList=[]
                    batchCommand = _removeDomain(batchCommand,'APME')
                elif domainRobotList.count('NOTRUN') != 0:
                    db_print('Do not run this command for ROBOT:%s' % batchCommand)
                    domainRobotList=[]
                    batchCommand = _removeDomain(batchCommand,'ROBOT')
                if domainSplit == 'true' :
                    for item in domainList:
                        splitdomainRobotList=[]
                        splitdomainOtherList=[]
                        res = re.search(r'ROBOT:([\S]+)',item)
                        if res :
                            splitdomainRobotList.append(res.group(1))
                        else:
                            splitdomainOtherList.append(item)
                        domainCommand = _getdomainCommand(batchCommand,splitdomainRobotList,splitdomainOtherList,robotVarList)
                        commandList.append(domainCommand)
               
                else:
                    domainCommand = _getdomainCommand(batchCommand,domainRobotList,domainOtherList,robotVarList)
                    commandList.append(domainCommand)
    return commandList  

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
    for idx in range(0,len(domainRobotList)):
        domainRobotList[idx] = domainRobotList[idx].lower()
    if runType == 'PYBOT':
        res = re.search('[\s|\b]+?([\S]+)$',batchCommand)
        if not res:
            print '\nThis is a bad pybot command without data source in the end'
            return None
        dataSource = res.group(1)
        batchCommand = re.sub(dataSource,'',batchCommand)
        batchCommand = batchCommand + ' '.join(domainRobotList + robotVarList) + ' ' + dataSource
        return batchCommand
    elif runType == 'PYBOT_LAUNCHER':
        #print batchCommand

        batchCommand = batchCommand + '\n' + '\n'.join(robotVarList + domainRobotList)
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
                    domainOtherList.insert(0,fixDomainList[0][:-1])
                domainRobotList.insert(0,fixDomainList[1])
            else:
                domainOtherList.insert(0,fixDomainList[0])

        if domainRobotList:
            #robot only
            batchCommand = batchCommand + ' -domainlist ROBOT:' + ','.join(domainRobotList + robotVarList)
        else:
            #apme only
            batchCommand = batchCommand + ' -domainlist ' + ','.join(domainOtherList)
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
                domainOtherList.insert(0,fixDomainList[0][:-1])
            domainRobotList.insert(0,fixDomainList[1])
        else:
            domainOtherList.insert(0,fixDomainList[0])

    domainOther = ','.join(domainOtherList)
    if domainOtherList and domainRobotList:
        #mixed robot/apme,not supported now
        domainRobotList += robotVarList
        domainRobot = ','.join(domainRobotList) 
        domainCommand = batchCommand + ' -d %s+ROBOT:%s' %(domainOther,domainRobot)
        #remove all -a option since this is mixed apme and robot
        domainCommand = re.sub('[\s]+-a','',domainCommand)
        if not re.search('--framework',domainCommand):
            domainCommand = domainCommand + ' --framework ROBOT'
    elif domainOtherList:
        domainCommand = batchCommand + ' -d %s' %domainOther
        #remove all -a option since this is mixed apme and robot
        domainCommand = re.sub('[\s]+-a','',domainCommand)
    elif domainRobotList:
        domainRobotList += robotVarList
        domainRobot = ','.join(domainRobotList)
        domainCommand = batchCommand + ' -d ROBOT:%s' %domainRobot
        if not re.search('--framework',domainCommand):
            domainCommand = domainCommand + ' --framework ROBOT'
    else:
        #robotRun, no domain, but with robot variable
        domainRobotList += robotVarList
        domainRobot = ','.join(domainRobotList)
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
            result = ssh2(linuxIP, userName,passwd, domainCommand,True,port=int(linuxPORT))
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
    jobname = os.environ['JOB_NAME']
    jobNum = os.environ['BUILD_NUMBER']
    if domainList:
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
    craftIp = dbDict.setdefault('craftIp','')
    saveTrace = dbDict.setdefault('saveTrace',False)
    team = dbDict.setdefault('team','')
    if craftIp :
        initCommands = dbDict.setdefault('initCommands',[])
        extraCommands =  dbDict.setdefault('extraCommands',[])
        print '----get new initCommands:'
        print initCommands
        print extraCommands
    for batchCommand in commandList:
        idx = commandList.index(batchCommand)
        working_dir = ''
        #for qemu host batch,1st domain will use the qemu working directory
        if idx ==0:
            try:
                cmd = "curl -s %sconsoleText |grep -o -a -E 'qemu is up with working_dir:[[:graph:]]+(root|atxuser)-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[0-9]{8}'|uniq |tail -1" %build_url
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                tmpList = result.split(':',1)
                if len(tmpList) == 2:
                    working_dir = tmpList[1].rstrip('\n')
            except Exception as inst:
                db_print('this is not qemu batch')
                
        extra_tar_file = ''

        try:
            cmd = "curl -s %sconsoleText |grep -o -a -E 'LTB extraTar file:[[:graph:]]+'|uniq |tail -1" %build_url
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            tmpList = result.split(':',1)
            if len(tmpList) == 2:
                extra_tar_file = tmpList[1].rstrip('\n')
        except Exception as inst:
            db_print('no LTB extraTar file')

        if runType == 'LTB':
            if working_dir:
                #batchCommand = re.sub(r'(launchTestBatch[\S]+)',r'\1 -D ' + working_dir + ' ',batchCommand)
                batchCommand += ' -D %s' %working_dir
            if extra_tar_file:
                batchCommand += ' -K %s' %extra_tar_file
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
        product_type = dbDict['product']
        if saveTrace:
            saveTrace = not isPlatformInGICIMAP()
        if saveTrace:
            start_trace_saver(linuxIP,trace_server_list,product_type)
        ssh2(linuxIP, userName,passwd, domainCommand,port=int(linuxPORT))

        #if domainSplit == 'true':
        #    domain = domainList[idx]
        #    handleRunResult(domain)
        #domain=_getdomain(batchCommand)
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
        res,timeStamp=handleRunResult(domain,platform,runType,linuxIP,linuxPORT,userName,passwd,team,load,storeLog)   
        #reportStatusSocket(smart_srv_ip,smart_srv_port,'domain',job_name,domain)  
        #reportStatus('domain',job_name,job_num,'COMPLETED',domain)
        if not domain:
            #after the last domain is finished, send message for batch
            #reportStatusSocket(smart_srv_ip,smart_srv_port,'batch',job_name) 
            if idx == len(commandList) -1 :
                reportStatus('batch',orig_job_name,job_num,'COMPLETED',timeStamp)
            else:
                reportStatus('batch',orig_job_name,job_num,'partial_completed',timeStamp)
        if defaultDB == 'true' and idx < len(commandList) -1:
            oam_ip = dbDict.setdefault('oam_ip','')
            oswpIndex = dbDict.setdefault('oswpIndex','')
            craftIp = dbDict.setdefault('craftIp','')
            craftPort = dbDict.setdefault('craftPort','')
            dbBackup = dbDict.setdefault('dbBackup',False)
            dbServer = dbDict.setdefault('dbServer','')

            dbMode  = dbDict.setdefault('dbMode','')
            product = dbDict['product']
            #checkDiskSyncForRedundancy(oam_ip)
            #for activate oswp between different domain ,oam ip will not be lost, do not do initialize dut
            if not product in ['NCDPU','SDFX','SDOLT']:
                db_print('backup database before activating oswp after batch run')
                product = dbDict['product']
                _backup_db_before_activation(build,oam_ip,dbBackup,dbServer,product)
                db_print('activate oswp after batch run')
                activateOSWP(oam_ip,oswpIndex,product,True)
            #if no craftIp provided, directly using check_telnet to check ip and configure passwd
                if not craftIp :
                    if not check_telnet(oam_ip):
                        db_print("Can not telnet oam ip after activateOSWP, break from runBatch")
                        result = False
                        break
                else:
                    initializeDUT(craftIp, craftPort,oam_ip,initCommands,extraCommands,product,True)
            #clearOSWP(oam_ip,oswpIndex)
            else:                
                if 'MOSWA_LIST' in dbDict and dbDict['MOSWA_LIST']:
                    db_print("clean db for moswa product and restart")
                    try:
                        board_arg_list = copy.deepcopy(dbDict['MOSWA_LIST'])
                        if len(board_arg_list) == 1:
                            moswa_dict = board_arg_list[0]
                            moswa_dict.pop('role','SINGLE')
                            moswa_board = Smartlab_Instance(moswa_dict)
                            moswa_board.NAME = Get_MOSWA_NAME()
                            moswa_board.URL = Get_MOSWA_URL()
                            moswa_board.clean_db_with_reset_build()
                        else:
                            nt_active_list = []
                            lt_keep_list = []
                            loop_mode = 'abort'
                            
                            for moswa_dict in board_arg_list:
                                board_role = moswa_dict.pop('role','SINGLE')
                                moswa_board = Smartlab_Instance(moswa_dict)
                                moswa_board.NAME = Get_MOSWA_NAME()
                                moswa_board.URL = Get_MOSWA_URL()
                                active_name = moswa_board._get_active_name(getlist=moswa_board.check_state())
                    
                                if board_role == 'NT':
                                    nt_active_list.append(moswa_board)
                                else:
                                    lt_keep_list.append(moswa_board)
                            if nt_active_list and len(lt_keep_list) >= 2:
                                loop_mode = 'continue'
                            Smartlab_Service.clean_db_with_reset_parallel(lt_keep_list)
                            if nt_active_list:
                                for lead_board in nt_active_list:
                                    lead_board.clean_db_with_reset_build()
                                for lt_plan in lt_keep_list:
                                    nt_upd.plan_sub_board(lt_plan.plan_rpc)
                    except Exception as inst:
                        db_print("clean db failed with exception:%s" %inst)        
                        break    
        if saveTrace:
            stop_trace_saver(linuxIP,trace_server_list)
            upload_trace_saver(linuxIP,trace_server_list,team)
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
        db_print('report data:%s' %data)
        #res = requests.post("http://135.251.200.29:30800/api/reportJobStatus",json.dumps(data))
        res = requests.post("%s/api/reportJobStatus" %SMARTLAB_SERVER,json.dumps(data))
        db_print('report res:%s' %res)
    except Exception as inst:
        db_print('report status failure:%s' %inst)

def reportStatus(report_type,job_name,job_num,status,timestamp=None,domain=None):
    try:
        data = {}
        data['jobName'] = job_name
        data['jobNum'] = job_num
        data['currentStatus'] = status
        data['type'] = report_type
        data['timeStamp'] = timestamp
        if report_type == 'domain' and domain:
            data['Domain'] = domain   
        elif report_type == 'batch':
            data['Domain'] = ''
        else:  
            return 
       #res = requests.post("http://smartservice.int.nokia-sbell.com/api/dbOperation",json.dumps(data))
        db_print('report data:%s' %data)
        res = requests.post("%s/api/dbOperation" %SMARTLAB_SERVER,json.dumps(data))
        #res = requests.post("http://135.251.200.29:30800/api/dbOperation",json.dumps(data))
        db_print('report res:%s' %res)
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
    try :
        workspace = os.environ['WORKSPACE']
        workspace = re.sub(r'([\(|\)])',r'\\\1',workspace)
    except Exception as inst:
        print 'failure to get workspace'
        workspace = '/tmp'
    lines=[]
    try:
        cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:~/configs/extra_init_commands %s" %(passwd,port,user,linux_ip,workspace)
        result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        db_print("\n%s with output:%s" %(cmd,result))
        aFile = open(workspace + '/extra_init_commands','r')
        lines = aFile.readlines()
        for idx in xrange(0,len(lines)):
            lines[idx] = lines[idx].strip('\n')
    except Exception as inst:
        #print "no extra init commands"
        pass
    return lines

def handleRunResult(domain,platform,runType,linux_ip,port,username,passwd,team,load='ManualLoad',uploadLog=True): 
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
        build_id = os.environ['BuildIDNew']
        #jenkins_home = os.environ['JENKINS_HOME']
        linux_ip = os.environ['LinuxIP'].split(':')[0]
        platformType = os.environ['PlatformType']
        ftpServer  = os.environ['TftpServer']
        build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)

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
        try:
            #replaced by curl http url directly
            #cmd = "cp -rf %s %s" %(jenkins_log,jenkins_target)
            #result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            #db_print("\n%s with output:%s" %(cmd,result))
            #for uniq timestamp, always get the latest one so tail -1
            #cmd = "cat %s |grep -o -E 'Creating [[:graph:]]+(root|atxuser)-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[0-9]{8}'|uniq |tail -1" %jenkins_target
            time.sleep(5)

            if runType == 'LTB':
                cmd = "curl -s %sconsoleText |grep -o -a -E '(Creating|Updating) [[:graph:]]+(root|atxuser)-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[0-9]{8} directory'|uniq |tail -1" %build_url
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                result = result.strip()
                if not result:
                    return False,'' 
                
                result = result.split(' ')[1].strip()
                timeStamp = os.path.basename(result)
                homeDir = os.path.dirname(result)
                db_print("\n%s with output:%s" %(cmd,timeStamp))
                jenkins_summary = workspace + '/testsummary_' + timeStamp + '.log'
                orig_jenkins_summary = orig_workspace + '/testsummary_' + timeStamp + '.log'
                cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:~/%s/testsummary.log %s" %(passwd,port,username,linux_ip,timeStamp,jenkins_summary)
                result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                db_print("\n%s with output:%s" %(cmd,result))
                
                ####To check log moved to storage or not
                try:
                    #ssh_scp_get(ip=linux_ip,username=username,password=passwd,port=int(linuxPORT),local=jenkins_summary,remote=os.path.join('~',timeStamp,'testsummary.log'))
                    cmd1 = "curl -s %sconsoleText |grep -o -a -E 'Moving [[:graph:]]+(root|atxuser)-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[0-9]{8} to (.*) in /storage success...'|uniq |tail -1" %build_url
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
                        cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --pctaUser %s --pctaPasswd %s --team %s --platform %s --domain %s --timeStamp %s;'" %(logSrv,logTool,build_id,linux_ip,homeDir,port,username,passwd,team,job_name,domain,timeStamp)
                    else:
                        cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --pctaUser %s --pctaPasswd %s --team %s --platform %s --serverNoTimestamp True --domain %s --timeStamp %s;'" %(logSrv,logTool,build_id,linux_ip,logpath,port,username,passwd,team,job_name,domain,timeStamp)        
                    result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                    db_print("\n%s with output:%s" %(cmd,result))
                    
                else:
                    #job_name = re.sub(r'(|)',r'\\\1',job_name)
                    if storage_flag != "True":
                        cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --pctaUser %s --pctaPasswd %s --team %s --platform %s --timeStamp %s;'" %(logSrv,logTool,build_id,linux_ip,homeDir,port,username,passwd,team,job_name,timeStamp)
                    else:
                        cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --pctaUser %s --pctaPasswd %s --team %s --platform %s --serverNoTimestamp True --timeStamp %s;'" %(logSrv,logTool,build_id,linux_ip,logpath,port,username,passwd,team,job_name,timeStamp)    
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
                fd.writelines("\n%s/%s/%s/%s/\n" %(logSrvFqdn,team,build_id,orig_job_name))
                fd.writelines("\n########################################################################")
                fd.close()
                all_jenkins_summary = os.path.join(workspace,'testsummary.log')
                cmd = "cat %s >> %s" %(jenkins_summary,all_jenkins_summary)
                result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                db_print("append testsummary.log \n%s with output:%s" %(cmd,result))
            elif runType == 'PYBOT_LAUNCHER':
                cmd = "curl -s %sconsoleText |grep -o -a -E 'outputdir [[:graph:]]+(root|atxuser)-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[0-9]{8}'|uniq |tail -1" %build_url

                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                result = result.strip()[9:]
                timeStamp = os.path.basename(result)
                jenkins_summary = workspace + '/testsummary_' + timeStamp + '.log'
                orig_jenkins_summary = orig_workspace + '/testsummary_' + timeStamp + '.log'
                homeDir = os.path.dirname(result)
                db_print("\n%s with output:%s" %(cmd,timeStamp))
                cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:~/%s/ROBOT/ATDD_focus.tms %s" %(passwd,port,username,linux_ip,timeStamp,jenkins_summary)
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
                    cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --team %s --platform %s --domain %s --timeStamp %s;'" %(logSrv,logTool,build_id,linux_ip,homeDir,port,team,job_name,domain,timeStamp)
                    result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                    db_print("\n%s with output:%s" %(cmd,result))
                    #reportStatus('domain',job_name,job_num,'COMPLETED',timeStamp,domain)
                else:
                    cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --pcta %s --pctaFolder %s --pctaPort %s --team %s --platform %s --timeStamp %s;'" %(logSrv,logTool,build_id,linux_ip,homeDir,port,team,job_name,timeStamp)
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
                    cmd = "ssh -o StrictHostKeyChecking=no root@%s 'python -u %s --buildID %s --team %s --platform %s --atxIP %s --atxPlatform %s --load %s --testSummaryFile %s --timeStamp %s --domain %s;'" %(logSrv,logTool,build_id,team,job_name,linux_ip,platform,load,timeStamp0,timeStamp,domain)
                else:
                    cmd = "ssh -o StrictHostKeyChecking=no root@%s 'python -u %s --buildID %s --team %s --platform %s --atxIP %s --atxPlatform %s --load %s --testSummaryFile %s --timeStamp %s;'" %(logSrv,logTool,build_id,team,job_name,linux_ip,platform,load,timeStamp0,timeStamp)
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
                fd.writelines("\n%s/%s/%s/%s/\n" %(logSrvFqdn,team,build_id,orig_job_name))
                fd.writelines("\n########################################################################")
                fd.close()

            
            fd_file=os.path.basename(orig_jenkins_summary)    
            fd_file = os.path.join(job_url,'ws',fd_file)
            cmd = "ssh -o StrictHostKeyChecking=no root@%s 'python -u %s --buildID %s --team %s --platform %s --traceFiles %s;'" %(logSrv,logTool,build_id,team,job_name,fd_file)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            db_print("\n%s with output:%s" %(cmd,result))
            if (runType == 'LTB' or runType == 'PYBOT_LAUNCHER') and domain:
                reportStatus('domain',orig_job_name,job_num,'COMPLETED',timeStamp,domain)
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

def updateREPO(linuxIP,userName,passwd,linuxPORT,cstag):
    try :
        cmd = "python -u /var/jenkins_home/scripts/repoUpdatev1.py --pcta %s  --pctaUser %s --pctaPasswd %s --pctaPort %s --csTag %s" %(linuxIP,userName,passwd,linuxPORT,cstag)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        db_print("\n%s with output:%s" %(cmd,result))
    except Exception:
        db_print("testsummary file operation exception :%s!" % str(inst))
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
    reportJobInstantStatus(jobname,jobNum,'007') 
    if hostFlag:
        _cleanQemu(linuxIP,userName,passwd,linuxPORT)
    try:
        cmd1 = 'ps -ef |grep xterm |grep %s |grep -v grep |cut -c 9-15' %oam_ip
        ssh2(linuxIP, userName,passwd, cmd1, port=int(linuxPORT))
        cmd3 = "ps -C octopus |awk \'{print $1}\' |sed -n \'2,$p\' |tr -s '\n' |xargs kill -9"
        #ssh2(linuxIP, 'atxuser','alcatel01', cmd3, port=int(linuxPORT))
        results=subprocess.Popen(cmd3, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        cmd2 = "ps -ef |grep launchTestBatch |grep %s |grep -v grep | awk '{print $2,$3}'" %oam_ip
        results=ssh2(linuxIP, userName,passwd, cmd2,True ,port=int(linuxPORT))
        resultsList = results.split('\n')
        zombiePid = ''
        parentPid = '1'
        for item in resultsList:
            if item.strip():
                pidList = item.strip().split(' ')
                parent = pidList [0]
                if pidList[1] == '1':
                    zombiePid = pidList[0]
                    break
                elif pidList[1] == parentPid:
                    zombiePid = parentPid
                    break
                else:
                    parentPid = pidList[0]
        if zombiePid:
            cmd3 = 'pstree -p %s -A' %zombiePid
            results=ssh2(linuxIP, userName,passwd, cmd3,True,port=int(linuxPORT))
            res = re.findall(r'\(([\d]+)\)',results)
            if res:
                res.reverse()
                cmd4 = 'kill -9'
                for item in res:
                    cmd4 += ' %s' %item
                ssh2(linuxIP,userName,passwd, cmd4,port=int(linuxPORT))
        db_print("zombie pids and child pids have been killed")
        try:
            if linuxPctaexe != '':
                #To retrieve start PCTA process pid
                pcta_cmd="ps -aef | grep pcta.exe | grep -v defunct | grep -v grep | awk '{print $2}'"
                pid=ssh2(linuxIP, userName,passwd,pcta_cmd,True ,port=int(linuxPORT))
                pid=pid.strip()
                #To kill PCTA process pid
                if pid:
                    kill_cmd="sudo /bin/kill -9 %s" %pid
                    ssh2(linuxIP, userName,passwd,kill_cmd,port=int(linuxPORT))
        except Exception as inst:
            db_print("PCTA process kill error:%s" %inst)
    except Exception as inst:
        db_print("post env cleaning error:%s" %inst)

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
            Telnet_send(Username)
            returnTmp = telnetTn.read_until("password:",3)              
            continue
        elif "enter new password:" in returnTmp:
            try:
                Telnet_send(passwd)
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
            Telnet_send(passwd)
            returnTmp = telnetTn.read_until("*",3)
            db_print(returnTmp, "recv")             
            continue
        elif "password:" in returnTmp:
            try:
                Telnet_send(PasswordDefault)
                returnTmp = telnetTn.read_until("*",3)
                if "Login incorrect" in returnTmp: 
                    db_print(returnTmp, "recv")
                    db_print("login with cli password")
                    raise Ex45ception() 
                if "enter new password:" in returnTmp:
                    Telnet_send(passwd)
                    returnTmp = telnetTn.read_until("*",3)
                    db_print(returnTmp, "recv")
                if "re-enter  password:" in returnTmp:
                    Telnet_send(passwd)
                    returnTmp = telnetTn.read_until("*",3)
                    db_print(returnTmp, "recv")             
                    continue
            except: 
                Telnet_send(Username)
                returnTmp = telnetTn.read_until("*",1)
                db_print(returnTmp, "recv")
                Telnet_send(passwd)
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

def updatelaunchTestBatchCmd(batchCommandAtx,linuxIP,username,passwd,linuxPORT):
    batchComlaunchList = filter(lambda str_filter:'launchTestBatch' in str_filter, reduce(lambda str_iter1,str_iter2:str_iter1+str_iter2,map(lambda str_iter:str_iter.split(' '), batchCommandAtx.split(';'))))    
    if len(batchComlaunchList) is not 0 :
        batchComHeadList = filter(lambda str_com:'launchTestBatch' in str_com, batchComlaunchList)
        if len(batchComHeadList) is not 0 :
            batchComHead = batchComHeadList[0]
            #batchComHead = batchComHead.strip('ROBOT:').strip('APME:')
            batchComHead = re.sub(r'^.*?:','',batchComHead)
        else :
            batchComHead = '/repo/atxuser/atc/cm8/auto/tools/pbscript/launchTestBatch' 
        batchComHeadNew = batchComHead
        if len(batchComHead) == len('launchTestBatch'):
            batchComHeadNew = '/repo/atxuser/atc/cm8/auto/tools/pbscript/launchTestBatch' 
        timeStampForBatch = datetime.datetime.now().strftime('%m%d%Y-%H%M%S')          
        runBatchIp = linuxIP
        batchComAtxHead = 'launchTestBatch.' +  timeStampForBatch     
        tempbatchfile = 'launchTestBatchtemp' +  timeStampForBatch 
        cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:%s %s" %(passwd,linuxPORT,username,linuxIP,batchComHeadNew,tempbatchfile)
        db_print(cmd)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        updatelauchTesBatchFile(tempbatchfile,batchComAtxHead,timeStampForBatch)
        cmd = "rm -rf %s" % tempbatchfile
        db_print(cmd)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        cmd = "chmod +x % s" % batchComAtxHead
        db_print(cmd)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s %s@%s:%s" %(passwd,linuxPORT,batchComAtxHead,username,linuxIP,'~/'+batchComAtxHead)
        db_print(cmd)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        cmd = "rm -rf % s" % batchComAtxHead
        db_print(cmd)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        batchCommandAtx = batchCommandAtx.replace(batchComHead,'~/' + batchComAtxHead)
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
    db_print(cmd)
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

def start_trace_saver(server_ip,trace_server_list,product,domain=True):
    if not trace_server_list:
        db_print("no gici trace server defined,skip")
        return
    result_pids = ''
    trace_files = ''
    for trace_server in trace_server_list:
        if not ' ' in trace_server:
            continue
        tmpList = trace_server.split(' ')
        if len(tmpList) < 3:
            continue
        gici_ip = tmpList[0].strip()
        gici_port = tmpList[1].strip()
        prefix = tmpList[2].strip()
        if len(tmpList) > 3:
            dut_type = product + ':' + tmpList[3].strip()
        else:
            dut_type = product
        if not 'NT' in prefix:
            prefix = 'LT_' + prefix  
        prefix = 'trace_' + prefix
        if not (gici_ip and gici_port):
            db_print("worng NT_gici configured,should be NT-A:<ip> <port>")
            continue
        timestamp=time.strftime('%b%d%H%M%S',time.localtime())
        trace_file = prefix  + '_' + timestamp
        remotepath = '/tmp/.jenkins'
        trace_file = os.path.join(remotepath,trace_file)
        try:
            localscript = SCRIPT_PATH + '/traceSaver.py'
            remotescript = '/tmp/.jenkins/traceSaver.py'
            cmd = "sshpass -p 'alcatel01' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'ls %s'" %(server_ip,remotescript)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            if not result.strip() == remotescript:
                cmd = "sshpass -p 'alcatel01' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atxuser@%s 'mkdir -p /tmp/.jenkins'" %server_ip
                db_print(cmd)
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
                db_print(cmd)
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                localscript = SCRIPT_PATH + '/clearConsolePort.py'
                remotescript = '/tmp/.jenkins/clearConsolePort.py'
                cmd = "sshpass -p 'alcatel01' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s atxuser@%s:%s" %(localscript,server_ip,remotepath)
                db_print(cmd)
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            remotescript = '/tmp/.jenkins/traceSaver.py'
            cmd_pcta = "nohup python -u %s --craftIp %s --craftPort %s --LOG_FILE %s --storeInterval 9999 --dut_type %s >/dev/null 2>&1 &" %(remotescript,gici_ip,gici_port,trace_file,dut_type)
            ssh2_non_block(server_ip, 'atxuser','alcatel01',cmd_pcta,True)
        except Exception as inst:
            db_print("Start trace saver failed:%s" %inst)

        cmd1="ps -aef | grep traceSaver.py | grep %s | grep %s | grep -v defunct | grep -v grep | awk '{print $2}'" %(gici_ip,gici_port)
        result_pid =ssh2(server_ip, 'atxuser','alcatel01',cmd1,True)
        result_pid=result_pid.strip("\n")
        if result_pid:
            result_pids += ' %s' %result_pid
            trace_files += ',%s' %trace_file
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

def stop_trace_saver(server_ip,trace_server_list,domain=True):
    if not trace_server_list:
        db_print("no gici trace server defined,skip")
        return
    try:
        build_url = os.environ['BUILD_URL']
        build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)
    except Exception as inst:
        db_print("get build_url failured")
        return
    try:
        pids = ""
        pid_list=[]
        if not domain:
            cmd = "curl -s %sconsoleText |grep -o -a -E 'START TRACE SAVER JOB:(.*) for'" %build_url
        else:
            cmd = "curl -s %sconsoleText |grep -o -a -E 'START TRACE SAVER:(.*) for' |uniq |tail -1" %build_url
        result = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True).communicate()[0]
        resultList = result.split('\n')
        for each in resultList:
            each = each.strip("")
            if each:
                if not domain:
                    nout=re.search('START TRACE SAVER JOB:(.*) for',each)
                else:
                    nout=re.search('START TRACE SAVER:(.*) for',each)
                pids=nout.group(1)
                for npid in pids.split(' '):
                    npid=npid.strip()
                    pid_list.append(npid)
    except Exception as inst:
        db_print("get TRACE SAVER process failure")
    try:
        for val in pid_list:
            cmd = "kill -9 %s" %val
           #result = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True).communicate()[0]
            result =ssh2(server_ip, 'atxuser','alcatel01',cmd,True)
            db_print("kill TRACE SAVER process:%s" %val)
    except Exception as inst:
        db_print("kill TRACE SAVER with exception:%s" %inst)
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
        build_id = os.environ['BuildID']
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
    logTool = '/root/wwang046/logUpload.py'
    domainDir = ''
    if domain:
        db_print("get log dir:")
        domainDir = GetLogDir()
        db_print("log dir is %s" %domainDir)
    if trace_file_list:
        for val in trace_file_list:
            db_print(build_url)
            traceFiles=os.path.join(build_url,val)
            db_print(traceFiles)
            if domainDir:
                cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --team %s --platform %s --traceFiles %s --domainDir %s --pcta %s'" %(logSrv,logTool,build_id,team,new_job_name,traceFiles,domainDir,linuxIP)
            else:
                cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@%s 'python -u %s --buildID %s --team %s --platform %s --traceFiles %s --pcta %s'" %(logSrv,logTool,build_id,team,new_job_name,traceFiles,linuxIP)
            result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            db_print("\n%s with output:%s" %(cmd,result))
            db_print("upload TRACE SAVER process successfully")
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
    return batchCommand

def processNonFrameBatchCommandFinal(batchCommand,**args):
    vlanType = args.setdefault("vlanType","")
    vectValue = args.setdefault("vectValue","")
    standalonecaseList = args.setdefault("standalonecaseList",'')
    board = args.setdefault("board",'')
    LT_check_list = args.setdefault("LT_check_list",'')
    if batchCommand.find('python') != -1 :
        runType = 'python'
    commandList = []
    if runType == 'python':
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

def runStandaloneBatch(commandList,prerunConfig,linuxIP,userName,passwd,linuxPORT,storeLog=True):
    #jobname = os.environ['JOB_NAME']
    #jobNum = os.environ['BUILD_NUMBER']
    #reportJobInstantStatus(jobname,jobNum,'061')
    result = True
    if commandList[0].find('python') != -1 :
        runType = 'python'
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
            ##handlerunresult
    return result

def GetNonFrameworkScriptList(batchCommand):
    try:
        if batchCommand.find('python') != -1:
            runType = 'python'
        scriptList = []
        if runType == 'python':
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
            pid=ssh2(linuxIP, userName,passwd,script_cmd,True ,port=int(linuxPORT))
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
            pid=ssh2(linuxIP, userName,passwd,pcta_cmd,True ,port=int(linuxPORT))
            pid=pid.strip()
            for val in pid.split('\r\n'):
                if val != '':
                    kill_cmd="sudo /bin/kill -9 %s" %val
                    ssh2(linuxIP, userName,passwd,kill_cmd,port=int(linuxPORT))
    except Exception as inst:
        db_print("VOICE process kill error:%s" %inst)
        

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
    parser.add_argument("--dbServer", dest="dbServer",default="", help="DB backup Server(eg. 135.252.245.44)")
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
    parser.add_argument("--init_config", dest="init_config",default='none', help="pass initial config")
    options = parser.parse_args()
    for key in options.__dict__.keys():
        if type(options.__dict__[key]) == 'str':
            options.__dict__[key] = options.__dict__[key].lstrip("'").rstrip("'")
        #print options.__dict__[key]
    HOST = 'ftp:135.251.206.97:/ftpserver/loads:asblab:asblab' if not options.buildServer else options.buildServer

    #DIRN = '/ftp'
    #DIRN = '/loads'
    ver2 = ''
    #DIRN = '/ftpserver/loads'
    SERVER_IP = '135.252.245.44' if not options.ftpServer else options.ftpServer
    platformType = options.platformType
    print platformType
    action = options.action
    oam_ip = options.oam_ip
    craftIp = options.craftIp
    oam_gw = options.oam_gw
    build = options.build
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
    print "dbMode is %s" %dbMode
    dbBackup = options.dbBackup
    dbServer = options.dbServer
    timeCheck = options.timeCheck
    defaultDB = options.defaultDB
    craftPort = options.craftPort
    cs_num = options.cs_tag	
    dbDict = {}
    dbDict['oam_ip']=oam_ip
    dbDict['craftPort']=craftPort
    dbDict['craftIp']=craftIp
    dbDict['dbMode']=dbMode
    dbDict['dbBackup']=dbBackup
    dbDict['dbServer']=dbServer
    killLTB = options.killLTB
    suiteRerun = options.suiteRerun
    updateRepo = options.updateRepo
    file_index = options.file_index

    ExtraOptions = ''  if options.ExtraOptions.lower() == 'none' else options.ExtraOptions
    #print options.ExtraOptions
    #print "printed extra options"		
    oam_port = options.oam_port
    init_config = []
    init_config = options.init_config
    ExtraOptions=options.ExtraOptions
    ExtraOptions=ExtraOptions.replace('{','{"').replace(':','":').replace(' ',' "').replace('}','"}').replace('"{','{').replace(',','",').replace('}"','}')
    metrics_user = ''
    board = ''
    trace_server_list = []
    LT_check_list = []
    standalonecaseList = []
    standalonescriptList = []
    build_type="official"
    oam_type="None"
    update_build ='NONE'
    extraKeyList = ['NT','NT_gici','LT_gici','LT','BUILDTYPE','METRICSUSER','BOARD','transMode','dutNetconfPort','dutTracePort','dutOamPasswd','indexDesc','saveTrace','UPDATEBUILD','caseMode','domainMode','LTCheck','LTSWCheck','redund','Team','fwdVlanMode','NonFwCaseList','batchType','PCTA','vectorType']
    #if no Team passed, Other will be used
    Team = 'Other'
    LT_Dict = {}
    for key in ['transMode','dutNetconfPort','dutTracePort','dutOamPasswd','indexDesc','saveTrace','caseMode','domainMode','LTCheck','LTSWCheck','redund','fwdVlanMode','NonFwCaseList','batchType','PCTA','vectorType']:
        cmd_set_value = "%s=''" %key
        exec(cmd_set_value)
    if ExtraOptions:
        try:
            dExtraOptions = json.loads(ExtraOptions)
            print dExtraOptions
            for extraKey in extraKeyList:
                if extraKey in dExtraOptions:
                    #for host,using 'BOARD
                    if extraKey == 'BOARD':
                        board = str(dExtraOptions[extraKey]).strip()
                        #oam_type is uppercase
                        oam_type=board
                        #board is lowercase
                        board = board.lower()
                    #for target, using NT
                    elif extraKey == 'NT':
                        #only support 1 board for phase1
                        if 'NT' in dExtraOptions[extraKey]:
                            board = dExtraOptions[extraKey]['NT']    
                        elif 'NT-A' in dExtraOptions[extraKey]:
                            board = dExtraOptions[extraKey]['NT-A']
                        elif 'NT-B' in dExtraOptions[extraKey]:
                            board = dExtraOptions[extraKey]['NT-B']
                        #strip blank
                        board = str(board).strip()
                        #oam_type is uppercase
                        oam_type=board
                        #board is lowercase
                        board = board.lower()
                    elif extraKey == 'LT':
                        try:    
                            LT_check_list=dExtraOptions['LT'].values()
                            LT_check_list=[x.strip(' ') for x in LT_check_list]
                            LT_check_list=json.dumps(LT_check_list)
                        except Exception as inst:
                            db_print("Invalid LT value format")
                            LT_check_list=[]
                        LT_Dict = dExtraOptions['LT']
                    elif extraKey == 'BUILDTYPE' and dExtraOptions['BUILDTYPE'].strip():
                        build_type=str(dExtraOptions['BUILDTYPE']).strip()
                    elif extraKey == 'UPDATEBUILD' and dExtraOptions['UPDATEBUILD'].strip():
                        update_build=str(dExtraOptions['UPDATEBUILD']).strip()
                    elif extraKey == 'METRICSUSER' and dExtraOptions['METRICSUSER'].strip():
                        metrics_user=str(dExtraOptions['METRICSUSER']).strip()
                    elif extraKey == 'NT_gici' or extraKey == 'LT_gici':
                        #only support NT_gici in phase1
                        for key in dExtraOptions[extraKey]:
                            if ('NT-A' in key or 'NT-B' in key or 'NT' in key) and dExtraOptions[extraKey][key].strip():
                                traceBoard = 'Other'        
                                res = re.search('(\D+)',key)
                                if res and 'NT' in dExtraOptions:
                                    slotPos = res.group(1)
                                    if slotPos in dExtraOptions['NT'] and dExtraOptions['NT'][slotPos].strip():
                                        traceBoard = str(dExtraOptions['NT'][slotPos].strip())                                 
                                trace_server_list.append(str(dExtraOptions[extraKey][key]).strip() + ' ' + str(key).strip() + ' ' + traceBoard)
                            elif re.match('[\d]+',key.strip()):
                                if 'LT' in dExtraOptions and key in dExtraOptions['LT'] and dExtraOptions['LT'][key].strip():
                                    traceBoard = str(dExtraOptions['LT'][key].strip())
                                else:
                                    traceBoard = 'Other'
                                trace_server_list.append(str(dExtraOptions[extraKey][key]).strip() + ' ' + str(key).strip() + ' ' + traceBoard)
                            else:
                                print("wrong parameter:%s" %dExtraOptions[extraKey])
                    elif  extraKey in ['transMode','dutNetconfPort','dutTracePort','dutOamPasswd','indexDesc','saveTrace','caseMode','domainMode','LTCheck','LTSWCheck','redund','Team','fwdVlanMode','NonFwCaseList','batchType','PCTA','vectorType']:
                        cmd_set_value = '%s=str(dExtraOptions[extraKey]).strip()' %extraKey
                        exec(cmd_set_value)
        except Exception as inst:
            db_print("wrong extraoptions passed:%s" %inst)
    #saveTrace = 'true'
    #LTCheck = 'true'
    #LTSWCheck = 'true'
    if saveTrace == 'True':
        saveTrace = True
    else:
        saveTrace = False
    if LTCheck == 'True':
        LTCheck = True
    else:
        LTCheck = False
    if LTSWCheck == 'True':
        LTSWCheck = True
    else:
        LTSWCheck = False
    if fwdVlanMode != 'NONE':
        vlanType = fwdVlanMode.strip()
    else:
        vlanType = ''
    if vectorType != 'NONE':
        vectValue = vectorType.strip()
    else:
        vectValue = ''
    if batchType != 'NONE':
        batch_type = batchType.strip()
    else:
        batch_type = ''
    if NonFwCaseList != 'NONE':
        for val in NonFwCaseList.split(","):
            standalonecaseList.append(val)
    else:
        standalonecaseList = []
    if PCTA != 'NONE':
        if PCTA == "":
            pctaServer = 'NONE'
        else:
            pctaServer = PCTA.strip()
    else:
        pctaServer = 'NONE'
    redund = True if redund == 'True' else False
    print LT_check_list
    caseMode = caseMode.strip()

    if 'skip_ATCs' in caseMode:
        caseMode = 'EXC'
    else:
        caseMode = 'INC'
    domainMode = domainMode.strip()
    if 'exclude_domain' in domainMode:
        domainMode = 'EXC'
    else:
        domainMode = 'INC'

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
    ntimestamp=''
    LIS_DIR = ''
    MOSWA_OSWP_NAME=''
    MOSWA_OSWP_URL = ''
    
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
    batchCommand = options.batchCommand
    linuxIpPort = options.linuxIP.strip().split(':')
    linuxIP = linuxIpPort[0]
    try:
        if ipaddress.ip_address(unicode(linuxIP)).is_private:
            LOG_SERVER={'FQDN':'http://smartlab-service.int.net.nokia.com:9000/log','IP':'135.251.206.149','HTTP':'http://10.131.213.53:9000/log'}
    except Exception as inst:
        db_print('Error :%s' % inst)
    linuxPORT = linuxIpPort[1] if len(linuxIpPort) > 1 else '22'
    linuxPctaexe = ''
    try:
        linuxUser = linuxIpPort[2]
        linuxPasswd = linuxIpPort[3]
    except Exception as inst:
        linuxUser = 'atxuser'
        linuxPasswd = 'alcatel01'
        linuxPctaexe = ''
    if len(linuxIpPort) == 5:
        linuxPctaexe = linuxIpPort[4]
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

    extraTar = True if options.extraTar == 'True' else False
    #extraTar = options.extraTar
    hostFlag = True if options.hostFlag.lower() == 'host' else False
    #for debug only
    debugOnly = options.debug
    try :
        job_name = os.environ['JOB_NAME'] 
        if not job_name.find('SF8') == -1 or not job_name.find('DF16') == -1:
            platfromType = 'REBORN'
        #ftp:135.251.206.97:/ftpserver/loads:asblab:asblab
        #HOST = _workaround_ftp_moswa(HOST,job_name,build)
            
    except Exception as inst:
        db_print('pls run on jenkins so that JOB_NAME can be got')
        #platformType = 'GPON'/* Commented for Tools Upgrade */
    if platformType in ['nothing','',None]:
        platformType = 'GPON'
    initCommands = []
    product = platformType
    dbDict['product'] = platformType
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
    print 'initCommands is'
    print initCommands
    telnetTn = telnetlib.Telnet() 
    tndTn = telnetlib.Telnet()
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
                'domainMode':domainMode}
    batchDictStandalone = {'vlanType':vlanType, \
                          'vectValue':vectValue, \
                          'standalonecaseList':standalonecaseList, \
                          'board':board, \
                          'LT_check_list':LT_check_list}
    if re.search('/ATX/bin/atx',batchCommand):
        batchDict['loadinfo'] = loadinfo
        batchDict['updateRepo'] = updateRepo   
    # for MOSWA update    
    if product in ['SDFX','SDOLT','NCDPU']:
        MOSWA_DICT = {} 
        (protocol,build_ip,build_dir,build_user,build_pazwd) = _parse_build_server(HOST)
        MOSWA_DICT['build_name'] = build
        MOSWA_DICT['update_ip'] = SERVER_IP
        MOSWA_DICT['protocol'] = protocol
        MOSWA_DICT['build_ip'] = build_ip
        MOSWA_DICT['build_dir'] = build_dir
        MOSWA_DICT['build_ftp_dir'] = build_dir
        MOSWA_DICT['no_fallback'] = True
        if build_user:
            MOSWA_DICT['build_user'] = build_user
        if build_pazwd:
            MOSWA_DICT['build_pazwd'] = build_pazwd
        if build_type == 'LIS':
            MOSWA_DICT['update_abs_dir'] = LIS_DIR
            MOSWA_DICT['alias_dir'] = ntimestamp
            MOSWA_DICT['build_type'] = 'LIS'
        boardType = 'NT'
        if product == 'SDFX':
            trans_mode = 'http'
            file_index = 'AG'
            dut_trace_port = '2222'
            dut_port = '830'
            boardType = 'LT'
        elif product == 'SDOLT':
            trans_mode = 'http'
            file_index = 'AG'
            dut_trace_port = '22'
            dut_port = '830'
            boardType = 'LT'
        elif product == 'NCDPU': 
            trans_mode = 'tftp'
            file_index = 'AF'
            dut_trace_port = '2222'
            dut_port = '830'
            boardType = 'NT'

        MOSWA_DICT['dut_ip'] = oam_ip 
        if dutNetconfPort:
            MOSWA_DICT['dut_port'] = dutNetconfPort
        else:
            MOSWA_DICT['dut_port'] = dut_port              
        if indexDesc:
            MOSWA_DICT['nt_type'] = indexDesc
        else:                
            MOSWA_DICT['nt_type'] = file_index
        if transMode:
            MOSWA_DICT['trans_mode'] =  transMode
        else:
            MOSWA_DICT['trans_mode'] = trans_mode
        if dutTracePort :
            MOSWA_DICT['db_port'] = dutTracePort 
        else:
            MOSWA_DICT['db_port'] = dut_trace_port
        
        
        if not dutNetconfPort == MOSWA_NT_NETCONF_PORT:
            #for old sdfx or nc dpu  or nc olt, do not set slot_id
            MOSWA_LIST.append(MOSWA_DICT)            
        else:
            planLT = False
            if board:
                boardType = 'NT'
                MOSWA_DICT['board_type'] = board
                MOSWA_DICT['role'] = 'NT'
                MOSWA_LIST.append(MOSWA_DICT)    
                planLT = True
            for lt in LT_Dict:
                ltMoswaDict = copy.deepcopy(MOSWA_DICT)
                ltMoswaDict['board_type'] = None
                if planLT:
                    ltMoswaDict['board_type'] = str(LT_Dict[lt])
                ltMoswaDict['role'] = 'LT'
                ltMoswaDict['slot_id'] = str(lt)
                MOSWA_LIST.append(ltMoswaDict)       

    tool_only = False
    if action == 'upgradeDUT':
        tool_only = False

    if action == 'getLatestBuild':
        #print 'get latest build in certain release and set build environment'
        db_print('STEP:%s' %action)
        if not getLatestBuildNew(build)[0]:
            sys.exit(1)
        #add security login banner
        if pingIp(oam_ip):
            configDUT(oam_ip,'banner',product,'add')
        sys.exit()
    if  action == 'prepareOSWP' or action == 'upgradeDUT':
        db_print('STEP:%s' %action)
        if re.search('/ATX/bin/atx',batchCommand):
            db_print("atx server skip step:%s" %action)
            sys.exit()
        if hostFlag:
            if not prepareQemu(linuxIP,linuxUser,linuxPasswd,linuxPORT,build,HOST,oam_ip,board):
                db_print('start qemu failed')
                sys.exit(1)
            db_print('start qemu host successfully')
            sys.exit()


        #if extraTar:
        #    db_print("download tar/extra tar for migtation cases")
        #    (res,dur) = prepareOSWP(build,linuxIP,'/tftpboot/atx/loads',True)
        if loadinfo == 'noload' or loadinfo == 'cleanDB':
            db_print("do not need change current oswp, skip step:%s" %action)
            sys.exit()
        elif loadinfo =='load' and not build:
            db_print("can not find latst build for %s, skip step:%s" %(buildRelease,action))
            sys.exit()
        if build_type != "LIS":
            (res,dur) = prepareOSWP(build,SERVER_IP,product,HOST,MOSWA_LIST,tool_only)
        else:
            (res,dur) = prepareOSWP(build,SERVER_IP,product,HOST,MOSWA_LIST,tool_only,LIS_DIR,build_type)
        if not res:
            db_print("prepareOSWP failure")
            sys.exit(1)
        if action == 'prepareOSWP':
            sys.exit()
    if action == 'downloadOSWP' or action == 'upgradeDUT':
        db_print('STEP: Start Trace collection')
        if saveTrace:
            start_trace_saver(linuxIP,trace_server_list,product,False)
        if re.search('/ATX/bin/atx',batchCommand):
            db_print("atx server skip step:%s" %action)
            sys.exit()
        if hostFlag:
            db_print("skip STEP:%s for HOST batch" %action)
            sys.exit()
        if loadinfo == 'noload' or loadinfo == 'cleanDB':
            db_print("do not need change current oswp, skip step:%s" %action)
            sys.exit()
        elif loadinfo =='load' and not build:
            db_print("can not find latst build for %s, skip step:%s" %(buildRelease,action))
            sys.exit()
        db_print('STEP:%s' %action)
        db_print(build + oam_ip)
        (res,dur) = (True,0)
        if product in ['SDFX','SDOLT','NCDPU']:
            #for MOSWA build, pass build directly to downloadOSWP
            if build_type != "LIS":
                (res,dur) = downloadOSWP(build,SERVER_IP,oam_ip,'',product,tool_only,MOSWA_LIST)
            else:
                #timestamp=time.strftime('%b%d%H%M%S',time.localtime())
                #ntimestamp = oam_ip + '_' + timestamp
                #LIS_DIR = '/tftpboot' + '/' + ntimestamp
                #db_print('LIS DIRECTORY: %s' % LIS_DIR)
                #db_print('LIS TIMESTAMP: %s' % ntimestamp)
                #MOSWA_DICT['update_abs_dir'] = LIS_DIR
                #MOSWA_DICT['alias_dir'] = ntimestamp
                #nLIS_DIR=GetLISDir()
                #MOSWA_DICT['update_abs_dir'] = LIS_DIR
                #MOSWA_DICT['alias_dir'] = ntimestamp
                (res,dur) = downloadOSWP(build,SERVER_IP,oam_ip,'',product,tool_only,MOSWA_LIST,build_type)
        else:
            clearOSWP(oam_ip,product)
            oswp_info = _get_oswp_info(oam_ip,product)
            if oswp_info:
                oswp_index = _get_oswp_index(build,oam_ip,product)
                db_print('target oswp index is %s' %oswp_index)

            if len(oswp_info) >= 1 and not oswp_info[1]['oswpIndex'] == oswp_index and not oswp_info[1]['status'] == 'enabled':
                if not _adjust_link_speed(oam_ip,product):
                    db_print("can not telnet equipment after link speed adjust:%s" %oam_ip)
                    sys.exit()
                if action == 'downloadOSWP':
                    configDUT(oam_ip,'pre_oswp',product,'add',linuxIP,linuxUser,linuxPasswd,linuxPORT)
            
                if build_type != "LIS":
                    (res,dur) = downloadOSWP(oswp_info[1]['index'],SERVER_IP,oam_ip,oswp_index,product,tool_only)
                else:
                    if action == 'upgradeDUT':
                        newtimestamp = ntimestamp
                    else:
                        newtimestamp=GetLISTimestamp()
                    newoswp_index = "%s/%s" %(newtimestamp,oswp_index.strip())
                    (res,dur) = downloadOSWP(oswp_info[1]['index'],SERVER_IP,oam_ip,newoswp_index,product,tool_only,build_type)
                if not res:
                    db_print("downloadOSWP failure")
                    sys.exit(1)
            else :
                db_print('no need to download oswp!')
        if action == 'downloadOSWP':
            if res:
                sys.exit()
            else:
                sys.exit(1)
    if  action == 'activateOSWP' or action == 'upgradeDUT':
        (res,dur) = (True, 0)
        if re.search('/ATX/bin/atx',batchCommand):
            db_print("atx server skip step:%s" %action)
            sys.exit()
        if hostFlag:
            db_print("skip STEP:%s for HOST batch" %action)
            sys.exit()
        if product in ['SDFX','SDOLT','NCDPU']:
            if loadinfo == 'load':
                #for upgradeDUT branch, the dict has been filled with value already
                #if action == 'activateOSWP':
                #    nLIS_DIR=GetLISDir()
                #    ntimestamp = os.path.basename(nLIS_DIR)
                #    MOSWA_DICT['update_abs_dir'] = LIS_DIR
                #    MOSWA_DICT['alias_dir'] = ntimestamp
                (res,dur) = activateOSWP(oam_ip,build,product,tool_only,MOSWA_LIST)
            elif loadinfo == 'cleanDB' :
                db_print("clean db for moswa product and restart")
                try:
                    board_arg_list = copy.deepcopy(MOSWA_LIST)
                    if len(board_arg_list) == 1:
                        moswa_dict = board_arg_list[0]
                        moswa_dict.pop('role','SINGLE')
                        moswa_board = Smartlab_Instance(moswa_dict)
                        moswa_board.NAME = Get_MOSWA_NAME()
                        moswa_board.URL = Get_MOSWA_URL()
                        moswa_board.clean_db_with_reset_build()
                    else:
                        nt_active_list = []
                        lt_keep_list = []
                        loop_mode = 'abort'
                    
                        for moswa_dict in board_arg_list:
                            board_role = moswa_dict.pop('role','SINGLE')
                            moswa_board = Smartlab_Instance(moswa_dict)
                            moswa_board.NAME = Get_MOSWA_NAME()
                            moswa_board.URL = Get_MOSWA_URL()
                            active_name = moswa_board._get_active_name(getlist=moswa_board.check_state())
            
                            if board_role == 'NT':
                                nt_active_list.append(moswa_board)
                            else:
                                lt_keep_list.append(moswa_board)
                        if nt_active_list and len(lt_keep_list) >= 2:
                            loop_mode = 'continue'
                        Smartlab_Service.clean_db_with_reset_parallel(lt_keep_list)
                        if nt_active_list:
                            for lead_board in nt_active_list:
                                lead_board.clean_db_with_reset_build()
                            for lt_plan in lt_keep_list:
                                nt_upd.plan_sub_board(lt_plan.plan_rpc)
                except Exception as inst:
                    db_print("clean db failed with exception:%s" %inst)        
                    sys.exit(1)
            else:
                db_print("loadinfo is noload,do not activate oswp")
        else:
            if loadinfo == 'cleanDB' :
                db_print('STEP:%s' %action)
                _backup_db_before_activation(build,oam_ip,dbBackup,dbServer,product)
                oswp_info = _get_oswp_info(oam_ip,product)
                if oswp_info:
                    (res,dur) = activateOSWP(oam_ip,oswp_info[0]['index'],product,tool_only)
            elif loadinfo =='load' :
                if not build :
                    db_print("can not find latst build for %s, skip step:%s" %(buildRelease,action))
                    sys.exit()
                db_print('STEP:%s' %action)
                oswp_info = _get_oswp_info(oam_ip,product)
                if oswp_info and oswp_info[1]['oswpIndex']:
                    _backup_db_before_activation(build,oam_ip,dbBackup,dbServer,product)
                    (res,dur) = activateOSWP(oam_ip,oswp_info[1]['index'],product,tool_only,{},dbMode)
            else:
                db_print("loadinfo is noload,do not activate oswp")
        if  action == 'activateOSWP':
            if res:
                sys.exit()
            else:
                sys.exit(1)
    if action == 'initializeDUT' or action == 'upgradeDUT':
        (res,dur) = (True, 0)
        #jobname = os.environ['JOB_NAME']/* Commented for Tools Upgrade */
        #jobNum = os.environ['BUILD_NUMBER']
        if re.search('/ATX/bin/atx',batchCommand):
            db_print("atx server skip step:%s" %action)
            sys.exit()
        if hostFlag:
            db_print("skip STEP:%s for HOST batch" %action)
            sys.exit()
        if loadinfo =='load' or loadinfo == 'cleanDB':
            if not build:
                db_print("can not find latst build for %s, skip step:%s" %(buildRelease,action))
                sys.exit()
            if not craftIp and not product in ['NCDPU','SDFX','SDOLT'] and not check_telnet(oam_ip):
                db_print("Can not telnet oam ip after activateOSWP %s, skip step:%s" %(buildRelease,action))
                sys.exit(1)
            db_print('STEP:%s' %action)
            if craftIp:
                #if re.search('/ATX/bin/atx',batchCommand):
                #   pctaIP = _get_pcta_info_from_atx(linuxIP, 'atxuser','alcatel01',batchCommand)
                #else:
                #   pctaIP = linuxIP
                if action == 'initializeDUT':
                    pctaIP = linuxIP
                    extraCommands = _get_extra_init_commands(pctaIP, linuxUser,linuxPasswd,linuxPORT)
                #print '----get new initCommands:'
                #print extraCommands
                if action == 'upgradeDUT':
                    extraCommands = ""
                res = initializeDUT(craftIp, craftPort, oam_ip,initCommands,extraCommands,product,tool_only)
            if redund:
                db_print('STEP: Check NT synchronize in Redund Setups in platform initialization')
                initComplete = True
                try:
                    initComplete = checkDiskSyncForRedundancy(SERVER_IP,oam_ip)
                except Exception as inst:
                    db_print("check dual nt init status fail with %s" %inst)
                    initComplete = True
                if not initComplete:
                    if not tool_only:
                        jobname = os.environ['JOB_NAME']
                        jobNum = os.environ['BUILD_NUMBER']
                        errorCode = '510'
                        reportJobInstantStatus(jobname,jobNum,'004',errorCode)
                    sys.exit(1)
            if loadinfo =='load':
                oswp_info = _get_oswp_info(oam_ip,product)
                if oswp_info:
                    oswp_index = _get_oswp_index(build,oam_ip,product)
                if len(oswp_info) >= 1 and not oswp_info[0]['oswpIndex'] == oswp_index:
                    db_print("target oswp %s is not the active one:%s, skip step:%s" %(oswp_index,oswp_info[0]['oswpIndex'],action))
                    if not tool_only:
                        jobname = os.environ['JOB_NAME']
                        jobNum = os.environ['BUILD_NUMBER']
                        errorCode = '505'
                        reportJobInstantStatus(jobname,jobNum,'004',errorCode)
                    sys.exit(1)
                clearOSWP(oam_ip,product)
        #add security login banner after activation
        if pingIp(oam_ip):
            configDUT(oam_ip,'banner',product,'add')
        if saveTrace:
            db_print('STEP: Stop Trace collection')
            stop_trace_saver(linuxIP,trace_server_list,False)
        if LTCheck:
            if not product in ['NCDPU','SDFX','SDOLT']:
                db_print('STEP: LT availability check in setup after build upgrade')
                db_print('STEP: Configure expansion shelf commands if exists')
                extraShelfCommands=_get_extra_shelf_commands(linuxIP, linuxUser,linuxPasswd,linuxPORT,'config')
                if extraShelfCommands:
                    config_shelf(oam_ip,extraShelfCommands)
                else:
                    pass
                if not check_lt_status(oam_ip,LT_check_list):
                    if not tool_only:
                        jobname = os.environ['JOB_NAME']
                        jobNum = os.environ['BUILD_NUMBER']
                        errorCode = '507'
                        reportJobInstantStatus(jobname,jobNum,'004',errorCode)
                    sys.exit(1)
                if LTSWCheck and LT_check_list:
                    new_LT_val=LT_check_list.replace('"',"").strip("]").strip("[").replace(", ",",")
                    if not check_lt_sw(SERVER_IP,oam_ip,new_LT_val,build):
                        if not tool_only:
                            jobname = os.environ['JOB_NAME']
                            jobNum = os.environ['BUILD_NUMBER']
                            errorCode = '508'
                            reportJobInstantStatus(jobname,jobNum,'004',errorCode)
                        sys.exit(1)
                db_print('STEP:UnConfigure expansion shelf commands if exists')
                extraShelfUCommands=_get_extra_shelf_commands(linuxIP, linuxUser,linuxPasswd,linuxPORT,'unconfig')
                if extraShelfUCommands:
                    config_shelf(oam_ip,extraShelfUCommands)
                else:
                    pass            
        if res:
            sys.exit()
        else:
            sys.exit(1)
    if action == 'updateREPO' :
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
            updateREPO(linuxIP,linuxUser,linuxPasswd,linuxPORT,cs_num)    
        sys.exit()    
    if action == 'dryRunRobot':
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
        ssh2(linuxIP, linuxUser,linuxPasswd, '~/configs/prerun_config_cmd',port=int(linuxPORT))
        robotOptions = robotOptions + ',dryrun-enable' if robotOptions else 'dryrun-enable'
        db_print('STEP:%s' %action)
        batchDict['testRun'] = 'true' 
        batchDict['robotOptions'] = robotOptions
        if extraTar:
            batchDict['extraTar'] = '/tftpboot/atx/loads/SD_%s.extra.tar' %build

        (commandList,domainList)=processBatchCommandFinal(batchCommand,**batchDict)
        print(commandList)
        print domainList
        prerunConfig = _set_metrics_user(prerunConfig,'')
        if prerunConfig:
            prerunConfig += ';export NOXTERM=True'
        else:
            prerunConfig = 'export NOXTERM=True'
        resultDirList = dryrunBatch(commandList,prerunConfig,domainList,linuxIP,linuxUser,linuxPasswd,domainSplit,defaultDB,dbDict,linuxPORT=linuxPORT,traceOnly=debugOnly)  
        casefile = generateCaseList(linuxIP,resultDirList,linuxPORT,linuxUser,linuxPasswd,debug = debugOnly)   
        ssh2(linuxIP, linuxUser,linuxPasswd, '~/configs/postrun_config_cmd',port=int(linuxPORT))
        db_print('STEP:%s finished with file:%s' %(action,casefile))
        sys.exit()
    if action == 'runBatch' :  
        if loadinfo =='load' and not build:
            db_print("can not find latst build for %s, skip step:%s" %(buildRelease,action))
            sys.exit()
        db_print('STEP: Processes to be started before LTB')
        if batch_type == 'non-framework':
            #db_print("STEP:%s Kill existing Non framework scripts process if any" %action)
            #standalonescriptList = GetNonFrameworkScriptList(batchCommand)
            #NonFrameworkProcessKill(linuxIP,linuxUser,linuxPasswd,linuxPORT,standalonescriptList)
            db_print("STEP:%s Execute scripts for non-framework batch type" %action)
            commandList=processNonFrameBatchCommandFinal(batchCommand,**batchDictStandalone)
            runStandaloneBatch(commandList,prerunConfig,linuxIP,linuxUser,linuxPasswd,linuxPORT,storeLog=storeLog)
            sys.exit()
        db_print('STEP: Processes to be started before LTB')
        if linuxPctaexe != '':
            db_print('STEP: Kill existing PCTA process if any')
            pcta_process_kill(linuxIP,linuxUser,linuxPasswd,linuxPORT)
            db_print('STEP: PCTA process start')
            try:
                directory=linuxPctaexe.strip('pcta.exe')
                exe=linuxPctaexe.strip('/root/PCTA/')
            except Exception as inst:
               directory='/root/PCTA/'
               exe='pcta.exe'
            pcta_exe_cmd="%s -d  > ./PCTA_OPF.txt &" %exe
            ##Start PCTA process
            pcta_start(SERVER_IP,linuxIP,linuxPORT,linuxUser,linuxPasswd,directory,pcta_exe_cmd)
        else:
            db_print('STEP: Skip PCTA process start')

        if platformType == 'Voice':    
            db_print('kill voice process')
            voice_process_kill(linuxIP,linuxUser,linuxPasswd,linuxPORT)
            db_print('start voice process')
            start_voice_process(linuxIP,linuxUser,linuxPasswd)
        db_print('STEP:%s' %action)        
        if extraTar:
            #db_print('STEP: Check NT synchronize in Redund Setups')
            #checkDiskSyncForRedundancy(oam_ip)
            if build_type == 'LIS':
                nLIS_DIR=GetLISDir()
                ckstatus=copy_extra_tar_to_linux(build,linuxIP,linuxUser,linuxPasswd,SERVER_IP,nLIS_DIR)
            else:
                ckstatus=copy_extra_tar_to_linux(build,linuxIP,linuxUser,linuxPasswd,SERVER_IP)
            if not ckstatus:
                db_print("Extra.tar download failure")
                #sys.exit(1)
                db_print("do not append extraTar to launchTestBatch")
            else:
                db_print("Extra.tar is copied successfully")		
                batchDict['extraTar'] = '/tftpboot/atx/loads/SD_%s.extra.tar' %build
        #commandList=processBatchCommandFinal(batchCommand,release=release,suiteRerun = suiteRerun,domain=domain,domainSplit=domainSplit,testRun=testRun,build=build,robotOptions=robotOptions,coverage=coverage,robotCaseList=robotCaseList)
        batchDict['update_build']=update_build
        if not (prerunConfig and 'DISPLAY' in prerunConfig) or hostFlag:
            batchCommand=updatelaunchTestBatchCmd(batchCommand,linuxIP,linuxUser,linuxPasswd,linuxPORT)
            if prerunConfig:
                prerunConfig += ';export NOXTERM=True'
            else:
                prerunConfig = 'export NOXTERM=True'


        (commandList,domainList)=processBatchCommandFinal(batchCommand,**batchDict)
        print(commandList)
        print domainList
        #sys.exit()
        #whether it is ATX or else, will store active oswp index for cleanDB bwteen two domains
        if defaultDB == 'true':
            oswp_info = _get_oswp_info(oam_ip,product)
            if oswp_info:
                dbDict['oswpIndex']=oswp_info[0]['index']
        dbDict['saveTrace'] = saveTrace
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
            print dbDict
            if craftIp:        
                #if re.search('/ATX/bin/atx',batchCommand):
                #   pctaIP = _get_pcta_info_from_atx(linuxIP, 'atxuser','alcatel01',batchCommand)
                #else:
                #   pctaIP = linuxIP
                pctaIP = linuxIP
                extraCommands = _get_extra_init_commands(linuxIP, linuxUser,linuxPasswd, linuxPORT)
                dbDict['extraCommands'] = extraCommands       
            ssh2(linuxIP, linuxUser,linuxPasswd, '~/configs/prerun_config_cmd',port=int(linuxPORT))
            prerunConfig = _set_metrics_user(prerunConfig,metrics_user)
            runBatch(commandList,prerunConfig,domainList,linuxIP,linuxUser,linuxPasswd,domainSplit,defaultDB,dbDict,linuxPORT=linuxPORT,traceOnly=debugOnly,storeLog=storeLog)
            ssh2(linuxIP, linuxUser,linuxPasswd, '~/configs/postrun_config_cmd',port=int(linuxPORT))
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
        if re.search('/ATX/bin/atx',batchCommand):
            db_print("atx server skip step:%s" %action)
            sys.exit()
        if loadinfo =='load' and not build:
            db_print("can not find latst build for %s, skip step:%s" %(buildRelease,action))
            sys.exit(1)
        db_print('STEP:%s' %action)
        #remove security login banner after batch finish
        if pingIp(oam_ip):
            configDUT(oam_ip,'banner',product,'delete')
        if saveTrace:
            db_print('STEP: Stop Trace collection')
            stop_trace_saver(linuxIP,trace_server_list,False)
            upload_trace_saver(linuxIP,trace_server_list,Team,False)
        if batch_type == 'non-framework':
            db_print("STEP:%s Kill Non framework scripts process id" %action)
            standalonescriptList = GetNonFrameworkScriptList(batchCommand)
            NonFrameworkProcessKill(linuxIP,linuxUser,linuxPasswd,linuxPORT,standalonescriptList)
            jobname = os.environ['JOB_NAME']
            jobNum = os.environ['BUILD_NUMBER']
            reportJobInstantStatus(jobname,jobNum,'000')
            sys.exit()
        cleanEnvPostRun(linuxIP,linuxUser,linuxPasswd,oam_ip,linuxPctaexe,hostFlag,linuxPORT=linuxPORT)
        if build_type == 'LIS':
            nLIS_DIR=GetLISDir()
            db_print('Delete LIS build directory')
            lis_build_dir_create(SERVER_IP,nLIS_DIR,"delete")
        db_print('cleanEnvPostRun')
        jobname = os.environ['JOB_NAME']
        jobNum = os.environ['BUILD_NUMBER']
        reportJobInstantStatus(jobname,jobNum,'000') 
        sys.exit()
    #other action,will go this branch
    db_print("wrong operation")
    sys.exit(1)


#!/usr/bin/python
#coding:utf-8

import time, re, os, ConfigParser, sys, inspect, subprocess
from optparse import OptionParser
#from lib.resultParser.writer.trancehandle import TraceFileHandle


SERVER_IP = '135.252.245.44'

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
    if re.search('Fi-Forwarding_IWF|Fi-Transport_1',team):
        os.system('chown -R smtlab:smtlab ' + buildID)
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

  

import os
from argparse import ArgumentParser
import re
import time
import signal
import subprocess
import json
import sys,paramiko
from bs4 import BeautifulSoup
import requests
from buildUtility import db_print
from sshClient import *

class clickTest:
    def __init__(self):
        parser = ArgumentParser()
        parser.add_argument("-host_ATC_on_cloud", default=True,type=self.str2bool, help="clicktest run on cloud")
        parser.add_argument("-boards", default='',type=str, help="used by build, package options. comma(,) separated, please alwasy specify NT with LTs for shelf products or standalone products. iempty or \"all\" means all available boards from casesets")
        parser.add_argument("-release", default='',type=str, help="if skip_build and skip_targetATC, then can't get the release from packageme, should specify it here for hostATC, like 6.2 or 6.2.01")
        parser.add_argument("-CSL", default='',type=str, help="")
        #parser.add_argument("-CSLPWD", default='',type=str, help="")
        parser.add_argument("-buildResults", default='',type=str, help="")
        parser.add_argument("-buildID", default='',type=str, help="")
        parser.add_argument("-Platform", default='',type=str, help="")
        parser.add_argument("-Batch", default='',type=str, help="")
        parser.add_argument("-logServerIp", default='',type=str, help="")
        parser.add_argument("-logServerPort", default='22',type=str, help="")
        parser.add_argument("-logServerUser", default='',type=str, help="")
        parser.add_argument("-logServerPwd", default='',type=str, help="")
        parser.add_argument("-logServerDirectory", default='',type=str, help="")
        parser.add_argument("-binPath", default='/ap/local/devtools',type=str, help="")
        parser.add_argument("-remoteIp", default='',type=str, help="")
        parser.add_argument("-remoteUsername", default='',type=str, help="")
        parser.add_argument("-remotePasswd", default='',type=str, help="")

        parser.add_argument("-batchHostIP", default='',type=str, help="")
        parser.add_argument("-batchHostUser", default='',type=str, help="")
        parser.add_argument("-batchHostPWD", default='',type=str, help="")
        parser.add_argument("-batchHostRobotPath", default='',type=str, help="")

        parser.add_argument("-FRAMEWORK", default='',type=str, help="")
        parser.add_argument("-TIMESTAMP", default='',type=str, help="")
        parser.add_argument("-DEVTOOLS_REV", default='',type=str, help="")
        parser.add_argument("-ATC_REV", default='',type=str, help="")
        parser.add_argument("-ROBOT_REV", default='',type=str, help="")
        parser.add_argument("-TEST_PACKAGES_REV", default='',type=str, help="")
        parser.add_argument("-CS", default='',type=str, help="")
        parser.add_argument("-SUPPRESSED_TESTBATCHES", default='',type=str, help="")
        parser.add_argument("-SUSPENDED_TESTBATCHES", default='',type=str, help="")
        parser.add_argument("-REGRESSION_MODE_RUN", default='',type=str, help="")
        parser.add_argument("-RERUN_TESTBATCHES", default='',type=str, help="")
        parser.add_argument("-TAGS", default='',type=str, help="")
        parser.add_argument("-build_ip", default='',type=str, help="")
        parser.add_argument("-build_port", default='',type=str, help="")
        parser.add_argument("-build_user", default='',type=str, help="")
        parser.add_argument("-build_passwd", default='',type=str, help="")
        parser.add_argument("-robot_repo", default='',type=str, help="")
        parser.add_argument("-display_user", default='',type=str, help="")
        parser.add_argument("-area_coverage", default=False,type=str, help="")

        options = parser.parse_args()
        for key in options.__dict__.keys():
            if key == 'CSLPWD':
                continue
            db_print('%s is:%s'%(key,options.__dict__[key]))
            if type(options.__dict__[key]) == 'str':
                options.__dict__[key] = options.__dict__[key].lstrip("'").rstrip("'")

        self.JOB_NAME=os.environ['JOB_NAME']
        self.BUILD_NUMBER=os.environ['BUILD_NUMBER']
        self.WORKSPACE='%s/%s'%(os.environ['WORKSPACE'],self.BUILD_NUMBER)

        self.jenkins_result_log_url=''
        self.options=options
        self.var_host_ATC_on_cloud=options.host_ATC_on_cloud
        self.host_boards = options.boards
        self.logServerIp=options.logServerIp
        self.logServerPort=options.logServerPort
        self.logServerUser=options.logServerUser
        self.logServerPwd=options.logServerPwd
        self.logServerDirectory=options.logServerDirectory
        self.devtoolsPath='/var/jenkins_home/scripts/devtools'

    def str2bool(self,v):
        if isinstance(v, bool):
            return v
        if v.lower() in ('yes', 'true', 't', 'y', '1'):
            return True
        elif v.lower() in ('no', 'false', 'f', 'n', '0'):
            return False
        else:
            raise ArgumentTypeError('Boolean value expected')

    def release_dot2no_dot(self,rel):
        return rel.replace('.','')

    def release_no_dot2dot(self,rel):
        if len(rel) == 2:
            rel = rel[0]+'.'+rel[1]
        else:
            rel = rel[0]+'.'+rel[1]+'.'+rel[2:]
        return rel

    def trim_str(self,str):
        if not str: 
            str='-'
        else:
            str = str.strip()
        return str

    def get_jenkins_url(self,jenkins_log_file):
        mr=matchObj=re.search(r".*u'url': u'([^']*)'.*",jenkins_log_file)
        if mr:
            return mr.group(1)
        else:
            print("ERR:can not find pipeline job url ")

    def get_build_logs_url(self,jenkins_build_logs_url):
        build_logs=re.search(r'.*<a href="(.*)">Build logs.*',jenkins_build_logs_url)
        if build_logs: 
            return build_logs.group(1)
        else:
            print("can not get build logs url")

    def generate_batchesRan(self,test_Summary):
        with open(test_Summary,'r') as ff:
            jsonContent=ff.read()
        json_str=json.dumps(jsonContent)
        ojt = json.loads(json_str).encode('utf-8')
        data = json.loads(ojt)
        return data

    def listFD(self,url, ext=''):
        fileList=[]
        page = requests.get(url).text
        #print(page)
        soup = BeautifulSoup(page, 'html.parser')
        for node in soup.find_all('a'):
            fileList.append(node.get('href'))
        return fileList

    def get_jenkins_results(self,summaryDic):
        batches=summaryDic['batches']['batchesRan']
        buildID=self.options.buildID
        Platform=self.options.Platform
        urlLenght=len(self.jenkins_result_log_url)
        if self.jenkins_result_log_url.endswith('/'):
            clickTestJenkindNum=self.jenkins_result_log_url.split('/')[-2]
        else:
            clickTestJenkindNum=self.jenkins_result_log_url.split('/')[-1]
        tt=time.strftime('%b%d%H%M%S',time.localtime())
        LogDir="SB_Logs_atxuser-%s"%tt

        allFiles=self.listFD(self.jenkins_result_log_url)
        checkFileList=[]
        execCommandList=[]
        execCommandList2=[]
        for batchI in batches:
            batchDownLoadSrc='/'.join([self.jenkins_result_log_url,batchI])+'/'
            batchDownLoadDest='/'.join([self.logServerDirectory,buildID,Platform,LogDir+'_'+batchI])+'/'
            checkFileList.append(batchDownLoadDest)
            cmd1='wget -r -k -L -P %s -np -nH --cut-dirs=6 -R index.html %s'%(batchDownLoadDest,batchDownLoadSrc)
            cmd2='unzip %s%s-clicktestLog.zip -d %s%s-clicktestLog'%(batchDownLoadDest,batchI,batchDownLoadDest,batchI)
            cmd3='mv -f %s%s-clicktestLog/*/%s/* %s' % (batchDownLoadDest,batchI,batchI,batchDownLoadDest)
            execCommandList += [cmd1,cmd2,cmd3]
            #execCommandList.append(cmd)

        for commonF in allFiles:
            if commonF!='../' and commonF.rstrip('/') not in batches:
                commonDownloadSrc='/'.join([self.jenkins_result_log_url,commonF])
                commonDownloadDest='/'.join([self.logServerDirectory,buildID,Platform,LogDir])+'/'
                checkFileList.append(commonDownloadDest)
                if commonF.endswith('/'):
                    cmd='wget -r -k -L -P %s -np -nH --cut-dirs=5 -R index.html %s'%(commonDownloadDest,commonDownloadSrc)
                    execCommandList2.append(cmd)
                else:
                    cmd='wget -r -k -L -P %s -np -nH --cut-dirs=5 -R index.html %s'%(commonDownloadDest,commonDownloadSrc)
                    execCommandList.append(cmd)
        execCommandList+=execCommandList2

        print('checkFileList is:%s'%set(checkFileList))
        self.logServerCheckFile(self.logServerIp,self.logServerUser,self.logServerPwd,set(checkFileList))
        print('execCommandList is:%s'%execCommandList)
        wgetResultList=[]
        for cmd in execCommandList:
            wgetResult=ssh2(self.logServerIp,self.logServerUser, self.logServerPwd,[cmd])
            wgetResultList.append(wgetResult)
        db_print('wgetResultList is:%s'%wgetResultList)
        if set(wgetResultList)==set(['']):
            LogDirDisplay="atxuser-%s"%tt
            print('Updating %s directory'%LogDirDisplay)
            print('Updating Batches: %s'%batches)

    def get_host_ATC_result(self):
        test_Summary = "%s/testSummary.json"%self.WORKSPACE
        cmd="wget -r -O %s %s/testSummary.json"%(test_Summary,self.jenkins_result_log_url)
        os.system(cmd)
        summaryInfo = self.generate_batchesRan(test_Summary)
        self.get_jenkins_results(summaryInfo)


    def run_jenkins_on_cloud(self,credentials):
        cmd="grep url %s/jenkins.log"%self.WORKSPACE
        jenkins_log_file=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0].strip()
        jenkins_log_url = self.get_jenkins_url(jenkins_log_file)
        print("jenkins_log_url=%s"%jenkins_log_url)
       # cmd="curl --user '%s:%s' %s | grep \"Build logs\""%(self.options.CSL,self.options.CSLPWD,jenkins_log_url)
       # print(cmd)
       # jenkins_build_logs_url=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0].strip()
       # self.jenkins_result_log_url = self.get_build_logs_url(jenkins_build_logs_url)
        jenkinsCont = requests.get(jenkins_log_url,auth=credentials, timeout=300)
        jenkinsMatch = re.search(r'.*<a href="(.*)">Build logs.*',jenkinsCont.content)
        self.jenkins_result_log_url = jenkinsMatch.group(1)
        print('jenkins_build_log_url is:%s'%self.jenkins_result_log_url)

    def logServerCheckFile(self,host_ip,username,password,pathList):
        print('#############################')
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host_ip, 22, username, password, timeout=5)
        for remotePath in pathList:
            cmd='mkdir -p %s'%remotePath
            print(cmd)
            stdin, stdout, stderr = client.exec_command(cmd)
        print(stdout.read().decode('utf-8'))

        client.close() 


    def readFileFromLogServer(self,host_ip, port, username, password,file_path):
        print('readFileFromLogServer host_ip is:%s,file is:%s'%(host_ip,file_path))
        contentLines=[]
        client = paramiko.SSHClient()
        try:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host_ip, port, username, password, timeout=5)
            sftp_client = client.open_sftp()
            remote_file = sftp_client.open(file_path, 'r+')
            contentLines=remote_file.read()
            remote_file.close()
            return 300
        except:
            print('failed to open the remote file!')
            return 301
        finally:
            client.close()
            return contentLines

    def getBatchList(self):
        batchHostIP=self.options.batchHostIP
        batchHostUser=self.options.batchHostUser
        batchHostPWD=self.options.batchHostPWD
        batchHostRobotPath=self.options.batchHostRobotPath
        file_path='%s/BATCH/hostbatch.json'%batchHostRobotPath
        batchInfo=self.readFileFromLogServer(batchHostIP, 22, batchHostUser, batchHostPWD,file_path)
        import json
        batchDic=json.loads(batchInfo)
        batchList=batchDic.keys()
        if self.options.Batch:
            userBatches=self.options.Batch.split(',')
            batchList=list(set(batchList+userBatches))
        print('available batchList is:%s'%batchList)
        return batchList

    def run_jenkins_on_local(self,clickTestResult):
        remotelogDir=''
        lines1=clickTestResult.split('\\r\\n')
        lines2=clickTestResult.split('\r\n')
        if len(lines1)>1:
            lines=lines1
        if len(lines2)>1:
            lines=lines2
        findResult=False
        findHead=False
        batchList=[]
        allAvailableBatches=self.getBatchList()
        for line in lines:
            if 'Test Result' in line:
                findResult=True
            if 'Batch' in line and 'Status' in line and 'Total' in line:
                findHead=True
                continue
            if findResult and findHead and 'total time:' in line:
                break
            if findResult and findHead:
                ll=line.split(' ')
                allItems=[x for x in ll if x != '']
                if allItems and len(allItems)>=7:
                    if allItems[0] in allAvailableBatches:
                        batchList.append(allItems[0])
                        remotelogDir=allItems[7]
        print('remotelogDir is:%s'%remotelogDir)
        print('batchList is:%s'%batchList)
        return remotelogDir,batchList

    def getRemoteFileList(self,cmd):
        ss=ssh2(self.options.remoteIp,self.options.remoteUsername,self.options.remotePasswd,cmd,'print')
        lines1=ss.split('\\r\\n')
        lines2=ss.split('\r\n')
        if len(lines1)>1:
            lines=lines1
        if len(lines2)>1:
            lines=lines2
        directoryList=[]
        fileList=[]
        for line in lines[1:]:
            if line:
                tt=line.split(' ')
                if len(tt)>2:
                    if tt[0].startswith('d'):
                        directoryList.append(tt[-1])
                    else:
                        fileList.append(tt[-1])
        print(directoryList)
        print(fileList)
        return directoryList,fileList

    def get_local_ATC_result(self,remotelogDir,batchList):
        if remotelogDir:
            buildID=self.options.buildID
            Platform=self.options.Platform
            tt=time.strftime('%b%d%H%M%S',time.localtime())
            LogDir="SB_Logs_atxuser-%s"%tt
            ########copy batch log################
            for batchI in batchList:
                logServerLogPath='/'.join([self.logServerDirectory,buildID,Platform,LogDir+'_'+batchI])+'/'
                checkFileList=[logServerLogPath]
                self.logServerCheckFile(self.logServerIp,self.logServerUser,self.logServerPwd,set(checkFileList))
                logSrcDir=remotelogDir+'/'+batchI
                cmd='sshpass -p %s scp -P 22 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r %s@%s:%s/* %s'%(self.options.remotePasswd,self.options.remoteUsername,self.options.remoteIp,logSrcDir,logServerLogPath)
                print(cmd)
                ssh2(self.logServerIp,self.logServerUser,self.logServerPwd,cmd)
            #####copy common logs#################
            cmd='ls -l %s'%remotelogDir
            directoryList,fileList=self.getRemoteFileList(cmd)
            commonDestDir='/'.join([self.logServerDirectory,buildID,Platform,LogDir])+'/'
            checkFileList=[commonDestDir]
            self.logServerCheckFile(self.logServerIp,self.logServerUser,self.logServerPwd,set(checkFileList))
            for dirItem in directoryList:
                if dirItem not in batchList:
                    logSrcDir=remotelogDir+'/'+dirItem
                    cmd='sshpass -p %s scp -P 22 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r %s@%s:%s %s'%(self.options.remotePasswd,self.options.remoteUsername,self.options.remoteIp,logSrcDir,commonDestDir)
                    print(cmd)
                    ssh2(self.logServerIp,self.logServerUser,self.logServerPwd,cmd)
            for fileItem in fileList:
                logSrcDir=remotelogDir+'/'+fileItem
                cmd='sshpass -p %s scp -P 22 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r %s@%s:%s %s'%(self.options.remotePasswd,self.options.remoteUsername,self.options.remoteIp,logSrcDir,commonDestDir)
                print(cmd)
                ssh2(self.logServerIp,self.logServerUser,self.logServerPwd,cmd)

            LogDirDisplay="atxuser-%s"%tt
            print('Updating %s directory'%LogDirDisplay)
            print('Updating Batches: %s'%batchList)

if __name__ == '__main__':
    obj = clickTest()
    options=obj.options

    #####################################get host batches to run#############################################
    print("get host batches to run")
    if obj.var_host_ATC_on_cloud:
        print('on cloud')
        cmd="mkdir -p %s && chmod a+w %s"%(obj.WORKSPACE,obj.WORKSPACE)
        print(cmd)
        os.system(cmd)
        cmd="%s/pythonlib/get_settings/get_settings.py areaci clicktest_trigger"%obj.devtoolsPath
        print(cmd)
        clicktest_trigger=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0].strip()
        cmd="%s/pythonlib/get_settings/get_settings.py areaci clicktest_user"%obj.devtoolsPath
        print(cmd)
        clicktest_user =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0].strip()
        cmd="%s/pythonlib/get_settings/get_settings.py areaci clicktest_apikey"%obj.devtoolsPath
        print(cmd)
        clicktest_api_key =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0].strip()
        print("clicktest_trigger=%s, clicktest_user=%s, clicktest_api_key=%s"%(clicktest_trigger,clicktest_user,clicktest_api_key))

        print('boards is:%s'%obj.host_boards)
        print('build id is:%s'%options.buildID)
        if options.buildResults:
            buildValue=options.buildResults
        elif options.buildID!='latest' and options.buildID:
            buildValue=options.buildID
        else:
            buildValue=''
        ROBOT_REV=options.ROBOT_REV
        if options.robot_repo:
            build_ip=options.build_ip
            build_port=options.build_port
            build_user=options.build_user
            build_passwd=options.build_passwd

            cmd=["hg outgoing -r %s -R %s ssh://hg@hg.be.alcatel-lucent.com/staging/test/robot"%(options.ROBOT_REV,options.robot_repo)]
            status=ssh2(build_ip,build_user,build_passwd,cmd,'print',port=build_port)
            print('hg outgoing result is:%s'%status)
            if status:
                if 'no changes found' in status:
                    changes=False
                else:
                    changes=True
            else:
                changes=False
            if changes:
                cmd=["hg push -f -r %s -R %s ssh://hg@hg.be.alcatel-lucent.com/staging/test/robot"%(options.ROBOT_REV,options.robot_repo)]
                ssh2(build_ip,build_user,build_passwd,cmd,'print',port=build_port)
            cmd=['hg id -i -R %s -r %s'%(options.robot_repo,options.ROBOT_REV)]
            ROBOT_REV=ssh2(build_ip,build_user,build_passwd,cmd,'print',port=build_port).strip()
            print('hg id to get ROBOT_REV:%s'%ROBOT_REV)

        credentials = (clicktest_user,clicktest_api_key)
        cmd="python %s/pythonlib/jenkins.py --trigger %s --wait --verbose --credentials user=%s --credentials pass=%s"%(obj.devtoolsPath,clicktest_trigger,clicktest_user,clicktest_api_key)
        cloudOptions={'USER':options.display_user,'BOARDS':obj.host_boards,'BUILD':buildValue,'RELEASE':options.release,'TESTBATCHES':options.Batch,'FRAMEWORK':options.FRAMEWORK,
        'TIMESTAMP':options.TIMESTAMP,'DEVTOOLS_REV':options.DEVTOOLS_REV,'ATC_REV':options.ATC_REV,'ROBOT_REV':ROBOT_REV,'TEST_PACKAGES_REV':options.TEST_PACKAGES_REV,
        'CS':options.CS,'SUPPRESSED_TESTBATCHES':options.SUPPRESSED_TESTBATCHES,'SUSPENDED_TESTBATCHES':options.SUSPENDED_TESTBATCHES,'REGRESSION_MODE_RUN':options.REGRESSION_MODE_RUN,
        'RERUN_TESTBATCHES':options.RERUN_TESTBATCHES,'TAGS':options.TAGS}
        for cloudOptionsItem,cloudOptionsValue in cloudOptions.items():
            if cloudOptionsValue!='':
                cmd+=' --parameters %s=%s'%(cloudOptionsItem,cloudOptionsValue)
        if options.area_coverage:
            cmd+=' --parameters COVERAGE=area'
        cmd+=' 2>&1 | tee %s/jenkins.log'%obj.WORKSPACE
        print(cmd)
        os.system(cmd)
        obj.run_jenkins_on_cloud(credentials)
        obj.get_host_ATC_result()
    else:
        print('not on cloud')
        Batches=options.Batch
        binPath=options.binPath
        remoteIp=options.remoteIp
        remoteUsername=options.remoteUsername
        remotePasswd=options.remotePasswd
        release=options.release
        buildID=options.buildID
        buildResult=options.buildResults
        Boards=options.boards
        FRAMEWORK=options.FRAMEWORK
        if buildResult:
            buildValue=buildResult
        elif buildID and buildID!='latest':
            buildValue=buildID
        else:
            buildValue=''
        cmd="%s/bin/clicktest"%binPath
        localOptions={'board':Boards,'build':buildValue,'release':release,'batch':Batches,'framework':FRAMEWORK}
        for localOptionItem,localOptionValue in localOptions.items():
            if localOptionValue!='':
                cmd+=' --%s %s'%(localOptionItem,localOptionValue)
        if options.area_coverage:
            cmd+=' --area-coverage'
        print(cmd)
        clickTestResult=ssh2(remoteIp,remoteUsername,remotePasswd,cmd,'print')
        localLogDir,batchList=obj.run_jenkins_on_local(clickTestResult)
        obj.get_local_ATC_result(localLogDir,batchList)

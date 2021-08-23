#!/usr/bin/python

#coding:utf-8

import subprocess, os, re, sys, paramiko,ftplib
from optparse import OptionParser
import argparse,json
import urlparse
repo_atc = '/repo/atxuser/atc'
repo_robot = '/repo/atxuser/robot'
repo_packages = '/repo/TEST_PACKAGES'
repo_moswa= '/repo/atxuser/moswa'
repo_devtools ='/repo/atxuser/devtools'
#urlparse
#parse
#parser = OptionParser()
parser= argparse.ArgumentParser()
parser.add_argument("--csTag", dest="csTag",default='NON', help="CS id info")
parser.add_argument("--pcta", dest="pcta",default="", help="PCTA IP")
parser.add_argument("--pctaPasswd", dest="pctaPasswd",default="alcatel01", help="PCTA password info")
parser.add_argument("--pctaUser", dest="pctaUser",default="atxuser", help="PCTA user info")
parser.add_argument("--pctaPort", dest="pctaPort",default="22", help="PCTA ssh port")
#parser.add_argument("--repo", dest="repo",default="", help="repo path", action='append', type=str)
parser.add_argument("--repoInfo", dest="repoInfo",default='', help="repoInfo", type=str)
#parser.parse_args('--repo ATC:/repo/atxuser/atc:CS1945 --repo ROBOT:/repo/atxuser/robot:CS1947'.split())
parser.add_argument("--purgeRepo", dest="purgeRepo",action="store_true",default=False, help="purge repo")
args = parser.parse_args()
csTag = args.csTag
pcta = args.pcta
pctaPasswd = args.pctaPasswd
pctaUser = args.pctaUser
pctaPort = args.pctaPort
repoInfo = args.repoInfo
purgeRepo = args.purgeRepo

#repoPath is a wrapped parameter,with field separator of :
#content could be
#ROBOT:/repo/atxuses/robot,ATC:/repo/atxuser/atc,PACKAGES:/repo/TEST_PACKAGES
#ROBOT:/repo/atxuser/robot
#ATC:/repo/atxuser/atc,PACKAGES:/repo/TEST_PACKAGES
if repoInfo:
    repoInfo=json.loads(repoInfo)
    repo_atc = repoInfo.get('ATC',repo_atc)
    repo_robot = repoInfo.get('ROBOT',repo_robot)
    #repo_packages = repoInfo.get('PACKAGES',repo_packages)
    repo_moswa= repoInfo.get('MOSWA',repo_moswa)
    repo_devtools = repoInfo.get('DEVTOOLS',repo_devtools)

#print(args)
#first parse --repo into a list['ATC:/repo/atxuser/atc:CS1945','ROBOT:/repo/atxuser/robot:CS1944']
#loop this list and parse each element in this list in to dictionary
#so the result can be a dictionaries of dictionary
#e.g.
'''
repoDict={
    'ATC':{'PATH':'/repo/atxuser/atc',
           'TAG':'CS1945'
          },
    'ROBOT':{'PATH':'/repo/atxuser/robot',
           'TAG':'CS1944'
          },
    'DEVTOOL':{'PATH':'/repo/atxuser/devtools',
           'TAG':'12948883dessdc'
          }
}
'''
centraRepo={
   #APME REPO

   'ATC':{

          'TBV':'ssh://remoteuser@135.249.31.114//repo/ci/validation/atc',

          'DEFAULT':'ssh://remoteuser@135.249.31.114//repo/isamtestserver/atc'

         },

   #ROBOT REPO

   'ROBOT':{

          'TBV':'ssh://remoteuser@135.249.31.114//repo/ci/validation/robot',

          'DEFAULT':'ssh://remoteuser@135.249.31.114//repo/isamtestserver/robot'

         },

   #TEST PACKAGE REPO

   'TEST_PACKAGE':{

          'DEFAULT':'ssh://remoteuser@135.249.31.114//repo/TEST_PACKAGES'

         },

   #MOSWA REPO

   'MOSWA':{

          'TBV':'ssh://remoteuser@135.249.31.114//repo/ci/validation/moswa',

          'DEFAULT':'ssh://remoteuser@135.249.31.114//repo/isamtestserver/moswa'

         },

   'DEVTOOL':{

          'DEFAULT':'ssh://hg@hg.be.alcatel-lucent.com/all/devtools'

         }

}

hspath='ftp://rmtlab:rmtlab@172.21.128.21/CS_HISTORY'
def updateRepo(pcta,pctaUser,pctaPasswd,pctaPort='22',csTag='',purgeRepo=False): 
    dir_list=[]
    repo_cmd_list=[]
    repo_cmd1_list=[]
    repo_cmd2_list=[]
    repo_cmd3_list=[]
    repo_cmd4_list=[]
    repo_cmd5_list=[]
    HOST = pcta
    CS_TAG = csTag
    host_user=pctaUser
    host_passwd=pctaPasswd
    host_port = pctaPort
    #for RLAB machne, CS_HISTORY is mounted,no need of downloading
    cs_dir = "cd /storage/CS_HISTORY/"
    cs_history_dir="/storage/CS_HISTORY"
    cs_history_file="/storage/CS_HISTORY/CS_history.txt"
    hg_cmd = "hg update -C -r"
    new_space = " "
    repo_dir1 = "cd %s" %repo_atc
    repo_dir2 = "cd %s" %repo_packages
    repo_dir3 = "cd %s" %repo_robot
    repo_dir4=  "cd %s" %repo_moswa
    repo_dir5=  "cd %s" %repo_devtools

    class SSH_COMMON:

        def __init__(self):
            self.user = host_user
            self.password = host_passwd
            self.port = host_port

        def login_pcta(self,ip_add,repo_dir,cmd):
            try:
                #print"mourya"
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip_add, username=self.user,password=self.password,port=int(self.port),timeout=10)
                channel = ssh.invoke_shell()
                stdin = channel.makefile('wb')
                stdout = channel.makefile('rb')
                #print"tonia"
                #print(str(repo_dir))
                #print(str(cmd))
                for x, y in map(None, repo_dir, cmd):
                    stdin.write(x+"\n")
                    for y1 in y:
                        stdin.write(y1+"\n")
                stdin.write('exit\n')
                stdin.write('exit\n')
                result= stdout.read()
                #print result
                return result
                stdout.close()
                stdin.close()
                ssh.close()
            except Exception as inst:
                print ip_add + " is not reachable with exception:%s" %inst
                sys.exit(1)

        def connect(self,ip_add,repo_dir,cmd):
            try:
                #print"Smartlab"
                dir=repo_dir+";"
                #print(dir)
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip_add,port=int(self.port),username=self.user,password=self.password)
                stdin, stdout, stderr = ssh.exec_command(dir+ str(cmd))
                output = stdout.read()
                #print output
                return output
            except Exception as inst:
                print ip_add +' is not Reachable:%s' %inst
                sys.exit(1)
    CS_TAG_MOSWA=''
    CS_TAG_DEVTOOLS=''
    CS_TAG_TEST_PACKAGES=''
    OFFICIAL_TAG_LIST = ("LATEST_VALIDATED","SMOKE","TBV","NONE")
    if CS_TAG == 'NONE':
        print "CS NOT specified.will use the latest tag"
       # return True

    ssh_obj=SSH_COMMON()
    #if branch1, atc/robot/test package repo could be different and diffirentiated
        #CS_TAG could be CS1927:CS1922:CS1947
        #CS_TAG could be CS1927::CS1947
        #CS_TAG could be ::CS1947
    #else branch, atc/robot/test package repo to be updated to the same tag/changeset, no ':' field separater
    #common part:
        #1.some tag could be official tag in OFFICIAL_TAG_LIST which means mercurail tag, can be used directly
        #the script just execute several hg command and return True
        #2.some tag could be the mercurial 12 digit changset, could be used without lookup
        #3.other tags could be non offical, need convert them by look up cs hisotry file to convert to mercurial changeset
        #the conversion part is more complex and handled in later part
    #if : in CS_TAG,means ROBOT/ATC/TEST_PACKAGES REPO
    if ':' in CS_TAG:
        tmpList = CS_TAG.split(':')
        #(CS_TAG_ROBOT,CS_TAG_APME) = CS_TAG.split(':',1)
        CS_TAG_ROBOT=tmpList[0] #==> for ROBOTREPO
        CS_TAG_APME=tmpList[1] #==> for ATCREPO
        CS_TAG_TEST_PACKAGE = '' #==>for TESTPACKAGES REPO
        if len(tmpList) == 3:
            CS_TAG_TEST_PACKAGE = tmpList[2]
        repo_cmd_list=[]
        dir_list=[]
        if all((CS_TAG_ROBOT,CS_TAG_APME)) and all((CS_TAG_ROBOT in OFFICIAL_TAG_LIST,CS_TAG_APME in OFFICIAL_TAG_LIST)):
            if CS_TAG_APME == 'TBV':
                repo_cmd1_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['ATC']['TBV'],"hg update -r %s -C" %CS_TAG_APME]
            else:
                repo_cmd1_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['ATC']['DEFAULT'],"hg update -r %s -C" %CS_TAG_APME]
            if purgeRepo:
                repo_cmd1_list.insert(1,'hg purge')
            repo_cmd_list.append(repo_cmd1_list)
            dir_list.append(repo_dir1)
            if CS_TAG_ROBOT =='TBV':
                repo_cmd3_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['ROBOT']['TBV'],"hg update -r %s -C" %CS_TAG_ROBOT]
            else:
                repo_cmd3_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['ROBOT']['DEFAULT'],"hg update -r %s -C" %CS_TAG_ROBOT]
            if purgeRepo:
                repo_cmd3_list.insert(1,'hg purge')
            repo_cmd_list.append(repo_cmd3_list)
            dir_list.append(repo_dir3)
            var2 = ssh_obj.login_pcta(HOST,dir_list,repo_cmd_list)
            print var2
            print "REPO UPDATED SUCCESSFULLY"
            return True
        if CS_TAG_ROBOT and not CS_TAG_APME and CS_TAG_ROBOT in OFFICIAL_TAG_LIST:
            if CS_TAG_ROBOT == 'TBV':
                repo_cmd3_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['ROBOT']['TBV'],"hg update -r %s -C" %CS_TAG_ROBOT]
            else:
                repo_cmd3_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['ROBOT']['DEFAULT'],"hg update -r %s -C" %CS_TAG_ROBOT]
            if purgeRepo:
                repo_cmd3_list.insert(1,'hg purge')
            repo_cmd_list.append(repo_cmd3_list)
            dir_list.append(repo_dir3)
            var2 = ssh_obj.login_pcta(HOST,dir_list,repo_cmd_list)
            print var2
            print "REPO UPDATED SUCCESSFULLY"
            return True
        if CS_TAG_APME and not CS_TAG_ROBOT and CS_TAG_APME in OFFICIAL_TAG_LIST:
            if CS_TAG_APME == 'TBV':
                repo_cmd1_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['ATC']['TBV'],"hg update -r %s -C" %CS_TAG_APME]
            else:
                repo_cmd1_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['ATC']['DEFAULT'],"hg update -r %s -C" %CS_TAG_APME]
            if purgeRepo:
                repo_cmd1_list.insert(1,'hg purge')
            repo_cmd_list.append(repo_cmd1_list)
            dir_list.append(repo_dir1)

            var2 = ssh_obj.login_pcta(HOST,dir_list,repo_cmd_list)
            print var2
            print "REPO UPDATED SUCCESSFULLY"
            return True
        #CS_TAG_TEST_PACKAGE = ''
    else:
        #two possibilities,for current condition, means update ROBOT/ATC/TEST PACKAGES with the same tag
        #or for MOSWA repo only
        print(repoInfo)
        if 'MOSWA' in repoInfo:
            CS_TAG_ROBOT = ''
            CS_TAG_APME = ''
            CS_TAG_TEST_PACKAGE = ''
            CS_TAG_MOSWA=CS_TAG
        else:
            CS_TAG_ROBOT = CS_TAG
            CS_TAG_APME = CS_TAG
            CS_TAG_TEST_PACKAGE = CS_TAG
            CS_TAG_MOSWA=''
        print(CS_TAG_ROBOT)
        print(CS_TAG_APME)
        print(CS_TAG_TEST_PACKAGE)
        if CS_TAG in OFFICIAL_TAG_LIST:
            if CS_TAG_APME == 'TBV':
                repo_cmd1_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['ATC']['TBV'],"hg update -r %s -C" %CS_TAG_APME]
            elif CS_TAG_APME == 'NONE':
                repo_cmd1_list =  ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['ATC']['DEFAULT'],"hg update -C"]
            else:
                repo_cmd1_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['ATC']['DEFAULT'],"hg update -r %s -C" %CS_TAG_APME]
            if purgeRepo:
                repo_cmd1_list.insert(1,'hg purge')
            repo_cmd_list.append(repo_cmd1_list)
            dir_list.append(repo_dir1)
            if CS_TAG_ROBOT == 'TBV':
                repo_cmd3_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['ROBOT']['TBV'],"hg update -r %s -C" %CS_TAG_ROBOT]
            elif CS_TAG_APME == 'NONE':
                repo_cmd3_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['ROBOT']['DEFAULT'],"hg update -C"]
            else:
                repo_cmd3_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['ROBOT']['DEFAULT'],"hg update -r %s -C" %CS_TAG_ROBOT]
            if purgeRepo:
                repo_cmd3_list.insert(1,'hg purge')
            repo_cmd_list.append(repo_cmd3_list)
            dir_list.append(repo_dir3)

            if CS_TAG_APME == 'NONE':
                repo_cmd2_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['TEST_PACKAGE']['DEFAULT'],"hg update -C"]
            else:
                repo_cmd2_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['TEST_PACKAGE']['DEFAULT'],"hg update -r %s -C" %CS_TAG_TEST_PACKAGE]
            if purgeRepo:
                repo_cmd2_list.insert(1,'hg purge')
            repo_cmd_list.append(repo_cmd2_list)
            dir_list.append(repo_dir2)

            if CS_TAG_MOSWA == 'TBV':
                repo_cmd4_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['MOSWA']['TBV'],"hg update -r %s -C" %CS_TAG_MOSWA]
            elif CS_TAG_MOSWA == 'NONE':
                repo_cmd4_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['MOSWA']['DEFAULT'],"hg update -C"]
            else:
                repo_cmd4_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['MOSWA']['DEFAULT'],"hg update -r %s -C" %CS_TAG_MOSWA]
            if purgeRepo:
                repo_cmd4_list.insert(1,'hg purge')
            repo_cmd_list.append(repo_cmd4_list)
            dir_list.append(repo_dir4)

            #if CS_TAG_DEVTOOLS == 'TBV':
             #   repo_cmd5_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['DEVTOOL']['TBV'],"hg update -r %s -C" %CS_TAG_DEVTOOLS]
            '''
            if CS_TAG_DEVTOOLS == 'NONE':
                repo_cmd5_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['DEVTOOL']['DEFAULT'],"hg update -C"]
            else:
                repo_cmd5_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['DEVTOOL']['DEFAULT'],"hg update -r %s -C" %CS_TAG_DEVTOOLS]
            if purgeRepo:
                repo_cmd5_list.insert(1,'hg purge')
            repo_cmd_list.append(repo_cmd5_list)
            dir_list.append(repo_dir5)
            '''
            print(dir_list)
            print(repo_cmd_list)
            var2 = ssh_obj.login_pcta(HOST,dir_list,repo_cmd_list)
            print var2
            print "REPO UPDATED SUCCESSFULLY"
            return True
    #here comes non-official tag handling part with cs tag to cs conversion by looking up cs history file
    #repo_cmd1_list = ["hg revert --all","hg pull ssh://remoteuser@135.249.31.114//repo/isamtestserver/atc"]
    #repo_cmd2_list = ["hg revert --all","hg pull ssh://remoteuser@135.249.31.114//repo/TEST_PACKAGES"]
    #repo_cmd3_list = ["hg revert --all","hg pull ssh://remoteuser@135.249.31.114//repo/isamtestserver/robot"]
    dir_list = []
    repo_cmd_list = []
    #cs hostory files mapping from cs tag to mercurial cs
    #one file for atc, one for robot, one for test package repo
    #located in remote ftp server directory : ftp://rmtlab:rmtlab@172.21.128.21/CS_HISTORY
    #one branch is rlab, with directly access of this dir just like a local dir, use directly ,no need download
    #use this dir:/storage/CS_HISTORY/CS_history.txt
    #another branch is non rlab, need download those files into dir of /tmp/CS_HISTORY
    #below is handling check of existence of the dir and do downloading of 3 files
    try:
        #first check whether mounted dir has cs history file for RLAB
        cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o TCPKeepAlive=yes -o UserKnownHostsFile=/dev/null -p%s %s@%s 'ls %s'" %(host_passwd,host_port,host_user,HOST,cs_history_file)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        #print(result)
        if result == "":
            #if no mounted dir of cs history, try /tmp
            print(cs_history_file)
            print "%s not available" %cs_history_file
            cs_history_dir='/tmp/CS_HISTORY'
            print "try temporary cs history dir:%s" %cs_history_dir
            cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o TCPKeepAlive=yes -o UserKnownHostsFile=/dev/null -p%s %s@%s 'rm -rf %s;mkdir -p %s'" %(host_passwd,host_port,host_user,HOST,cs_history_dir,cs_history_dir)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o TCPKeepAlive=yes -o UserKnownHostsFile=/dev/null -p%s %s@%s 'ls -d %s'" %(host_passwd,host_port,host_user,HOST,cs_history_dir)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            if result == "": 
                print "REPO NOT UPDATED"
                return True
                sys.exit()
            cs_dir = 'cd %s' %cs_history_dir
            hs_ftp_path=urlparse.urlparse(hspath)
            hs_ftp_credentials=re.split(r'[:@]',hs_ftp_path.netloc)
            cmd_wget = 'wget --ftp-user=%s --ftp-password=%s ftp://%s%s' %(hs_ftp_credentials[0],hs_ftp_credentials[1],hs_ftp_credentials[2],hs_ftp_path.path)
            #cmd1 = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p%s %s@%s '%s/CS_history.txt'" %(host_passwd,host_port,host_user,HOST,cmd_wget)
            cmd1 = cmd_wget + '/CS_history.txt' + " " + "-O"+ " "+"CS_history.txt"
            print(cmd1)
            #result=subprocess.Popen(cmd1, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            result = ssh_obj.connect(HOST,cs_dir,cmd1)

            #cmd2 = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p%s %s@%s '%s/CS_history_test_packages.txt'" %(host_passwd,host_port,host_user,HOST,cmd_wget)
            cmd2 = cmd_wget + '/CS_history_test_packages.txt'+" "+"-O" +" "+"CS_history_test_packages.txt"
            print(cmd2)
            #result=subprocess.Popen(cmd2, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            result = ssh_obj.connect(HOST,cs_dir,cmd2)

            #cmd3 = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p%s %s@%s '%s/CS_history_robot.txt'" %(host_passwd,host_port,host_user,HOST,cmd_wget)
            cmd3 = cmd_wget + '/CS_history_robot.txt' + " "+ "-O" + " "+ "CS_history_robot.txt"
            print(cmd3)
            #result=subprocess.Popen(cmd3, stdin=subprocess.PIPE,stdout=subprocesscd .PIPE, shell=True).communicate()[0]
            result = ssh_obj.connect(HOST,cs_dir,cmd3)



            repo_cmd1_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['ATC']['DEFAULT']]
            repo_cmd2_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['TEST_PACKAGE']['DEFAULT']]
            repo_cmd3_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['ROBOT']['DEFAULT']]
            repo_cmd4_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['MOSWA']['DEFAULT']]
            repo_cmd5_list = ["hg revert --all","hg pull --ssh 'ssh -o StrictHostKeyChecking=no -oBatchMode=yes' %s" %centraRepo['DEVTOOL']['DEFAULT']]

        #####To grep APME CS tag#############
        #grep the cs tag in the hisotry file accordinly and get mercurial changeset
        apmevar =0
        var=0
        var1=0
        var2=0
        var3=0
        if CS_TAG_APME:#atc repo
            #if already global changeset
            #part1,process changeset
            if len(CS_TAG_APME) == 12:#tag type 2, 12 digit changeset,no need conversion,used directly
                apmevar = CS_TAG_APME
                print apmevar
            else:#tag type3, need lookup and conversion
                grep_apme_cmd = "grep"+" "+CS_TAG_APME+" "+ "CS_history.txt"
                var = ssh_obj.connect(HOST,cs_dir,grep_apme_cmd)
                print(grep_apme_cmd)
                if var != "":
                    apmevar = var.split(":")[1].strip()
                else:
                    print apmevar
                    apmevar = ""
                    print CS_TAG+"  is invalid"
                    return False
                    sys.exit(1)
            #part2,check existence of current changeset on the atc repo
            if apmevar:
                old_cs = ssh_obj.connect(HOST,repo_dir1,'hg id')
                #old_cs = old_cs.split(":")[0]
                old_cs = re.split('[\s\+]',old_cs)[0].strip()
                print "current apme repo cs is %s" %old_cs
                print "target apme repo cs is %s" %apmevar
                #if current repo existing,skip
                if old_cs == apmevar:
                    print "current apme repo is already %s equal to %s,ignore!" %(old_cs,apmevar)
                else:
                #if not existing, execute related hg commands to update repo chageset 
                    apme_cmd = hg_cmd+new_space+apmevar
                    repo_cmd1_list.insert(2,apme_cmd)
                    if purgeRepo:
                        repo_cmd1_list.insert(1,'hg purge')
                    repo_cmd_list.append(repo_cmd1_list)
                    dir_list.append(repo_dir1)
                    print "update apme repo to be %s" %apmevar

        if CS_TAG_TEST_PACKAGE:#test package repo mercurial changeset lookup
            if len(CS_TAG_TEST_PACKAGE) == 12:
                test_packagevar = CS_TAG_TEST_PACKAGE
            else:
                grep_test_package_cmd = "grep"+" "+CS_TAG_TEST_PACKAGE+" "+"CS_history_test_packages.txt"
                print(grep_test_package_cmd)
                var = ssh_obj.connect(HOST,cs_dir,grep_test_package_cmd)
                if var != "":
                    test_packagevar = var.split(":")[1].strip()
                else:
                    test_packagevar = ssh_obj.connect(HOST,repo_dir2,'hg tags |grep %s' %CS_TAG_TEST_PACKAGE)
                    test_packagevar = test_packagevar.split(':')[-1].strip()
            if test_packagevar:
                old_cs = ssh_obj.connect(HOST,repo_dir2,'hg id')
                old_cs = re.split('[\s\+]',old_cs)[0].strip()
                print "current testpackage repo cs is %s" %old_cs
                print "target testpackage repo cs is %s" %test_packagevar
                if old_cs == test_packagevar:
                    print "current testpackage repo is already %s equal to %s,ignore!" %(old_cs,test_packagevar)
                else:
                    robo_cmd = hg_cmd+new_space+test_packagevar
                    repo_cmd2_list.insert(2,robo_cmd)
                    if purgeRepo:
                        repo_cmd2_list.insert(1,'hg purge')
                    repo_cmd_list.append(repo_cmd2_list)
                    dir_list.append(repo_dir2) 
                    print "update testpackage repo to be %s" %var

        #####To grep ROBOT CS tag##############
        if CS_TAG_ROBOT:#robot chageset lookup
            if len(CS_TAG_ROBOT) == 12:
                robovar = CS_TAG_ROBOT
            else:
                grep_robo_cmd = "grep"+" "+CS_TAG_ROBOT+" "+"CS_history_robot.txt"
                print(grep_robo_cmd)
                var1 = ssh_obj.connect(HOST,cs_dir,grep_robo_cmd)
                if var1 != "":
                    robovar = var1.split(":")[1].strip()
                else:
                    robovar = ""
                    print CS_TAG+"  is invalid"
                    return False
                    sys.exit(1)
            if robovar:
                old_cs = ssh_obj.connect(HOST,repo_dir3,'hg id')
                #old_cs = old_cs.split(":")[0]
                old_cs = re.split('[\s\+]',old_cs)[0].strip()
                print "current robot repo cs is %s" %old_cs
                print "target robot repo cs is %s" %robovar
                if old_cs == robovar:
                    print "current robot repo is already %s equal to %s,ignore!" %(old_cs,robovar)
                else:
                    robo_cmd = hg_cmd+new_space+robovar
                    repo_cmd3_list.insert(2,robo_cmd)
                    if purgeRepo:
                        repo_cmd3_list.insert(1,'hg purge')
                    repo_cmd_list.append(repo_cmd3_list)
                    dir_list.append(repo_dir3)
                    print "update robot repo to be %s" %var1
        #here with all hg commands ready, now execute them one by one    
        '''
	if CS_TAG_MOSWA:#robot chageset lookup
            if len(CS_TAG_MOSWA) == 12:
                mosovar = CS_TAG_MOSWA
            else:
                grep_moso_cmd = "grep"+" "+CS_TAG_MOSWA+" "+"CS_history_moswa.txt"
                var1 = ssh_obj.connect(HOST,cs_dir,grep_robo_cmd)
                if var1 != "":
                    mosovar = var1.split(":")[1].strip()
                else:
                    mosovar = ""
                    print CS_TAG+"  is invalid"
                    return False
                    sys.exit(1)
            if mosovar:
                old_cs = ssh_obj.connect(HOST,repo_dir4,'hg id')
                #old_cs = old_cs.split(":")[0]
                old_cs = re.split('[\s\+]',old_cs)[0].strip()
                print "current moswa repo cs is %s" %old_cs
                print "target moswa repo cs is %s" %mosovar
                if old_cs == mosovar:
                    print "current robot repo is already %s equal to %s,ignore!" %(old_cs,robovar)
                else:
                    moso_cmd = hg_cmd+new_space+mosovar
                    repo_cmd4_list.insert(2,moso_cmd)
                    if purgeRepo:
                        repo_cmd4_list.insert(1,'hg purge')
                    repo_cmd_list.append(repo_cmd4_list)
                    dir_list.append(repo_dir4)
                    print "update moswa repo to be %s" %var1

	if CS_TAG_DEVTOOLS:#robot chageset lookup
            if len(CS_TAG_DEVTOOLS) == 12:
                devvar = CS_TAG_DEVTOOLS
            else:
                grep_dev_cmd = "grep"+" "+CS_TAG_DEVTOOLS+" "+"CS_history_devtools.txt"
                var1 = ssh_obj.connect(HOST,cs_dir,grep_dev_cmd)
                if var1 != "":
                    devvar = var1.split(":")[1].strip()
                else:
                    devvar = ""
                    print CS_TAG+"  is invalid"
                    return False
                    sys.exit(1)
            if devvar:
                old_cs = ssh_obj.connect(HOST,repo_dir5,'hg id')
                #old_cs = old_cs.split(":")[0]
                old_cs = re.split('[\s\+]',old_cs)[0].strip()
                print "current devtools repo cs is %s" %old_cs
                print "target devtools repo cs is %s" %mosovar
                if old_cs == devvar:
                    print "current devtools repo is already %s equal to %s,ignore!" %(old_cs,devvar)
                else:
                    dev_cmd = hg_cmd+new_space+devvar
                    repo_cmd5_list.insert(2,dev_cmd)
                    if purgeRepo:
                        repo_cmd5_list.insert(1,'hg purge')
                    repo_cmd_list.append(repo_cmd5_list)
                    dir_list.append(repo_dir5)
                    print "update devtools repo to be %s" %var1'' '''
        if dir_list:
            var3 = ssh_obj.login_pcta(HOST,dir_list,repo_cmd_list)
            print var3
            print "REPO UPDATED SUCCESSFULLY"
        return True
    except Exception as inst:
        print "%s with exception:%s" %(HOST,inst)
        sys.exit(1)

#here is the script entrance, 
if __name__ == '__main__':
    if pcta.strip():
        ret=updateRepo(pcta,pctaUser,pctaPasswd,pctaPort,csTag,purgeRepo)
        print ret
        if ret:
            print 'Repo process is success'
            sys.exit()
        else:
            print 'Repo process is Failure'
            sys.exit(1)
    else:
        print("Invalid arguments")
        print("Please input at least pcta IP...")
        sys.exit(1)

import threading
import time,sys
import copy,json
import telnetlib, time, re, os, ConfigParser, sys, inspect, subprocess,datetime
from lxml import etree
from argparse import ArgumentParser
import oswpUtility
import pexpect
#from qemuUtility import startHostBySSH
ddir='/root/pylib'
sys.path.append(ddir)
from urlDaily import *
#SMARTLAB_SERVER='https://smartservice.int.nokia-sbell.com'
#SMARTLAB_SERVER='http://135.251.206.149'
#from retrieveLatestBuild import *
from sw_update_netconf import Smartlab_Instance,get_event_time
from sshClient import ssh2,ssh_scp_get,ssh2_non_block,ssh_server_check
import yaml
logLevel={'normal':0,'info':1,'debug':2}
LEVEL='normal'
PRINT_PREFIX={'recv':"<<<",'send':">>>",'debug':'---'}
loginCmd = {'TELNET':'telnet ','SSH':'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null isadmin@'}
BUILD_ID_MAP_FILE = 'BuildIDMapping.yaml'
MOSWA_NT_NETCONF_PORT = '832'
MOSWA_NT_TRACE_PORT = '923'
MOSWA_PRODUCT_MAP={
    'SDFX':{
        'transMode':'http',
        'indexDesc': 'AG',
        'dutTracePort':'2222',
        'dutNetconfPort':'830',
        'boardType':'LT'
    },
    'SDOLT':{
        'transMode':'http',
        'indexDesc': 'AG',
        'dutTracePort': '22',
        'dutNetconfPort': '830',
        'boardType': 'LT'
    },
    'NCDPU':{
        'transMode':'tftp',
        'indexDesc': 'AF',
        'dutTracePort':'2222',
        'dutNetconfPort': '830',
        'boardType': 'NT',
    }
}
#OLD_MOSWA_LT_LIST=['FGLT-B','FWLT-B']
STEP1='prepareOSWP'
STEP2='downloadOSWP'
STEP3='activateOSWP'
STEP4='initializeDUT'
ERROR_CODES={STEP1:'501',
             STEP2:'502',
             STEP3:'503',
             STEP4:'504'}
#failure code definition only as reference
#REALTIMEJOBSTATUS={'001':'oswppreparing','002':'downloading','003':'activating','004':'initializing','005':'dryrunning','060':'batchrunning','061':'domainrunning','007':'postcleaning','000':'Completed',\
#'501':'prepare oswp failure','502':'download oswp failure','503':'activation oswp failure','504':'DUT inaccessible after activation','505':'activation oswp failure','506':'DUT out of reach after activation',\
#'507':'LT is not available after build upgrade','508':'LT SW mismatch with loaded build','509':'ISAM not up for more than 10min after activate with default db','510':'Disk sync is not finished in redundancy setups after activate with default db'}
def db_print(printStr,debugType="normal",prefix='',):
    global logLevel,LEVEL
    if prefix:
        prefix = '[%s]%s' %(prefix,PRINT_PREFIX.get(debugType,'---'))
    else:
        prefix = '%s' %PRINT_PREFIX.get(debugType,'---')
    if debugType=="recv" :
        print  (prefix + printStr)
    elif debugType=="send" :
        print  (prefix + printStr)
    elif logLevel[debugType] <= logLevel[LEVEL]:
        print  (prefix + printStr)

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

class myThread(threading.Thread):
    def __init__(self,func,args=(),kwargs={}):
        super(myThread,self).__init__()
        self.func = func
        self.args = args
        self.kwargs= kwargs
    def run(self):
        self.result = self.func(*self.args,**self.kwargs)
        
    def get_result(self):
        try:
            return self.result
        except Exception as inst:
            print "Exception:%s" %inst
            return {}
        
class BUILD(object):
    def __init__(self,args):
        self.buildSource = args.setdefault('buildSource','')
        self.buildAgent = args.setdefault('buildAgent','')
        self.buildID = args.setdefault('buildID','')
        self.buildType = args.setdefault('buildType','official')
        self.buildRelease = args.setdefault('buildRelease','')
        self.sourceDict = self._parseBuildServer(self.buildSource)
        self.agentDict = self._parseAgentInfo(self.buildAgent)
        self.buildName = self._parseBuildInfo(self.buildID)
        self.buildSourceDict = args.setdefault('buildType','official')
        self.destDir = args.setdefault('destDir','/tftpboot')
        self.oswpIndexPrefix = ''
        self.moswaDict = args.setdefault('moswaDict',None)

    def _parseBuildInfo(self,build):
        resDict = {}
        try :
            prop_flag=False
            b = build.split('.')
            i1 = b[0][0:2]
            i2 = b[1]
            if re.search('p',i2):
                prop_flag=True
            resDict['proposal'] = prop_flag
            resDict['release'] = b[0]
            resDict['ver'] = i1 + re.sub('i2','p*','')
            resDict['sdfile'] = 'SD_' + build + '.tar'
            resDict['lightspanfile'] = 'lightspan_' + build + '.tar'
        except Exception as inst:
            db_print("build check exception :%s!" % str(inst))
            return resDict
        return resDict

        
    def _parseBuildServer(self,build_server):
        resDict = {}
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
            resDict['protocol'] = protocol
            resDict['build_ip'] = build_ip
            resDict['build_dir'] = build_dir
            resDict['build_user'] = build_user
            resDict['build_pazwd'] = build_pazwd
        except Exception as inst:
            db_print('aprser build server with exception:%s' %inst)     
            return resDict   
        return resDict  
    
    def _parseAgentInfo(self,build_agent):
        tmpList = build_agent.split(":")
        resDict = {}
        resDict['agent_ip'] = tmpList[0]

        try:
            if len(tmpList) == 1:
                resDict['agent_port'] = '22'
                resDict['agent_user'] = 'atxuser'
                resDict['agent_password'] = 'alcatel01'
                resDict['agent_dir'] = '/tftpboot'
            else:
                resDict['agent_port'] = tmpList[1]
                resDict['agent_user'] = tmpList[2]
                resDict['agent_password'] = tmpList[3]  
                resDict['agent_dir'] = tmpList[4] 
        except Exception as inst:
            db_print('parese build agent with exception:%s' %inst)        
        return resDict

    def setOswpPrefix(self,timestamp):
        self.oswpIndexPrefix = timestamp   

    def getOswpPrefix(self):
        return self.oswpIndexPrefix
     


class DUT(object):
    #reset duration of 400s
    def __init__(self,args):
        self.conType = args.setdefault('connectType','TELNET')
        if self.conType == 'TELNET':
            self.dutPort = args.setdefault('dutPort','23')
        elif self.conType == 'SSH':
            self.dutPort = args.setdefault('dutPort','22')
        self.dutIP = args.setdefault('DutOamIP','')
        self.craftIP = args.setdefault('CraftIP','')
        self.craftPort = args.setdefault('CraftPort','')
        self.gateway = args.setdefault('OamIpGateway','')
        self.oamPort = args.setdefault('OamPort','')
        self.oamPrefix = args.setdefault('OamIpPrefix','')
        self.oamType = args.setdefault('oam_type','')
        self.oamIntf = None
        self.craftIntf = None
        self.redund = args.setdefault('redund',False)
        self.isAlive = None
        self.description = args.setdefault('Description','')
        self.ltCheckList = args.setdefault('ltCheckList',None)
        if self.description=='SUB':
            self.order=0
        else:
            self.order=1
        self.upgrade = args.setdefault('Upgrade',True)
        self.site = args.setdefault('site','')
    
    @classmethod    
    def dutPreCheck(self,instance_list,**params):
        retrytimes = params.setdefault('retrytimes',1)
        for dutInstance in instance_list:
            dutUp = False
            for i in range(0,retrytimes):
                dut_ip =  dutInstance.dutIP
                if not dutInstance.pingIp(dut_ip):
                    dutUp = False
                    break
                else:
                    dutUp = True
            if not dutUp:
                #db_print("%s IP is unreachable" %dut_ip)
                db_print("IP is unreachable",'send',dut_ip)
                return False
        return True
            
    @classmethod
    def dutPostActCheck(cls,instance_list,**params):
        resDict = {}
        resDict['res'] = True
        ltcheck = params.setdefault('ltcheck','False')
        ltswcheck = params.setdefault('ltswcheck','False')
        buildInstance = params.setdefault('buildInstance',None)
        build = buildInstance.buildID
        for dutInstance in instance_list:
            dut_ip =  dutInstance.dutIP
            if not dutInstance.pingIp(dut_ip):
                #db_print("dutInstance.dutIP is unreachable:%s" %dutInstance.dutIP)
                db_print("dutInstance.dutIP is unreachable",'send',dutInstance.dutIP)
                return resDict
            
            if not dutInstance.checkandclearOSWP(build):
                res={}
                resDict['res'] = False
                res['errCode'] = '505'
                resDict['errors']=[]
                resDict['errors'].append(res)
                return resDict
        if ltcheck:
            dutThreadList = []
            for dutInstance in instance_list:
                dutThread = myThread(dutInstance.check_lt_status,args=(),kwargs=params)
                dutThreadList.append(dutThread)
            for DutThread in dutThreadList:
                DutThread.start()
            for DutThread in dutThreadList:
                DutThread.join()
            
            resDict = {}
            resDict['res'] = True
            resDict['errors']=[]
            for dutThread in dutThreadList:
                result = dutThread.get_result()
                if not result.get('res','False'):
                    resDict['res'] = False
                res={}
                res=copy.deepcopy(result)
                resDict['errors'].append(res) 
            if not resDict['res']:
                return resDict
        if ltswcheck:
            dutThreadList = []

            for dutInstance in instance_list:
                dutThread = myThread(dutInstance.check_lt_sw,args=(),kwargs=params)
                dutThreadList.append(dutThread)
            for DutThread in dutThreadList:
                DutThread.start()
            for DutThread in dutThreadList:
                DutThread.join()

            resDict = {}
            resDict['res'] = True
            resDict['errors']=[]
            for dutThread in dutThreadList:
                result = dutThread.get_result()
                if not result.get('res','False'):
                    resDict['res'] = False
                res={}
                res=copy.deepcopy(result)
                resDict['errors'].append(res)
            if not resDict['res']:
                return resDict
        
        return resDict      
          
    @classmethod
    def prepareOSWP(cls,instance_list,**params):  
        db_print("prepare oswp")

        dutThreadDict = {}
        for dutInstance in instance_list:
            if not 'snmpDUT' in dutThreadDict and isinstance(dutInstance,snmpDUT):
                dutThread = myThread(snmpDUT.prepareOSWP,kwargs=params) 
                dutThreadDict['snmpDUT'] = dutThread
            elif not 'moswaDUT' in dutThreadDict and isinstance(dutInstance,moswaDUT):
                dutThread = myThread(moswaDUT.prepareOSWP,kwargs=params) 
                dutThreadDict['moswaDUT'] = dutThread
            elif not 'nbn4fDUT' in dutThreadDict and isinstance(dutInstance,nbn4fDUT):
                dutThread = myThread(nbn4fDUT.prepareOSWP,kwargs=params)
                dutThreadDict['nbn4fDUT'] = dutThread
            else:
                continue
        for dutType in dutThreadDict:
            dutThreadDict[dutType].start()
        for dutType in dutThreadDict:
            dutThreadDict[dutType].join()
        resDict = {}
        resDict['res'] = True
        resDict['errors']=[]
        for dutType in dutThreadDict:
            result = dutThreadDict[dutType].get_result()
            if not result.get('res','False'):
                resDict['res'] = False
            res={}
            res=copy.deepcopy(result)
            resDict['errors'].append(res) 
        return resDict

    @classmethod
    def adjustLinkSpeedParallel(cls,instance_list,**params):
        db_print("adjust link speed first before download")
        dutThreadList = []
        for dutInstance in instance_list:
            dutThread = myThread(dutInstance.adjust_link_speed,args=(),kwargs=params)
            dutThreadList.append(dutThread)
        for DutThread in dutThreadList:
            DutThread.start()
        for DutThread in dutThreadList:
            DutThread.join()
        resDict = {}
        resDict['res'] = True
        resDict['errors']=[]
        for dutThread in dutThreadList:
            result = dutThread.get_result()
            if not result.get('res','False'):
                resDict['res'] = False
            res={}
            res=copy.deepcopy(result)
            resDict['errors'].append(res)
        return resDict
    
    @classmethod
    def downloadParallel(cls,instance_list,**params):
        dutThreadList = []
        resDict = cls.adjustLinkSpeedParallel(instance_list)
        if not resDict['res']:
            return resDict
        linuxHost = params.setdefault('cmdLocation',None)
        resDict = cls.configDUT(instance_list,cmdType='pre_oswp',action='add',cmdLocation=linuxHost)
        #if not resDict['res']:
        #    return resDict        
        dutThreadList = []
        for dutInstance in instance_list:
            dutThread = myThread(dutInstance.downloadOSWP,args=(),kwargs=params)
            dutThreadList.append(dutThread)
        for DutThread in dutThreadList:
            DutThread.start()
        for DutThread in dutThreadList:
            DutThread.join()
        resDict = {}
        resDict['res'] = True
        resDict['errors']=[]
        for dutThread in dutThreadList:
            result = dutThread.get_result()
            if not result.get('res','False'):
                resDict['res'] = False
            res={}
            res=copy.deepcopy(result)
            resDict['errors'].append(res) 
        return resDict
            
    @classmethod
    def activateParallel(cls,instance_list,**params):
        db_print("activate in parallel:")
        dutThreadList = []
        db_print("handler dut in the 1st order like HUB")
        for dutInstance in instance_list:
            if dutInstance.order ==0:
                dutThread = myThread(dutInstance.activateOSWP,args=(),kwargs=params)
                dutThreadList.append(dutThread)
        for DutThread in dutThreadList:
            DutThread.start()
        for DutThread in dutThreadList:
            DutThread.join()
        resDict = {}
        resDict['res'] = True
        resDict['errors']=[]
        for dutThread in dutThreadList:
            result = dutThread.get_result()
            if not result.get('res','False'):
                resDict['res'] = False
            res={}
            res=copy.deepcopy(result)
            resDict['errors'].append(res)   
        if not resDict['res']:
            db_print("SUB activating failed,skip HUB")
            return resDict
        db_print("handler dut in the normal order like quad setup or HUB")
        dutThreadList = []
        for dutInstance in instance_list:
            if not dutInstance.order ==0:
                dutThread = myThread(dutInstance.activateOSWP,args=(),kwargs=params)
                dutThreadList.append(dutThread)
        for DutThread in dutThreadList:
            DutThread.start()
        for DutThread in dutThreadList:
            DutThread.join()
        resDict = {}
        resDict['res'] = True
        resDict['errors']=[]
        for dutThread in dutThreadList:
            result = dutThread.get_result()
            if not result.get('res','False'):
                resDict['res'] = False
            res={}
            res=copy.deepcopy(result)
            resDict['errors'].append(res) 
        return resDict
    
    @classmethod
    def cleanDBParallel(cls,instance_list,**params):
        db_print("activate in parallel:")
        dutThreadList = []
        db_print("handler dut in the 1st order like SUB")
        for dutInstance in instance_list:
            if dutInstance.order ==0:
                dutThread = myThread(dutInstance.cleanDB,args=(),kwargs=params)
                dutThreadList.append(dutThread)
        for DutThread in dutThreadList:
            DutThread.start()
        for DutThread in dutThreadList:
            DutThread.join()
        resDict = {}
        resDict['res'] = True
        resDict['errors']=[]
        for dutThread in dutThreadList:
            result = dutThread.get_result()
            if not result.get('res','False'):
                resDict['res'] = False
            res={}
            res=copy.deepcopy(result)
            resDict['errors'].append(res)   
        if not resDict['res']:
            db_print("SUB activating failed,skip HUB")
            return resDict
        db_print("handler dut in the normal order like quad setup or HUB")
        dutThreadList = []
        for dutInstance in instance_list:
            if not dutInstance.order ==0:
                dutThread = myThread(dutInstance.cleanDB,args=(),kwargs=params)
                dutThreadList.append(dutThread)
        for DutThread in dutThreadList:
            DutThread.start()
        for DutThread in dutThreadList:
            DutThread.join()
        resDict = {}
        resDict['res'] = True
        resDict['errors']=[]
        for dutThread in dutThreadList:
            result = dutThread.get_result()
            if not result.get('res','False'):
                resDict['res'] = False
            res={}
            res=copy.deepcopy(result)
            resDict['errors'].append(res) 
        return resDict
    
    @classmethod
    def initializeParallel(cls,instance_list,**params):
        resDict = {}
        resDict['res'] = True
        resDict['errors']=[]      
        redund = params.setdefault('redund',False)
        #db_print("put intialization script to tftp server")
        #if not cls.init_config(server_ip, craftIp, craftPort, oam_ip, initCommands, extraCommands, product, oam_type, redund, toolOnly):
        #    db_print("failure in putting initialization script to tftp server")
        #    resDict['res'] = True
        #    resDict['errors']=[]
        #    return resDict
        db_print("initialize in parallel:")
        dutThreadList = []
        db_print("handler dut in the 1st order like SUB")
        for dutInstance in instance_list:
            if dutInstance.order ==0:
                dutThread = myThread(dutInstance.initializeDUT,args=(),kwargs=params)
                dutThreadList.append(dutThread)
        for DutThread in dutThreadList:
            DutThread.start()
        for DutThread in dutThreadList:
            DutThread.join()
        for dutThread in dutThreadList:
            result = dutThread.get_result()
            if not result.get('res','False'):
                resDict['res'] = False
            res={}
            res=copy.deepcopy(result)
            resDict['errors'].append(res)   

        if not resDict['res']:
            db_print("SUB activating failed,skip HUB")
            return resDict
        db_print("handler dut in the normal order like quad setup or HUB")
        dutThreadList = []
        for dutInstance in instance_list:
            if not dutInstance.order ==0:
                dutThread = myThread(dutInstance.initializeDUT,args=(),kwargs=params)
                dutThreadList.append(dutThread)
        for DutThread in dutThreadList:
            DutThread.start()
        for DutThread in dutThreadList:
            DutThread.join()
        resDict = {}
        resDict['res'] = True
        resDict['errors']=[]
        for dutThread in dutThreadList:
            result = dutThread.get_result()
            if not result.get('res','False'):
                resDict['res'] = False
            res={}
            res=copy.deepcopy(result)
            resDict['errors'].append(res) 
        if not resDict['res']:
            return resDict
        print('init normal')

        #Check NT synchronize in Redund Setups in platform initialization
        if redund:        
            dutThreadList = []
            for dutInstance in instance_list:
                if not dutInstance.order ==0:
                    dutThread = myThread(dutInstance.checkDiskSyncForRedundancy,args=(),kwargs=params)
                    dutThreadList.append(dutThread)
            for DutThread in dutThreadList:
                DutThread.start()
            for DutThread in dutThreadList:
                DutThread.join()

            for dutThread in dutThreadList:
                result = dutThread.get_result()
                if not result.get('res','False'):
                    resDict['res'] = False
                res={}
                res=copy.deepcopy(result)
                resDict['errors'].append(res) 
        print('diskcheck')
        return resDict
    
    @classmethod    
    def dutPlanLTParallel(self,instance_list,**params):
        resDict = {}
        resDict['res'] = True
        resDict['errors']=[]
        dutThreadList = []
        for dutInstance in instance_list:
            dutThread = myThread(dutInstance.plan_lt_board,args=(),kwargs=params)
            dutThreadList.append(dutThread)
        for DutThread in dutThreadList:
            DutThread.start()
        for DutThread in dutThreadList:
            DutThread.join()
        resDict = {}
        resDict['res'] = True
        resDict['errors']=[]
        for dutThread in dutThreadList:
            result = dutThread.get_result()
            if not result.get('res','False'):
                resDict['res'] = False
            res={}
            res=copy.deepcopy(result)
            resDict['errors'].append(res)
        return resDict
    
    @classmethod
    def putScript2Remote(cls,**params):
        scriptList = ['initConfigFunc.py','clearConsolePort.py','lt_swcheck.py','com_tnd.py','octopus','oswpUtility.py','urlDaily.py','paxel.py','packagemeUtility.py','sw_update_netconf.py']
        remotepath = '/tmp/.jenkins'
        SCRIPT_PATH=params.setdefault('SCRIPT_PATH','')
        db_print(SCRIPT_PATH)
        privateNetwork = params.setdefault('privateNetwork',False)
        buildInstance = params.setdefault('buildInstance',None)
        serverIp = buildInstance.agentDict['agent_ip']
        serverUser = buildInstance.agentDict['agent_user']
        serverPasswd = buildInstance.agentDict['agent_password']
        serverPort = buildInstance.agentDict['agent_port']
        destDir = buildInstance.destDir
        postfix = re.sub('^.*tftpboot\/?','',destDir)
        product = params.setdefault('product','')
        if product == 'NBN-4F':
            scriptList = ['urlDaily.py','paxel.py','sw_update_nbn4f.py']
        if privateNetwork:
            #scriptList.append('retrieveLatestBuild.py')
            scriptList.append('urlNetconf.py')
            scriptList.append('sshClient.py')
        try:
            cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p%s %s@%s 'mkdir -p /tmp/.jenkins'" %(serverPasswd,serverPort,serverUser,serverIp)
            #db_print(cmd)
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        except Exception as inst:
            db_print("mkdir in remote machine fail with :%s" %inst)    
            return False
        for aScript in scriptList:
            try:
                localscript = os.path.join(SCRIPT_PATH,aScript)
                remotescript = os.path.join(remotepath,aScript)
                cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p%s %s@%s 'cksum %s'" %(serverPasswd,serverPort,serverUser,serverIp,remotescript)        
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                old_cksum = result.strip().split(' ')[0]
                cmd = 'cksum %s' %localscript
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                new_cksum = result.strip().split(' ')[0]
                if new_cksum and not old_cksum == new_cksum :
                    cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s %s@%s:%s" %(serverPasswd,serverPort,localscript,serverUser,serverIp,remotepath)
                    db_print(cmd,'debug')
                    result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            except Exception as inst:
                db_print("put script %s failed with exception as inst:%s" %(aScript,inst))
                return False
        
        if privateNetwork:
            aScript = 'buildUtility.py'
            localscript = os.path.join(SCRIPT_PATH,aScript)
            remotescript = os.path.join(remotepath,aScript)
            remotescript = postfix2script(remotescript,postfix)
            try:
                cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s %s@%s:%s" %(serverPasswd,serverPort,localscript,serverUser,serverIp,remotescript)
                db_print(cmd,'debug')
                result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            except Exception as inst:
                db_print("put script %s failed with exception as inst:%s" %(aScript,inst))
                return False    
        try:
            cmd = "sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p%s %s@%s 'chmod -R +x %s'" %(serverPasswd,serverPort,serverUser,serverIp,remotepath)
            db_print(cmd,'debug')
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        except Exception as inst:
            db_print("put script failed with exception as inst:%s" %inst)
            return False
        return True
    
    @classmethod
    def configDUT(cls,instance_list,**params):
        for dutInstance in instance_list:
            dutInstance.configDUT(**params)

    @classmethod
    def compareOSWP(cls,instance_list,**params):
        resDict = {}
        resDict['res'] = False
        resDict['errors']=[] 
        for dutInstance in instance_list:
            result = dutInstance.compareOSWP(**params)
            if result.get('res',False):
                resDict['res'] = True
            res={}
            res=copy.deepcopy(result)
            resDict['errors'].append(res)
        return resDict

    @classmethod
    def adjust_link_speed(self):
        return True
    
    def plan_lt_board(self,**params):
        return {'res':True}

    def checkDiskSyncForRedundancy(self,**params):
        return True
    
    def checkandclearOSWP(self,build):
        return True
    
    def check_lt_status(self,**params):
        return {'res':True}
    
    def check_lt_sw(self,**params):
        return {'res':True}   
    
class moswaDUT(DUT):
    reset_duration = 400
    def __init__(self,args):
        super(moswaDUT,self).__init__(args)
        self.conType = args.setdefault('connectType','SSH')
        self.product = args.setdefault('product','')
        self.dutUser = args.setdefault('dutUser','admin')
        self.dutPassword = args.setdefault('dutOamPassword','admin')
        self.dutDefPassword = 'netconf#123'
        self.oamType = args.setdefault('oam_type','')
        self.redund = args.setdefault('redund','')
        self.MAX_PING_TRY = 6
        if self.redund or self.oamType == 'FANT-H':
            self.MAX_PING_TRY = 12
        self.dutIP = args.setdefault('DutOamIP','')
        self.craftIp = args.setdefault('CraftIP','')
        self.craftPort = args.setdefault('CraftPort','')
        self.ltCheckList = args.setdefault('ltCheckList',None)
        self.MOSWA_OSWP_NAME = ''
        self.MOSWA_OSWP_URL = ''
        self.nt_type = args.setdefault('indexDesc',MOSWA_PRODUCT_MAP[self.product]['indexDesc'])
        self.transMode = args.setdefault('transMode',MOSWA_PRODUCT_MAP[self.product]['transMode'])
        self.db_port = args.setdefault('dutTracePort',MOSWA_PRODUCT_MAP[self.product]['dutTracePort'])
        self.dutPort = args.setdefault('dutNetconfPort',MOSWA_PRODUCT_MAP[self.product]['dutNetconfPort'])
        #master_board is oam_type
        self.master_board = args.setdefault('oam_type','').lower()
        #LT_Dict is a dictionary
        self.lt_boards=args.setdefault('LT_Dict',None)
        self.moswa_list = []


    @classmethod
    def prepareOSWP(cls,**params):
        #db_print(str(params))
        buildInstance = params.setdefault('buildInstance',None)
        moswaDict = buildInstance.moswaDict
        ver = buildInstance.buildID
        buildip = buildInstance.buildSource
        serverIp = buildInstance.agentDict['agent_ip']
        serverUser = buildInstance.agentDict['agent_user']
        serverPasswd = buildInstance.agentDict['agent_password']
        serverPort = buildInstance.agentDict['agent_port']
        buildDict = params.setdefault('buildDict',None)
        destDir = buildInstance.destDir
        buildRelease=buildInstance.buildRelease
        #for /tftpboot ,it is ''
        #for lis build, it is /tftpboot/135.251.194.30_Apr26145113

        postfix = re.sub('^.*tftpboot\/?','',destDir)
        build_type = buildInstance.buildType
        extraTar = params.setdefault('extraTar',False)
        loadinfo = params.setdefault('loadinfo','noload')
        jksbuildID = params.setdefault('JKS_BuildID','')
        jksbuildIDNew= params.setdefault('JKS_BuildIDNew','')
        hostFlag= params.setdefault('hostFlag','')
        t0 = time.time()
        old_ver = ver
        result = True
        retDict = {}
        retDict['res'] = True
        latest_ver = jksbuildIDNew
        remotescript = '/tmp/.jenkins/oswpUtility.py'
        #remotescript = postfix2script(remotescript,postfix)
        if extraTar:
            db_print("Download extra tar")
            cmd = "/usr/bin/python %s --action prepareOSWP --build %s --serverip %s --Host '%s'" %(remotescript,ver,serverIp,buildip)
            cmd = cmd + ' --extraTar lightspan_%s.extra.tar --destDir %s' %(ver,destDir)
            ##LIS build check
            if build_type == 'LIS':
                cmd = cmd + ' --build_type %s' %build_type
            cmd1=str(cmd)
            try:
                print(cmd1)
                tmpRes1 = ssh2(serverIp, serverUser,serverPasswd,cmd1,'check')
                print tmpRes1
            except Exception as inst:
                db_print("Download extra tar failed with %s" %inst)
                pass
        if loadinfo == 'load':
            if not moswaDict:
                db_print("no moswa boards defined,skip preparation of build")
                t1 = time.time()
                return retDict

            db_print('MOSWA PREP')
            #db_print(str(moswaDict))

            #for moswa, in case build server changed by latest, need do below:
            if jksbuildID == 'latest':
                try:
                    tmpBuildInfo = _parse_build_server(buildip)
                #(protocol,build_ip,build_dir,build_user,build_pazwd)
                    moswaDict['build_ip'] = tmpBuildInfo[1]
                    moswaDict['build_dir'] = tmpBuildInfo[2]
                    moswaDict['build_ftp_dir'] = tmpBuildInfo[2]
                    db_print("change build server for latest build in moswa:%s" %str(moswaDict) )
                except Exception as inst:
                    db_print("moswa latest build,parse changed build info with exception:%s" %inst)


            try:
                if moswaDict.get('trans_mode','').lower() == 'http':
                    if '135.251.206.149' in moswaDict.get('update_ip',''):
                        db_print("change port to be 8090 for shanghai backup build server")
                        moswaDict['server_port'] = '8090'
                db_print("generate moswa instance")
                db_print("moswaDict:")
                db_print(str(moswaDict))
                lead_board = Smartlab_Instance(moswaDict)
                db_print("build id handling")
                lead_board.build_id_guess()
                db_print("untar")
                lead_board.build_to_update()
                db_print("prepare index")
                lead_board.gen_index_url()
            #cls.MOSWA_OSWP_NAME = lead_board.NAME
            #cls.MOSWA_OSWP_URL = lead_board.URL
                db_print('MOSWA OSWP NAME: %s' % lead_board.NAME)
                db_print('MOSWA OSWP URL: %s' % lead_board.URL)
                cls.Set_MOSWA_NAME(moswa_name=lead_board.NAME)
                cls.Set_MOSWA_URL(moswa_oswp_url=lead_board.URL)
            except Exception as inst:
                db_print("moswa prepare oswp with exception as inst:%s" %inst)
                result = False
        t1 = time.time()
        #501 means prepare oswp failure
        if not result:
            retDict['res'] = False
            retDict['error'] = '501'
        return retDict

    def setMoswaList(self,**params):
        buildInstance = params.setdefault('buildInstance',None)
        logLocation = params.setdefault('logLocation',None)
        moswa_dict=copy.deepcopy(buildInstance.moswaDict)
        moswa_dict['dut_ip'] = self.dutIP
        if self.dutPort:
            moswa_dict['dut_port'] = self.dutPort
        if self.nt_type:
            moswa_dict['nt_type'] = self.nt_type
        if self.transMode:
            moswa_dict['trans_mode'] =  self.transMode
        if self.db_port:
            moswa_dict['db_port'] = self.db_port
        if logLocation:
            moswa_dict['ip']=logLocation['linuxIP']
            moswa_dict['port']=logLocation['linuxPORT']
            moswa_dict['user']=logLocation['linuxUser']
            moswa_dict['password']=logLocation['linuxPasswd']
            moswa_dict['dir']='/tmp'            
        moswa_list = []

        if not self.dutPort == MOSWA_NT_NETCONF_PORT:
        #for old sdfx or nc dpu  or nc olt, do not set slot_id
            moswa_list.append(moswa_dict)
        else:
            planLT = False
            board = self.master_board
            if board:
                boardType = 'NT'
                moswa_dict['board_type'] = board
                moswa_dict['role'] = 'NT'
                moswa_list.append(moswa_dict)
                planLT = True
            if self.lt_boards:
                for lt in self.lt_boards:
                    ltMoswaDict = copy.deepcopy(moswa_dict)
                    ltMoswaDict['board_type'] = None
                    ltMoswaDict['board_type'] = str(self.lt_boards[lt])
                    ltMoswaDict['role'] = 'LT'
                    ltMoswaDict['slot_id'] = str(lt)
                    moswa_list.append(ltMoswaDict)
        self.moswa_list = moswa_list
    def downloadOSWP(self,**params):
        moswa_list = self.moswa_list
        moswa_name = moswaDUT.Get_MOSWA_NAME()
        moswa_url = moswaDUT.Get_MOSWA_URL()   
        SWMgmt=params.setdefault('SWMgmt',False) 
        t0 = time.time()
        result = True
        errorCode = '502'
        retDict= {}
        retDict['res'] = result
        try:
            if not moswa_list:
                db_print("no moswa boards defined,skip downloading of build")
                t1 = time.time()
                return retDict
            board_arg_list = copy.deepcopy(moswa_list)
            download_list = []
            for moswa_dict in board_arg_list:
                moswa_dict.pop('role','SINGLE')
                moswa_board = Smartlab_Instance(moswa_dict)
                moswa_board.NAME = moswa_name
                moswa_board.URL = moswa_url
                db_print("get active name")
                active_name = moswa_board._get_active_name(getlist=moswa_board.check_state())
                db_print("get active version")
                active_version = moswa_board._get_active_name(getlist=moswa_board.check_state(),out_item='version')
                if SWMgmt:
                    #set download time = 0 if in-active build == load_build, since it causes dashboard time is not accurate
                    in_active_version = moswa_board._get_active_name(getlist=moswa_board.check_state(),in_val='false',out_item='version')
                    db_print("get current in-active version:%s"%in_active_version)
                    if in_active_version and moswa_board.NAME.endswith(in_active_version):
                        db_print("cancel record SWMgmt metrics since in-active build == load_build")
                        SWMgmt = False

                if not (moswa_board.NAME == active_name or moswa_board.NAME.endswith(active_version)):
                    if SWMgmt:
                        moswa_board.set_board_name()
                    download_list.append(moswa_board)
            db_print("boards involved in downloads:%s" %str(download_list),'send',self.dutIP)
            if not download_list:
                db_print("current image version already existing in DUT,skip",'send',self.dutIP)
                result = True
                return retDict
            else:
                db_print("download build parallel")
                Smartlab_Instance.board_event_loop('download_build_parallel',download_list)
                if SWMgmt:
                    db_print('buildUtility->downloadOSWP deal with moswa_upgrade.json')
                    rec_time = get_event_time(download_list)
                    if rec_time:
                        db_print(str(rec_time))
                        job_name = os.environ['JOB_NAME']
                        workspace=os.path.join('/var/jenkins_home/workspace',job_name)
                        with open(os.path.join(workspace,'moswa_upgrade.json'),'w+') as fin:
                            json.dump(rec_time,fin)
                    else:
                        db_print('get_event_time return empty!')
        except Exception as inst:
            db_print("moswa download with exception:%s" %inst)
            result = False
            retDict['res'] = result
            retDict['error'] = errorCode
        return retDict

    def activateOSWP(self,**params):
    #def activateOSWP(shelfIp,oswp,product,cleanDB=False,toolOnly = False,moswa_list=[],password='isamcli!',mode='default',connectType='TELNET'):
        moswa_list = self.moswa_list
        moswa_name = moswaDUT.Get_MOSWA_NAME()
        moswa_url = moswaDUT.Get_MOSWA_URL()
        db_print(str(params))    
        cleanDB = params.setdefault('defaultDB',False)
        SWMgmt=params.setdefault('SWMgmt',False)
        result = True
        errorCode = '505'
        if cleanDB == 'true':
            cleanDB = True 
        if cleanDB == 'false':
            cleanDB = False
        db_print('cleanDB:%s' %cleanDB)
        t0 = time.time()

        retDict= {}
        retDict['res'] = result
        if not moswa_list:
            result = True
            db_print("no moswa boards defined,skip activation of build")
            return retDict
        
        board_arg_list = copy.deepcopy(moswa_list)
        if self.product in ['NCDPU','SDOLT']:
            try:
                moswa_dict = board_arg_list[0]
                moswa_dict.pop('role','SINGLE')
                db_print("generate moswa instance")
                moswa_board = Smartlab_Instance(moswa_dict)
                moswa_board.NAME = moswa_name
                moswa_board.URL = moswa_url
                db_print("target name:%s" %moswa_board.NAME)
                db_print("target url:%s" %moswa_board.URL)  
                db_print("get current active name")
                active_name = moswa_board._get_active_name(getlist=moswa_board.check_state())
                db_print(active_name)
                db_print("get current active version")
                active_version = moswa_board._get_active_name(getlist=moswa_board.check_state(),out_item='version')
                db_print(active_version)
                if not (moswa_board.NAME == active_name or moswa_board.NAME.endswith(active_version)):
                    db_print('open_debug_and_cli_access before activation')
                    moswa_board.open_debug_and_cli_access()
                    if SWMgmt:
                        moswa_board.set_board_name()
                    if self.product == 'SDOLT':
                        db_print("set reboot flag")
                        moswa_board.set_reboot_flag(timeout=20)
                    db_print("active build")
                    moswa_board.active_build()
                    db_print("commit build")
                    moswa_board.commit_build(commit_timeout=120)
                    db_print('open_debug_and_cli_access after activation')
                    moswa_board.open_debug_and_cli_access()
                    #db_print("clean env")
                    #moswa_board.clean_env()
                elif cleanDB:
                    db_print('open_debug_and_cli_access before activation')
                    moswa_board.open_debug_and_cli_access()
                    db_print("clean db with reset")
                    moswa_board.clean_db_with_reset_build()
                    db_print('open_debug_and_cli_access after activation')
                    moswa_board.open_debug_and_cli_access()
                if SWMgmt:
                    db_print("get event time")
                    rec_time = get_event_time([moswa_board])
            except Exception as inst:
                db_print("activate moswa with exception:%s" %inst)
                result = False
        else:
            nt_active_list = []
            nt_keep_list = []
            lt_active_list = []
            lt_keep_list = []
            #commit_timeout_lt = 30
            try:
                loop_mode = 'abort'
                for moswa_dict in board_arg_list:
                    board_role = moswa_dict.pop('role','SINGLE')
                    db_print("generate moswa instance")
                    moswa_board = Smartlab_Instance(moswa_dict)
                    moswa_board.NAME = moswa_name
                    moswa_board.URL = moswa_url
                    db_print("target name:%s" %moswa_board.NAME)
                    db_print("target url:%s" %moswa_board.URL)         
                    db_print("get current active name:")
                    active_name = moswa_board._get_active_name(getlist=moswa_board.check_state())
                    db_print(active_name)
                    db_print("get current active version:")
                    active_version = moswa_board._get_active_name(getlist=moswa_board.check_state(),out_item='version')
                    db_print(active_version)
                    db_print("board_role:%s" %board_role)
                    #if moswa_dict.get('board_type','').strip() in OLD_MOSWA_LT_LIST:
                    #    commit_timeout_lt = 180
                    if SWMgmt:
                        moswa_board.set_board_name()
                    if board_role == 'NT':
                        nt_keep_list.append(moswa_board)
                        if not (moswa_board.NAME == active_name or moswa_board.NAME.endswith(active_version)):
                            nt_active_list.append(moswa_board)
                        db_print("open_debug_and_cli_access before activation")
                        moswa_board.open_debug_and_cli_access()
                        db_print("set reboot flag")
                        moswa_board.set_reboot_flag(timeout=40)
                    else:
                        lt_keep_list.append(moswa_board)
                        if not (moswa_board.NAME == active_name or moswa_board.NAME.endswith(active_version)):
                            lt_active_list.append(moswa_board)
                            db_print("open_debug_and_cli_access before activation for LT")
                            moswa_board.open_debug_and_cli_access()
            except Exception as inst:
                db_print("moswa get active name with exception:%s" %inst)
                result = False
            if result:
                db_print("lt boards involved in activation:%s" %str(lt_active_list),'send',self.dutIP)
                db_print("nt boards involved in activation:%s" %str(nt_active_list),'send',self.dutIP)
            try:
                if lt_active_list:
                    Smartlab_Instance.board_event_loop('active_build_parallel',lt_active_list,loop_mode=loop_mode)
                for moswa_board in lt_active_list:
                    db_print("open_debug_and_cli_access after activation for LT")
                    moswa_board.open_debug_and_cli_access()
            except Exception as inst:
                db_print("activate moswa lt with exception:%s" %inst)
                result = False
            if nt_active_list:
                try:
                    for nt_upd in nt_active_list:
                        nt_upd.active_build()
                        db_print('open_debug_and_cli_access after activation')
                        nt_upd.open_debug_and_cli_access()
                except Exception as inst:
                    db_print("activate moswa nt with exception:%s" %inst)
                    result = False
                try:
                    for lt_plan in lt_keep_list:
                        nt_upd.plan_sub_board(lt_plan.plan_rpc)
                except Exception as inst:
                    db_print("plan moswa lt with exception:%s" %inst)
                    result = False
            if not result:
                retDict['res'] = result
                retDict['error'] = errorCode
                return retDict
            commit_timeout=30
            if lt_active_list:
                try:
                    #Smartlab_Instance.board_event_loop('commit_build_parallel',lt_active_list,loop_mode=loop_mode,commit_timeout=commit_timeout_lt) 
                    Smartlab_Instance.board_event_loop('commit_build_parallel',lt_active_list,loop_mode=loop_mode,commit_timeout=180) 
                except Exception as inst:
                    db_print("commit moswa lt with exception:%s" %inst)
                    result = False
            if self.redund:
                commit_timeout=60
                db_print("redun sdfx,put 60 as timeout")
            if nt_active_list:
                try:
                    Smartlab_Instance.board_event_loop('commit_build_parallel',nt_active_list,loop_mode=loop_mode,commit_timeout=commit_timeout)
                except Exception as inst:
                    db_print("commit moswa nt with exception:%s" %inst)
                    result = False
            #try:
            #    for moswa_board in nt_active_list + lt_keep_list:
            #        moswa_board.clean_env()
            #except Exception as inst:
            #    db_print("clean env with exception:%s" %inst)
            #    result = False
            loop_mode = 'continue'
            if not nt_active_list + lt_active_list and cleanDB:
                db_print("no nt + lt need upgrade,but defaultDb set True")
                if lt_keep_list:
                    try:
                        for moswa_board in lt_keep_list:
                            db_print("open_debug_and_cli_access before activation for LT")
                            moswa_board.open_debug_and_cli_access()
                        Smartlab_Instance.board_event_loop('clean_db_with_reset_parallel',lt_keep_list,loop_mode=loop_mode)
                        for moswa_board in lt_keep_list:
                            db_print("open_debug_and_cli_access after activation for LT")
                            moswa_board.open_debug_and_cli_access()
                    #requested by fiber area guys
                    except Exception as inst:
                        db_print("clean_db_with_reset_parallel:%s" %inst)
                        result = False
                
                try:
                    for nt_upd in nt_keep_list:
                        db_print('open_debug_and_cli_access after activation')
                        nt_upd.open_debug_and_cli_access()
                        db_print('clean_db_with_reset_build')
                        nt_upd.clean_db_with_reset_build()
                        db_print('open_debug_and_cli_access after activation')
                        nt_upd.open_debug_and_cli_access()
                except Exception as inst:
                    db_print("clean db with reset moswa nt with exception:%s" %inst)
                    result = False
                try:
                    if nt_keep_list:
                        nt_upd=nt_keep_list[0]
                        for lt_plan in lt_keep_list:
                            nt_upd.plan_sub_board(lt_plan.plan_rpc)
                except Exception as inst:
                    db_print("plan moswa lt with exception:%s" %inst)
                    result = False
            if SWMgmt:
                db_print('buildUtility->activateOSWP deal with moswa_upgrade')
                db_print("get event time")
                rec_time = get_event_time(nt_active_list + lt_active_list)
        if SWMgmt:
            if rec_time:
                job_name = os.environ['JOB_NAME']
                workspace=os.path.join('/var/jenkins_home/workspace',job_name)
                db_print('workspace is:%s'%workspace)
                db_print(str(rec_time))
                with open(os.path.join(workspace,'moswa_upgrade.json'),'r') as fin:
                    dwd_rec = json.load(fin)
                    db_print('moswa_upgrade file json load:%s'%dwd_rec)
                    for key in rec_time:
                        if key in dwd_rec:
                            dwd_time = dwd_rec[key].get('Download',0)
                            if dwd_time:
                                rec_time[key]['Download'] = dwd_time
                            else:
                                rec_time = False
                                break
                db_print('rec_time is:%s'%rec_time)
                #not rec time when download time is 0
                if rec_time:
                    with open(os.path.join(workspace,'moswa_upgrade.json'),'w+') as fin:
                        json.dump(rec_time,fin)
            else:
                db_print('get_event_time return empty!')
        retDict['res'] = result
        if not result:
            retDict['error'] = errorCode
        return retDict
    
    def plan_lt_board(self,**params):
        retDict= {}
        retDict['res'] = True
        try:
            nt_list = [moswa_dict for moswa_dict in self.moswa_list if moswa_dict.get('role', 'SINGLE') == 'NT']
            if not len(nt_list):
                return retDict

            nt_ins = Smartlab_Instance(nt_list[0])
            lt_lists = [moswa_dict for moswa_dict in self.moswa_list if moswa_dict.get('role','SINGLE') != 'NT']
            for lt in lt_lists:
                if not nt_ins.plan_sub_board(Smartlab_Instance(lt).plan_rpc,check_time=600):
                    retDict['res'] = False
                    return retDict
            return retDict
        except Exception as inst:
            db_print("fail to plan_lt_board with exception:%s" % inst)
        retDict['res'] = False
        return retDict

    def cleanDB(self,**params):
        moswa_list = self.moswa_list
        moswa_name = moswaDUT.Get_MOSWA_NAME()
        moswa_url = moswaDUT.Get_MOSWA_URL()
        result = True
        errorCode = '505'
        #cleanDB = True if cleanDB == 'true' else False
        t0 = time.time()

        retDict= {}
        retDict['res'] = result
        if not moswa_list:
            result = True
            db_print("no moswa boards defined,skip activation of build")
            return retDict
        db_print("clean db for moswa product and restart",'send',self.dutIP)

        board_arg_list = copy.deepcopy(moswa_list)
        if self.product in ['NCDPU','SDOLT']:
            try:
                moswa_dict = board_arg_list[0]
                moswa_dict.pop('role','SINGLE')
                db_print("generate moswa instance")
                moswa_board = Smartlab_Instance(moswa_dict)
                moswa_board.NAME = moswa_name
                moswa_board.URL = moswa_url
                db_print("get active name to create netconf instance")
                active_name = moswa_board._get_active_name(getlist=moswa_board.check_state())
                db_print('open_debug_and_cli_access before activation')
                moswa_board.open_debug_and_cli_access()
                db_print("set reboot flag")
                moswa_board.set_reboot_flag(timeout=20)
                db_print("clean db with reset")
                moswa_board.clean_db_with_reset_build()
                db_print('open_debug_and_cli_access after activation')
                moswa_board.open_debug_and_cli_access()
            except Exception as inst:
                db_print("clean db failed with exception:%s" %inst)
                result = False
        else:
            nt_active_list = []
            lt_keep_list = []
            loop_mode = 'abort'
                    
            for moswa_dict in board_arg_list:
                try:
                    board_role = moswa_dict.pop('role','SINGLE')
                    db_print("generate moswa instance")
                    moswa_board = Smartlab_Instance(moswa_dict)
                    moswa_board.NAME = moswa_name
                    moswa_board.URL = moswa_url
                    db_print("get active name")
                    active_name = moswa_board._get_active_name(getlist=moswa_board.check_state())
                    if board_role == 'NT':
                        nt_active_list.append(moswa_board)
                        db_print('open_debug_and_cli_access before activation')
                        moswa_board.open_debug_and_cli_access()
                        db_print("set reboot flag")
                        moswa_board.set_reboot_flag(timeout=20)
                    else:
                        lt_keep_list.append(moswa_board)
                except Exception as inst:
                    db_print("set reboot flag with exception:%s" %inst)
                    result = False
            if nt_active_list and len(lt_keep_list) >= 2:
                loop_mode = 'continue'
            try:
                for moswa_board in lt_keep_list:
                    db_print("open_debug_and_cli_access before activation for lt")
                    moswa_board.open_debug_and_cli_access()
                Smartlab_Instance.board_event_loop('clean_db_with_reset_parallel',lt_keep_list,loop_mode=loop_mode)
                for moswa_board in lt_keep_list:
                    db_print("open_debug_and_cli_access after activation for lt")
                    moswa_board.open_debug_and_cli_access()
            except Exception as inst:
                db_print("clean db with reset parallel with exception:%s" %inst)
                result = False
            if nt_active_list:
                try:
                    for lead_board in nt_active_list:
                        db_print('clean db for nt')
                        lead_board.clean_db_with_reset_build()
                        db_print('open_debug_and_cli_access after activation')
                        lead_board.open_debug_and_cli_access()
                except Exception as inst:
                    db_print("clean db with reset nt with exception:%s" %inst)
                    result = False
                lead_board = nt_active_list[0]
                try:
                    for lt_plan in lt_keep_list:
                        lead_board.plan_sub_board(lt_plan.plan_rpc)
                except Exception as inst:
                    db_print("plan lt with reset nt with exception:%s" %inst)
                    result = False
        retDict['res'] = result
        if not result:
            db_print("clean db failed")
            retDict['error'] = errorCode
        return retDict

    @classmethod
    def Set_MOSWA_NAME(cls,**params):
       cls.MOSWA_OSWP_NAME=params.get('moswa_name','')

    @classmethod
    def Set_MOSWA_URL(cls,**params):
       cls.MOSWA_OSWP_URL=params.get('moswa_oswp_url','')

    @classmethod
    def Get_MOSWA_NAME(cls):
      if hasattr(cls,'MOSWA_OSWP_NAME') and cls.MOSWA_OSWP_NAME:
          return cls.MOSWA_OSWP_NAME      
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
      cls.MOSWA_OSWP_NAME=moswa_name
      return cls.MOSWA_OSWP_NAME

    @classmethod
    def Get_MOSWA_URL(cls):
      if hasattr(cls,'MOSWA_OSWP_URL') and cls.MOSWA_OSWP_URL:
          return cls.MOSWA_OSWP_URL
      try :
          build_url = os.environ['BUILD_URL']
          build_url = re.sub(r'([\(|\)])',r'\\\1',build_url)
      except Exception as inst:
          db_print('Failed to get LIS  directory:%s' %inst)
          return ''
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
      cls.MOSWA_OSWP_URL=moswa_url
      return cls.MOSWA_OSWP_URL

    def pingIp(self,oam_ip):
        ret = os.system('/bin/ping -c 4 %s 2>&1 >/dev/null' % oam_ip)
        if not ret:
            db_print('%s is reachable' % oam_ip,'send',oam_ip)
            return True
        else:
            db_print('%s is not reachable' % oam_ip,'send',oam_ip)
            return False

    def configDUT(self,**params):
        db_print("Skip configDUT step for MOSWA setups")
        retDict={}
        retDict['res']=True
        return retDict

    def compareOSWP(self,**params):
        db_print("Skip compareOSWP step for MOSWA setups")
        retDict={}
        retDict['res']=False
        return retDict

    def initializeDUT(self,**params):
        action = 'intializeDUT'
        db_print("Skip initialize step for MOSWA setups")
        retDict={}
        retDict['res']=True
        return retDict

    def adjust_link_speed(self):
        db_print("Skip Adjust link speed step for MOSWA setups")
        retDict={}
        retDict['res']=True
        return retDict

    def checkDiskSyncForRedundancy(self,**params):
        db_print("Skip Disk sync check for MOSWA setups")
        retDict={}
        retDict['res']=True
        return retDict


class nbn4fDUT(DUT):
    reset_duration = 400
    def __init__(self,args):
        super(nbn4fDUT,self).__init__(args)
        self.conType = args.setdefault('connectType','TELNET')
        self.product = args.setdefault('product','')
        if self.conType == 'TELNET':
            self.dutPort = args.setdefault('dutPort','23')
        elif self.conType == 'SSH':
            self.dutPort = args.setdefault('dutPort','22')
        self.dutUser = args.setdefault('dutUser','isadmin')
        self.dutPassword = args.setdefault('dutPassword','isamcli!')
        self.dutDefPassword = 'i$@mad-'
        self.oamType = args.setdefault('oam_type','')
        self.redund = args.setdefault('redund','')
        self.MAX_PING_TRY = 6
        if self.redund or self.oamType == 'FANT-H':
            self.MAX_PING_TRY = 12
        self.dutIP = args.setdefault('DutOamIP','')
        self.craftIp = args.setdefault('CraftIP','')
        self.craftPort = args.setdefault('CraftPort','')
        self.ltCheckList = args.setdefault('ltCheckList',None)
        self.target_oswp_slot = ''
        self.active_oswp_slot = ''
        self.target_oswp_index = ''

    @classmethod
    def prepareOSWP(cls,**params):
    #def prepareOSWP(ver,serverip,product,buildip='135.251.206.97',moswa_list=[],toolOnly =False, destDir='/tftpboot',build_type='official',extraTar = False,debug=False):
        print('inside nbn4f')
        #print(str(params))
        buildInstance = params.setdefault('buildInstance',None)
        SCRIPT_PATH=params.setdefault('SCRIPT_PATH','')
        ver = buildInstance.buildID
        buildip = buildInstance.buildSource
        serverip = buildInstance.buildAgent
        destDir = buildInstance.destDir
        #for /tftpboot ,it is ''
        #for lis build, it is /tftpboot/135.251.194.30_Apr26145113
        postfix = re.sub('^.*tftpboot\/?','',destDir)
        build_type = buildInstance.buildType
        jksbuildID = params.setdefault('JKS_BuildID','')
        jksbuildIDNew= params.setdefault('JKS_BuildIDNew','')
        cmdLocation = params.setdefault('cmdLocation','')
        linuxPasswd = cmdLocation['linuxPasswd']
        linuxPORT = cmdLocation['linuxPORT']
        linuxUser = cmdLocation['linuxUser']
        linuxIP = cmdLocation['linuxIP']
        oam_ip = params.setdefault('oam_ip','')
        site = params.setdefault('site','')
        csv = params.setdefault('csv','')
        t0 = time.time()
        old_ver = ver 
        retDict = {}
        retDict['res'] = True
        result = True
        latest_ver = jksbuildIDNew
        buildRelease=buildInstance.buildRelease

        t0 = time.time()
        ret_val = ''
        try:
            db_print('put sw_update_nbn4f.py for NBN_4F to PCTA')
            localscript = SCRIPT_PATH + '/sw_update_nbn4f.py'
            remotepath = '/tmp/.jenkins'
            remotescript = '/tmp/.jenkins/sw_update_nbn4f.py'
            #remotescript = postfix2script(remotescript,postfix)
            '''
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
            '''
            new_build="lightspan-omci_"+ver+".tar"
            if csv:
                cmd_init = 'python -u %s --ip %s --logDirectory %s --build %s --ftpserver %s --Site %s --csv %s' %(remotescript,oam_ip,remotepath,new_build,buildip,site,csv)
            else:
                cmd_init = 'python -u %s --ip %s --logDirectory %s --build %s --ftpserver %s --Site %s' %(remotescript,oam_ip,remotepath,new_build,buildip,site)
            tmp_res=ssh2(linuxIP,linuxUser,linuxPasswd,cmd_init,'check')
            print tmp_res
            if tmp_res.find('Prepare build file successfully') == -1:
                ret_val=False
            else:
                ret_val=True
            t1 = time.time()

        except Exception as inst:
            db_print("Prepare build file failed for NBN_4F setup:%s" %inst)
            ret_val = False
            t1 = time.time()
        retDict['res'] = ret_val
        if not ret_val:
            errorCode = '501'
            retDict['error'] = errorCode
        return retDict
            
            
            
    def initializeDUT(self):
        action = 'intializeDUT'
        db_print("Skip initialize step for NBN_4f setups")
        retDict={}
        retDict['res']=True
        return retDict
        
    def downloadOSWP(self,**params):
        retDict={}
        retDict['res']=True
        db_print("Skip download step for NBN_4f setups")
        return retDict
    
    def activateOSWP(self,**params):
        retDict={}
        retDict['res']=True
        db_print("Skip activation step for NBN_4f setups")
        return retDict
    
    def cleanDB(self,**params):
        retDict={}
        retDict['res']=True
        db_print("Skip cleanDB step for NBN_4f setups")
        return retDict

    def pingIp(self,oam_ip):
        ret = os.system('/bin/ping -c 4 %s 2>&1 >/dev/null' % oam_ip)
        if not ret:
            db_print('%s is reachable' % oam_ip,'send',oam_ip)
            return True
        else:
            db_print('%s is not reachable' % oam_ip,'send',oam_ip)
            return False

    def compareOSWP(cls,**params):
        db_print("Skip compareOSWP step for NBN_4f setups")
        retDict={}
        retDict['res']=False
        return retDict
        
    def configDUT(cls,**params):
        db_print("Skip configDUT step for NBN_4f setups")
        retDict={}
        retDict['res']=True
        return retDict

                        
class snmpDUT(DUT):
    reset_duration = 400
    loginCmd = {'TELNET':'telnet ','SSH':'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null isadmin@'}

    def __init__(self,args):
        super(snmpDUT,self).__init__(args)
        self.conType = args.setdefault('connectType','TELNET')
        self.product = args.setdefault('product','')
        if self.conType == 'TELNET':
            self.dutPort = args.setdefault('dutPort','23')
        elif self.conType == 'SSH':
            self.dutPort = args.setdefault('dutPort','22')
        self.dutUser = args.setdefault('dutUser','isadmin')
        self.dutPassword = args.setdefault('dutPassword','isamcli!')
        self.dutDefPassword = 'i$@mad-'
        self.oamType = args.setdefault('oam_type','')
        self.redund = args.setdefault('redund','')
        self.MAX_PING_TRY = 6
        if self.redund or self.oamType == 'FANT-H':
            self.MAX_PING_TRY = 12
        self.dutIP = args.setdefault('DutOamIP','')
        self.craftIp = args.setdefault('CraftIP','')
        self.craftPort = args.setdefault('CraftPort','')
        self.ltCheckList = args.setdefault('ltCheckList',None)
        self.target_oswp_slot = ''
        self.active_oswp_slot = ''
        self.target_oswp_index = ''    
        self.set_init_commands(args)
        
    def set_init_commands(self,args):
        oam_gw=args.setdefault('OamIpGateway','').strip()
        oam_port=args.setdefault('OamPort','').strip()
        oam_prefix=args.setdefault('OamIpPrefix','').strip()
        oam_ip = self.dutIP
        craftIp = self.craftIp
        craftPort = self.craftPort
        oam_ip_prefix = oam_ip + "/" + oam_prefix

        oam_type = self.oamType
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
        elif oam_type in ['CFNT-B','CFNT-C','CFNT-D']:
            initCommands = [
            "configure system management no default-route",
            "configure system management host-ip-address manual:"+oam_ip_prefix,
            "configure system management default-route "+oam_gw,
            ]
            if oam_type in ['CFNT-D','CFNT-C']:
                initCommands.append("configure system mgnt-vlan-mode outband")
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
        self.initCommands = copy.deepcopy(initCommands)
        
    def set_extra_init_commands(self,**params):
        cmdLocation = params.setdefault('cmdLocation',None)
        workspace = params.setdefault('workspace','/tmp')
        linux_ip=cmdLocation['linuxIP']
        user=cmdLocation['linuxUser']
        passwd=cmdLocation['linuxPasswd']
        port=cmdLocation['linuxPORT']

        old_workspace=workspace
        workspace = re.sub(r'([\(|\)])',r'\\\1',old_workspace)

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
        self.extraInitCommands=copy.deepcopy(lines)
        
    def login(self):
        #if not self.oamIntf or not self._active(self.oamIntf):
        if not self.oamIntf:
            exp = ''
            try:
                exp = pexpect.spawn(loginCmd[self.conType]+self.dutIP)
                exp.timeout = 60
                exp.logfile_read = sys.stdout
                self.oamIntf = exp
            except Exception as inst:
                db_print("spawn login failed with exception:%s" %inst)
                return False
        res = False
        Password2="      "
        exp = self.oamIntf
        if self.conType == "TELNET":
            try:
                #db_print("exp")
                res=exp.expect("login:")
                #db_print("res:%s" %res)
                exp.sendline(self.dutUser)
                exp.expect('password:')
                #db_print("res:%s" %res)
                exp.sendline(self.dutPassword)
            except Exception as inst:
                db_print("spawn login failed with exception:%s" %inst)
                self.logout()
                return False
            try:
                if exp.expect(["#","incorrect"],timeout=10):
                    raise Exception("login failed")
            except:
                db_print('login with default password...','send',self.dutIP)
                exp.sendline(self.dutUser)
                exp.expect('password:')
                exp.sendline(self.dutDefPassword)
                try:
                    if exp.expect(["new password","incorrect"]) != 0:
                        raise Exception("login failed")
                    exp.sendline(self.dutPassword)
                    exp.expect("re-enter")
                    db_print('repeat entering new password!','send',self.dutIP)
                    exp.sendline(self.dutPassword)
                    exp.expect(["#","$"])
                except:
                    db_print('login with password2...','send',self.dutIP)
                    exp.sendline(self.dutUser)
                    exp.expect('password:')
                    exp.sendline(Password2)
                    if exp.expect(["#","Connection closed"]) != 0:
                        res = False
            db_print('login successfully:TELNET','send',self.dutIP)
            res = True
        elif self.conType == "SSH":
            i = exp.expect(['password:', r'\(yes\/no\)',r'Connection refused',pexpect.EOF])
            if i == 0:
                exp.sendline(self.dutPassword)
            elif i == 1:
                exp.sendline("yes")
                ret1 = exp.expect(["password:",pexpect.EOF])
                if ret1 == 0:
                    exp.sendline(self.dutPassword)
                else:
                    pass
            elif i == 2:
                print "Device is not reachable"
            else:
                print "Timeout : Error in SSH connect"
            var= exp.expect(['#',r'Permission denied',pexpect.EOF])
            if var == 0:
                db_print('login successfully:SSH','send',self.dutIP)
                res = True
            elif var == 1:
                exp.sendline(self.dutDefPassword)
                exp.expect("new password:")
                exp.sendline(self.dutPassword)
                exp.expect("re-enter  password:")
                exp.sendline(self.dutPassword)
                exp.expect(["#",pexpect.TIMEOUT])
                db_print('login successfully','send',self.dutIP)
                res = True                   
            else:
                db_print('Login failure','send',self.dutIP)
                res = False
        self.isAlive = res
        return self.isAlive
        
    def logout(self):
        db_print('logout cli')
        self.oamIntf.close()
        del self.oamIntf
        self.oamIntf = None
        
    def Telnet_send(cmd, linecmd = 1):
        global telnetTn
        telnetTn.write(cmd)
        db_print(cmd, "send")
        if linecmd == 1:
            telnetTn.write("\r")

        
    def _get_oswp_index(self,build):
        global loginCmd
        if self.product in ['SDFX','SDOLT','NCDPU']:
            return ''
        db_print('args are:%s:%s:%s' %(build,self.dutIP,self.dutPassword),'send',self.dutIP)
        shelfIp=self.dutIP
        password=self.dutPassword
    #b = build.split('.')
    #i1 = b[0]
    #oswp_version = b[0]
    #i1 = i1[0:2]
    #i2 = b[1]
        
        (oswp_version,i2) = build.split('.')
        i1 = oswp_version[0:2]
        if re.search('p',i2):
            i2=i2.split('p')[0]
        i2 = i2[-3:]
        oswpIndex = 'L6GPAA' + i1 + '.' + i2
        oswpIndex1 = 'l6gpaa' + i1 + '.' + i2
        oswpIndex2 = 'L6GPAA' + i1 + '.' + i2
        oswpIndex3 = 'L6GPAB' + i1 + '.' + i2
        oswpIndex4 = 'L6GPAC' + i1 + '.' + i2
        oswpIndex5 = 'L6GPAE' + i1 + '.' + i2
        oswpIndex6 = 'L6GPAH' + i1 + '.' + i2
        oswpIndex7 = 'L6GPAD' + i1 + '.' + i2
        oswpIndex8 = 'L6GPAI' + i1 + '.' + i2
        #exp = pexpect.spawn(loginCmd[self.conType]+shelfIp)
        #exp.timeout = 60
        #exp.logfile_read = sys.stdout
        if not self.login():
            db_print("########################################")
            db_print("Login OAM failed.Please check your ENV",'send',self.dutIP)
            db_print("########################################")
        db_print('get oswp index','send',self.dutIP)
        exp = self.oamIntf
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
        if oswp_version > '4000' and oswp_version < '5401':
            db_print("Build is older than 5401.using l6gpaa index")
            oswpIndex = oswpIndex1
        if self.product == 'SDFX_AH' or self.product == 'SDFX-AH':
            oswpIndex = oswpIndex6

        exp.sendline("exit all")
        time.sleep(3)
        exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
        #time.sleep(30)
        self.logout()
        return oswpIndex
    
    #def _get_oswp_info(shelfIp,product,connectType='TELNET',password='isamcli!'):
    def _get_oswp_info(self):
        global loginCmd
        shelfIp=self.dutIP
        password=self.dutPassword
        if self.product in ['SDFX','SDOLT','NCDPU']:
            return []
        db_print('args are:%s:%s' %(shelfIp,password),'send',shelfIp)
        n = 0
        #exp = pexpect.spawn(loginCmd[self.conType]+shelfIp)
        #exp.timeout = 60
        #exp.logfile_read = sys.stdout
        if not self.login():
            db_print("########################################")
            db_print("Login OAM failed.Please check your ENV",'send',self.dutIP)
            db_print("########################################")
        exp = self.oamIntf    
        oswp_info = []
    
        num_try = 0

        tmp1 = ''
        tmp2 = ''
        db_print('get oswp info','send',self.dutIP)
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
                self.logout()
                return oswp_info
        exp.sendline("exit all")
        time.sleep(3)
        exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
        #time.sleep(30)
        self.logout()
        #del exp
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

    def clearOSWP(self):
        global loginCmd
        shelfIp=self.dutIP
        password=self.dutPassword
        if self.product in ['SDFX','SDOLT','NCDPU']:
            db_print("this version skip")
            return [True,0]
            sw_update_netf.clear_SEQ(shelfIp) 
            return [True,0]
        db_print('args are:%s:%s' %(shelfIp,password),'send',self.dutIP)
        n = 0
        #exp = pexpect.spawn(loginCmd[self.conType]+shelfIp)
        #exp.timeout = 60
        #exp.logfile_read = sys.stdout
        if not self.login():
            db_print("########################################")
            db_print("Login OAM failed.Please check your ENV",'send',self.dutIP)
            db_print("########################################")
        exp = self.oamIntf
        exp.sendline("show software-mngt oswp")
        time.sleep(3)
        oswp = "1"
        try:
            oswp_match = exp.expect(['1\s{5}(.*?)\r\n2\s{5}(.*?)\r\n',pexpect.EOF])

            if oswp_match == 0:
                tmpList = exp.match.groups()
                tmp1 = re.split('[\s|\b]+',tmpList[0])
                tmp2 = re.split('[\s|\b]+',tmpList[1])
                cmd1 = ''
                cmd2 = ''
                if tmp1[2] == 'active':
                    if tmp2[1] == 'empty':
                        db_print("oswp 1 is active and oswp 2 is empty",'send',self.dutIP)
                    else:
                        cmd1 = 'admin software-mngt oswp 1 commit'
                        cmd2 = 'admin software-mngt oswp 2 abort-download'

                if tmp2[2] == 'active':
                    if tmp1[1] == 'empty':
                        db_print("oswp 2 is active and oswp 1 is empty",'send',self.dutIP)
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
        self.logout()

    def setOSWPInfo(self,**params):
        buildInstance = params.setdefault('buildInstance',None)
        defaultDB = params.setdefault('defaultDB',False)
        action = params.setdefault('action',None)
        if action == 'download':
            build = buildInstance.buildID
            self.clearOSWP()
            oswp_info = self._get_oswp_info()
            if oswp_info:
                oswp_index = self._get_oswp_index(build)
                db_print('target oswp index is %s' %oswp_index)
            if len(oswp_info) >= 1 and not oswp_info[1]['oswpIndex'] == oswp_index and not oswp_info[1]['status'] == 'enabled':
                self.target_oswp_slot=oswp_info[1]['index']
                self.target_oswp_index=oswp_index
                return True
            else:
                return False
        elif action == 'activate':
            #activate OSWP step
            #special handling if defaultDB set True
            oswp_info = self._get_oswp_info()
            db_print("DefaultDB check %s" %oswp_info)
            
            if oswp_info and oswp_info[1]['oswpIndex'] and oswp_info[1]['status'] == 'enabled':
                self.target_oswp_slot=oswp_info[1]['index']
                db_print("activate oswp,regardless of defaultDB")
                db_print(self.target_oswp_slot)
            elif defaultDB and oswp_info and oswp_info[0]['oswpIndex']:
                self.target_oswp_slot=oswp_info[0]['index']
                db_print("activate oswp fall back to check defaultDB")
                db_print(self.target_oswp_slot)
            else:
                db_print('not match')
                db_print('target build exits,skip')
            return True
        else:
            #cleanDB branch
            oswp_info = self._get_oswp_info()
            db_print("DefaultDB check %s" %oswp_info)

            if oswp_info and oswp_info[0]['oswpIndex']:
                self.target_oswp_slot=oswp_info[0]['index']
                db_print("clean db")
                db_print(self.target_oswp_slot)
            else:
                db_print('not match')
            return True

    #def configDUT(self,cmdType,action='add',command=None,linux_ip=None,username='atxuser',passwd='alcatel01',port='22'):
    def configDUT(self,cmdType,**argw):
        action = argw.setdefault('action','')
        command = argw.setdefault('command',None)
        platform = argw.setdefault('platform',None)
        cmdLocation = argw.setdefault('cmdLocation',None)
        workspace = argw.setdefault('workspace','/tmp')
        passwd = cmdLocation['linuxPasswd']
        port = cmdLocation['linuxPORT']
        userName = cmdLocation['linuxUser']
        ipAddr = cmdLocation['linuxIP']
        
        lines=[]
        if cmdType == 'banner':
            if action == 'add':
                lines.append('configure system id %s' %platform)
                lines.append('configure system security login-banner \"+++++ %s - %s +++++\"' %(platform,platform))
                lines.append('configure system security welcome-banner \"+++++ This platform is restricted for smart service usage, unprivileged login should be forbidden!+++++\"')
            else:
                lines.append('configure system no id')
                lines.append('configure system security no login-banner')
                lines.append('configure system security no welcome-banner') 
        elif cmdType == 'command':
            lines.append(command) 
        else:
            #here merges the preshelf config/unconfig in DUT, for backward compatibility
            if cmdType in ['pre_shelf_config','post_shelf_unconfig']:
                cmd_file = '%s_command' %cmdType
            else:
                cmd_file = '%s_commands' %cmdType
            try:
                old_workspace = workspace
                workspace = re.sub(r'([\(|\)])',r'\\\1',old_workspace)
                cmd = "sshpass -p %s scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %s %s@%s:~/configs/%s %s" %(passwd,port,userName,ipAddr,cmd_file,workspace)
                result =subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
                db_print("\n%s with output:%s" %(cmd,result))
            #ssh_scp_get(ip=linux_ip,username=username,password=passwd,port=int(port),local=jenkins_summary,remote=os.path.join('~',timeStamp,'testsummary.log'))
                aFile = open(os.path.join(old_workspace,cmd_file),'r')
                lines = aFile.readlines()
                for idx in xrange(0,len(lines)):
                    lines[idx] = lines[idx].strip('\n')
            except Exception as inst:
                print "did not get configuration commands from linux machine"
        if not lines:
            pre_config_flag = False
            return
        else:
            pre_config_flag = True

        db_print('equipment configuration in %s' %cmdType)
        n = 0
        if not self.login():
            db_print("########################################")
            db_print("Login OAM failed.Please check your ENV")
            db_print("########################################")
            return False    
        exp = self.oamIntf
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
        self.logout()
        if pre_config_flag:
            db_print("Check connectivity after preconfig")
            for trytimes in range (0,60):
                if not self.login():
                    db_print("Login OAM failed.skip testing")
                    db_print("wait for 20 seconds and retry")
                    time.sleep(20)
                else:
                    break  
            self.logout()

    def checkDiskSyncForRedundancy(self,**params):
        retDict={} 
        retDict['res']=True
        if self.product == "Voice" or not self.redund:
            db_print("non redundancy or voice platform skip this check")
            return retDict
        cmd="\"inic showStates\""
        syncCheck = False
        syncComplete = False
        if not self.login():
            db_print("########################################")
            db_print("Login OAM failed.Please check your ENV")
            db_print("########################################")
            syncCheck = False
            errorCode = '506'
            retDict['error']=errorCode
            retDict['res']=syncCheck
            return retDict
        exp = self.oamIntf
        exp.sendline("show equipment slot nt-b")
        res = exp.expect(['\r\nnt-b\s+(\S+)',pexpect.EOF,pexpect.TIMEOUT])
        if res == 0:
            actType = exp.match.groups()[0]
            if not actType == 'empty':
                syncCheck = True
        self.logout()
        if syncCheck:
            buildInstance = params.setdefaults('buildInstance',None)
            script_path=params.setdefault('SCRIPT_PATH','')
            server_ip = buildInstance.agentDict['agent_ip']
            oam_ip = self.dutIP
            syncComplete=self.octopus_check(script_path,server_ip,oam_ip,cmd)
        if syncComplete:
            db_print("diskSync finished")
        else:
            db_print('diskSync not finished,timeout')
        errorCode = '510'
        retDict['error']=errorCode
        retDict['res']=syncComplete
        return retDict

    ##def compareOSWP(shelfIp,product,build,build_type,connectType='TELNET',password='isamcli!'):
    def compareOSWP(self,**argw):
        global loginCmd
        shelfIp=self.dutIP
        build = argw.setdefault('build','')
        buildInstance = argw.setdefault('buildInstance',None)
        build_type = buildInstance.buildType
        password = argw.setdefault('password','isamcli!')
        #build_check=False
        retDict={}
        retDict['res']=False
        (oswp_version,i2) = build.split('.')
        i1 = oswp_version[0:2]
        newbuild = i1+"."+i2[-3:]
        oswp_exist = ''
        #if build_type == 'LIS':
        #    db_print("this version skip for LIS build types",'send',self.dutIP)
        #    return False
        if self.product in ['SDFX','SDOLT','NCDPU','NBN-4F']:
            db_print("this version skip")
            return False
        db_print('args are:%s:%s' %(shelfIp,password),'send',shelfIp)
        n = 0
        #exp = pexpect.spawn(loginCmd[self.conType]+shelfIp)
        #exp.timeout = 60
        #exp.logfile_read = sys.stdout
        if not self.login():
            db_print("########################################")
            db_print("Login OAM failed.Please check your ENV",'send',self.dutIP)
            db_print("########################################")
        exp = self.oamIntf
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
                        db_print("oswp 1 is active and oswp 2 is empty",'send',self.dutIP)
                        tmp1[0]=tmp1[0].strip()
                        out=re.match('[A-Z|0-9]{6}(\d+\.\d+)',tmp1[0])
                        oswp_exist = out.group(1)
                    elif tmp2[1] == 'enabled' and tmp2[0] != 'NO_OSWP':
                        db_print("oswp 1 is active and oswp 2 is not-active",'send',self.dutIP)
                        oswp_exist = ""
                if tmp2[2] == 'active' and tmp2[0] != 'NO_OSWP':
                    if tmp1[1] == 'empty' and tmp1[0] == 'NO_OSWP':
                        db_print("oswp 2 is active and oswp 1 is empty",'send',self.dutIP)
                        tmp2[0]=tmp2[0].strip()
                        out=re.match('[A-Z|0-9]{6}(\d+\.\d+)',tmp2[0])
                        oswp_exist = out.group(1)
                    elif tmp1[1] == 'enabled' and tmp1[0] != 'NO_OSWP':
                        db_print("oswp 2 is active and oswp 1 is not-active",'send',self.dutIP)
                        oswp_exist = ""
            oswp_exist=oswp_exist.strip()
            if oswp_exist == newbuild:
                retDict['res']=True
            else:
                retDict['res']=False
            print oswp_exist + "," + newbuild
            exp.sendline("exit all")
            time.sleep(3)
            exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
            self.logout()
        except Exception as inst:
            db_print("Unable to find a match for oswp version :%s" %inst)
            retDict['res']=False
            self.logout()
        return retDict
    
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
            
    def pingIp(self,oam_ip):
        ret = os.system('/bin/ping -c 4 %s 2>&1 >/dev/null' % oam_ip)
        if not ret:
            db_print('%s is reachable' % oam_ip,'send',oam_ip)
            return True
        else:
            db_print('%s is not reachable' % oam_ip,'send',oam_ip)
            return False

    def check_telnet(self,oam_ip): 
        systemup = False
        time.sleep(180)
    #for trytimes in range (0,900):
    #change retry time to be 200

        for trytimes in range (0,200):
            if not self.pingIp(oam_ip):
                db_print('%s is not reachable, waiting longer...' % oam_ip,'send',oam_ip)
                time.sleep(10)
            else:
                systemup = True
                break
        if systemup == False:
            db_print("30mins passed and OAM is not reachable",'send',oam_ip)
            sys.exit(1)
        trytimes = 0
        systemup = False
        try:
            telnetTn = telnetlib.Telnet(oam_ip)
        except Exception as inst:
            db_print("telnet oam_ip with exception:%s" %inst)
            return False
        while trytimes < 40:
            try:
                telnetTn.open(oam_ip, 23)
                systemup = True
                break
            except:
                db_print("telnet OAM exception,wait 15s and continue...",'send',oam_ip)
                time.sleep(15)
                trytimes = trytimes + 1
        if systemup == False:
            db_print("10mins passed and can not open telnet connection to OAM",'send',oam_ip)
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
                db_print("Warning : The abnormal scenario in openCli():%s" % returnTmp)
                retryTimes = retryTimes + 1
                if (retryTimes  >= 20):
                    db_print("sleep 5 mins and CLI cannot be reached")
                    return False
                Telnet_send("\r", 0)
                time.sleep(15)
                returnTmp = telnetTn.read_until("*",1)                    
                continue
            retryTimes = retryTimes + 1
        db_print("Telent CLI success",'send',oam_ip)
        t3 = time.time()
        telnetTn.close()
        return True

        
    def octopus_check(self,SCRIPT_PATH,server_ip,isamIP,tnd_cmd):
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

    ###################################
    #check_lt_status(ltCheck=True,ltCheckList=LT_Check_List,cmdLocation=linuxHost)
    ###################################
    def check_lt_status(self,**params):

        lt_check = params.setdefault('ltcheck',False)
        lt_swcheck = params.setdefault('ltswcheck',False)
        lt_complete_list=self.ltCheckList
        cmdLocation=params.setdefault('cmdLocation','')
        retDict={}
        errorCode = '507'
        retDict['res']=True
        if not lt_check or not lt_complete_list:
            return retDict
        syncCheck = False
        syncComplete= False
        LT_list=[]
        
        db_print('STEP: Configure expansion shelf commands if exists')
        self.configDUT(cmdType='pre_shelf_config',action='add',cmdLocation=cmdLocation)
            
        if not self.login():
            db_print("########################################")
            db_print("Login OAM failed.Please check your ENV",'send',self.dutIP)
            db_print("########################################")
            errorCode = '506'
            retDict['res']=False
            retDict['error']=errorCode
            return retDict
        

        exp = self.oamIntf
        maxRetryTime = 5
        retryTimes = 0
        db_print("count:%s" %retryTimes)
        while retryTimes < maxRetryTime:
            try:
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
            except Exception as inst:
                db_print("show equiment slot with exception :%s" %inst)
                test_out=''
            retryTimes = retryTimes + 1
            if len(LT_list)==len(lt_complete_list) and all(LT_list.count(i)==lt_complete_list.count(i) for i in LT_list):
                syncComplete = True
                break
            else:
                syncComplete = False
                db_print("LT available check failed, retry......")
                time.sleep(10)
        if syncComplete:
            db_print("LT is available after OSWP upgrade",'send',self.dutIP)
            print("Total available LT is %s")%LT_list
            retDict['res']=True
        else:
            db_print('LT is not available after OSWP upgrade','send',self.dutIP)
            retDict['res']=False
            retDict['error']=errorCode
        self.logout()
        if not lt_swcheck:
            self.configDUT(cmdType='post_shelf_unconfig',action='add',cmdLocation=cmdLocation)
        return retDict

    ###################################
    #check_lt_sw(ltCheck=True,ltCheckList=LT_Check_List,cmdLocation=linuxHost,build=build)
    ###################################
    def check_lt_sw(self,**params):
        LTSWCheck=params.setdefault('ltswcheck',False)
        LT_check_list=self.ltCheckList
        cmdLocation = params.setdefault('cmdLocation','')
        buildInstance = params.setdefault('buildInstance',None)
        #serverip = buildInstance.buildAgent
        serverIp = buildInstance.agentDict['agent_ip']
        serverUser = buildInstance.agentDict['agent_user']
        serverPasswd = buildInstance.agentDict['agent_password']
        serverPort = buildInstance.agentDict['agent_port']
        build = buildInstance.buildID
        passwd = cmdLocation['linuxPasswd']
        port = cmdLocation['linuxPORT']
        userName = cmdLocation['linuxUser']
        ipAddr = cmdLocation['linuxIP']
        retDict={}
        errorCode = '508'
        retDict['res']=True
        if not (LTSWCheck and LT_check_list and cmdLocation and build):
            return retDict
        sep=','
        new_LT_val=sep.join(LT_check_list) 
        try:
            remotescript = '/tmp/.jenkins/lt_swcheck.py'
            cmd_octopus = '%s --isam_ip %s --lt_list %s --build %s' %(remotescript,self.dutIP,new_LT_val,build)
            final_res = False
            for trytimes in range (0,5):
                tmp_res=ssh2(serverIp,serverUser,serverPasswd,cmd_octopus,'check')
                print tmp_res
                if tmp_res.find('LT SW check is successfull') == -1:
                    db_print("wait for 60 seconds and retry")
                    time.sleep(60)
                else:
                    final_res = True
                    break
        except Exception as inst:
            db_print("LT SW check is failed:%s" %inst)
            final_res = False
            
        retDict['res']=final_res
        if not final_res:
            retDict['error'] = errorCode
        self.configDUT(cmdType='post_shelf_unconfig',action='add',cmdLocation=cmdLocation)
        return retDict
    
    @classmethod
    def prepareOSWP(cls,**params):
    #def prepareOSWP(ver,serverip,product,buildip='135.251.206.97',moswa_list=[],toolOnly =False, destDir='/tftpboot',build_type='official',extraTar = False,debug=False):
        buildInstance = params.setdefault('buildInstance',None)
        ver = buildInstance.buildID
        buildip = buildInstance.buildSource
        #serverip = buildInstance.buildAgent
        serverIp = buildInstance.agentDict['agent_ip']
        serverUser = buildInstance.agentDict['agent_user']
        serverPasswd = buildInstance.agentDict['agent_password']
        serverPort = buildInstance.agentDict['agent_port']
        destDir = buildInstance.destDir
        #for /tftpboot ,it is ''
        #for lis build, it is /tftpboot/135.251.194.30_Apr26145113
        postfix = re.sub('^.*tftpboot\/?','',destDir)
        build_type = buildInstance.buildType
        extraTar = params.setdefault('extraTar',False)
        loadinfo = params.setdefault('loadinfo','noload')
        jksbuildID = params.setdefault('JKS_BuildID','')
        jksbuildIDNew= params.setdefault('JKS_BuildIDNew','')
        hostFlag= params.setdefault('hostFlag','')
        t0 = time.time()
        old_ver = ver 
        retDict = {}
        retDict['res'] = True
        result = True
        #if jksbuildID == 'latest':
        #bServerL=buildip.split(':')
        latest_ver = jksbuildIDNew
        buildRelease=buildInstance.buildRelease
        #buildip=getAvailableBuild(bServerL,buildRelease,latest_ver,hostFlag)
        #db_print("change build server to be:%s" %buildip)
        ver = buildRelease.replace('.','') + '.' + latest_ver.split('.')[-1]
        #db_print("change build to be :%s" %buildip)
        remotescript = '/tmp/.jenkins/oswpUtility.py'
        #remotescript = postfix2script(remotescript,postfix)
        result = True
        if extraTar:
            db_print("Download extra tar")
            cmd = "%s --action prepareOSWP --build %s --serverip %s --Host '%s'" %(remotescript,ver,serverIp,buildip)
            cmd = cmd + ' --extraTar SD_%s.extra.tar  --destDir %s' %(ver,destDir)

            cmd1=str(cmd)
            try:
                tmpRes1 = ssh2(serverIp, serverUser,serverPasswd,cmd1,'check')
                print tmpRes1
            except Exception as inst:
                db_print("Download extra tar failed with %s" %inst)
                pass
        if loadinfo == 'load':
            if build_type == 'LIS':
                dr4Flag = False
            else:
                dr4Flag = _check_build_dr4(ver)

            #remotescript = '/tmp/.jenkins/oswpUtility.py'
            cmd = "%s --action prepareOSWP --build %s --serverip %s --Host '%s'" %(remotescript,ver,serverIp,buildip)
            cmd = cmd + ' --destDir %s' %destDir
        ##LIS build check
            if build_type == 'LIS':
                cmd = cmd + ' --build_type %s' %build_type
            if dr4Flag:
                cmd = cmd + ' --dr4'

            db_print("Download normal tar")
            db_print(cmd)
            try:
                tmpRes = ssh2(serverIp, serverUser,serverPasswd,cmd,'check')
            except :
                tmpRes = ''
            print tmpRes
            if tmpRes.find('download failure') == -1:
                result = True
            else:
                result = False
        t1 = time.time()
        retDict['res'] = result
        if not result:
            retDict['error'] = '501'
        return retDict

    #########################################
    #  downloadOSWP(buildInstance=buildInstance)
    #########################################
    def downloadOSWP(self,**params):
        retDict={}
        retDict['res']=True
        errorCode = '502'
        buildInstance = params.setdefault('buildInstance',None)
        if not self.setOSWPInfo(buildInstance=buildInstance,action='download'):
            retDict['res'] = False
            retDict['error'] = errorCode
            return retDict
        oswp = self.target_oswp_slot
        oswpIndex = self.target_oswp_index
        serverip = buildInstance.agentDict['agent_ip']    
        if buildInstance.oswpIndexPrefix:
            oswpIndex = buildInstance.oswpIndexPrefix + '/' + oswpIndex  
        if not self.login():
            db_print("########################################")
            db_print("Login OAM failed.Please check your ENV",'send',self.dutIP)
            db_print("########################################")
            retDict['res'] = False
            retDict['error'] = errorCode
            return retDict
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
        max_dl_try = 3
        exp = self.oamIntf
        for i in range(max_dl_try):
            for command in Commands:
                exp.sendline(command)
                time.sleep(4)
                try:
                    exp.expect(["#","$"])
                except:
                    db_print("Warning, no prompt retrieve",'send',self.dutIP)
                    db_print(str(exp.eof()))
            time.sleep(5)
            while True:
                exp.sendline("admin software-mngt oswp %s download %s" % (oswp, oswpIndex))
            #t0 = time.time()

                try:
                    ret = exp.expect(["SWDB MGT error 22", "SWDB MGT error 18"], timeout=10)
                except:
                    db_print("Download CLI command is OK",'send',self.dutIP)
                    break
                if ret:
                    time.sleep(30)
                    exp.sendline("admin software-mngt oswp %s abort-download" % oswp)
                time.sleep(15)
            exp.sendline("show software-mngt oswp %s" % oswp)
            trycounts = 0
            ret = 10
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
                        db_print("60 mins passed. downloading still not completed.Skip this download",'send',self.dutIP)
                        break
                    time.sleep(10)
                    exp.sendline("show software-mngt oswp %s" % oswp)
            if ret == 0:
                break
            else:
                db_print("Download fail with exp result: %s retry time:%s" % (ret,i))
                continue
        exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
        self.logout()
        if ret == 0:
            result = True
        else:
            result = False
        #if ret ==1:
        #    errorCode = '503'
        #if ret ==2:
        #    errorCode = '504'
        t1 = time.time()
        retDict['res'] = result
        if result:
            db_print("Download success",'send',self.dutIP)
        else:
            db_print("Download fail",'send',self.dutIP)
            retDict['error'] = errorCode
        # 502 means download failure
        return retDict
    
    def activateOSWP(self,**params):
    #def activateOSWP(shelfIp,oswp,product,cleanDB=False,toolOnly = False,moswa_list=[],password='isamcli!',mode='default',connectType='TELNET'):
        redund = self.redund
        #db_print(str(params))
        cleanDB = params.setdefault('defaultDB',False)
        result = True
        errorCode = '505'
        if cleanDB == 'true':
            cleanDB = True
        if cleanDB == 'false':
            cleanDB = False
        t0 = time.time()
        active_mode=params.setdefault('active',True)
        mode=params.setdefault('mode','')
        buildInstance = params.setdefault('buildInstance',None)
        db_print("cleandb:%s" %cleanDB)
        db_print('active_mode:%s' %active_mode)
        #cleanDB used for inter domains active with def 
        #in loadinfo=load branch, cleanDB also done for backward compatibility
        #branches
        #action = 'activate'
        #branch 1: loadinfo = load, will firstly activate not-active oswp index
        #branch 2: loadinfo = load, if no not-active oswp index, if defaultDB=True,activate active oswpindex
        #action = 'clean db'
        #branch 3: loadinfo = cleanDB,regardless of defaultdb,activate active oswpindex
        #branch 4: invoked in cleandb parallel,with condition of default db, activate active index
        if active_mode:
            res = self.setOSWPInfo(buildInstance=buildInstance,action='activate',defaultDB=cleanDB)
        else:
            res = self.setOSWPInfo(buildInstance=buildInstance,action='cleandb',defaultDB=cleanDB)
        if not res:
            retDict['res'] = False
            retDict['error'] = errorCode
            return retDict

        oswp = self.target_oswp_slot

        retDict= {}
        retDict['res'] = result
        if not oswp:
            db_print('target build existing,defaultDB not set,return directly')
            return retDict
        if not self.login():
            db_print("########################################")
            db_print("Login OAM failed.Please check your ENV",'send',self.dutIP)
            db_print("########################################")
            retDict['res'] = False
            retDict['error'] = errorCode
            return retDict
        #based on different nt type, wait more time for delayed restart
        max_sleep_time = 120
        exp = self.oamIntf
        delay_restart=False
        exp.sendline("show equipment slot")
        try:
            ret=exp.expect(['fant-f','fant-g','fant-h',pexpect.EOF,pexpect.TIMEOUT])
            if ret == 0 or ret == 1 or ret == 2:
                max_sleep_time = 600
                delay_restart = True
        except:
            pass

        retryTimes = 0
        maxRetryTime = 30
        exp.sendline("\r")
        db_print("active oswp %s" % oswp,'send',self.dutIP)
        db_print("count:%s" %retryTimes)
        while retryTimes < maxRetryTime:
            if mode == 'default':
                exp.sendline("admin software-mngt oswp %s activate with-default-db" % oswp)
                db_print("active with default DB",'send',self.dutIP)
            elif mode == 'linked':
                exp.sendline("admin software-mngt oswp %s activate with-linked-db" % oswp)
                db_print("active with linked DB",'send',self.dutIP)
            else:
                db_print("Nothing done")
                self.logout()
                return retDict

            try:
                #exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
                ret = exp.expect(["SWDB MGT error 25","Error : resource is currently held by one manager"])
                print 'expect end with %d' %ret
            except :
                db_print("count:%s" %retryTimes)
                db_print("activate executed successfully!",'send',self.dutIP)
                break
            db_print("count:%s" %retryTimes)
            retryTimes = retryTimes + 1
            time.sleep(15)
        exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
        #db_print('wait for 4 seconds for oswp activation')
        #time.sleep(4)
        db_print('wait for %s seconds for oswp activation' %max_sleep_time)
        time.sleep(max_sleep_time)
        try:
            PING_TRY = 0
            if  redund or delay_restart:
                PING_TRY = 18
                db_print("for redundany or fant-f/g/h platform, ping oam ip accessibility after dispatch activation command")
                if self.pingIp(self.dutIP):
                    db_print("oam ip still accessible,nt restart delayed,wait for 180s")
                    time.sleep(180)
            db_print("ping oam accessibility in case nt restart delayed...")
            for i in range(0,PING_TRY):
                if self.pingIp(self.dutIP):
                    time.sleep(10)
                #oswp_info = _get_oswp_info(shelfIp,product,connectType)
                #db_print("oswp_info:%s" %str(oswp_info))
                #if oswp_info :
                #    active_index = oswp_info[0].get('index','')
                #    if not active_index == oswp:
                #        db_print("current active oswp index is %s while target should be %s" %(active_index, oswp))
                #        time.sleep(20)
                break
        except Exception as inst:
            db_print("ping and oswp check after dispatch activate cmd faile with %s" %inst) 
            pass
        self.logout()
        result = True
        t1 = time.time()
        db_print("ISAM oswp activate finished",'send',self.dutIP)
        retDict['res'] = result
        if not result:
            retDict['error'] = errorCode
        return retDict
    
    def cleanDB(self,**params):
        params.setdefault('active',False)
        retDict = self.activateOSWP(**params)
        if not retDict['res']:
            return retDict
        params.setdefault('toolOnly',True)
        retDict = self.initializeDUT(**params)
        return retDict
        
     
    def initializeDUT(self,**params):
        retDict={} 
        retDict['res']=True
        result = True
        errorCode = '506'
        remotescript = '/tmp/.jenkins/initConfigFunc.py'
        initCommands=self.initCommands
        cmdLocation = params.setdefault('cmdLocation','')
        workspace=params.setdefault('workspace','') 
        self.set_extra_init_commands(cmdLocation=cmdLocation,workspace=workspace)
        extraCommands=self.extraInitCommands
        craftIp = self.craftIp
        craftPort = self.craftPort
        oam_ip = self.dutIP
        oam_type = self.oamType
        product = self.product
        redund = self.redund
        toolOnly = params.setdefault('toolOnly',False)
        buildInstance = params.setdefault('buildInstance',None)
        serverIp = buildInstance.agentDict['agent_ip']
        serverUser = buildInstance.agentDict['agent_user']
        serverPasswd = buildInstance.agentDict['agent_password']
        serverPort = buildInstance.agentDict['agent_port']
        if initCommands:
            initCommands=','.join(initCommands)
            initCommands="'"+initCommands+"'"
        else:
            initCommands=''
        if extraCommands:
            extraCommands=','.join(extraCommands)
        else:
            extraCommands=''
        cmd_init = 'python -u %s --server_ip %s --craft_ip %s --craft_port %s --isam_ip %s --command %s --command_extra \"%s\" --product %s --oamtype %s --redund %s --toolonly %s' %(remotescript,serverIp,craftIp,craftPort,oam_ip,initCommands,extraCommands,product,oam_type,redund,toolOnly)
        tmp_res=ssh2(serverIp, serverUser,serverPasswd,cmd_init,'checkandprint')
        db_print(cmd_init)
        if not tmp_res:
            db_print("no output caught in ssh")
            ret_val=False
        elif tmp_res.find('Initial config is success in ISAM') == -1:
            db_print("no success info in ssh")
            ret_val=False
        else:
            db_print("Initial config is success in ISAM")
            ret_val=True
        t1 = time.time()
        if not ret_val:
            errorCode = '506'
            #return False
            retDict['error']=errorCode
            retDict['res']=False
            return retDict
        #self.configDUT(cmdType='banner',action='add')
        retDict['res'] = True
        return retDict
    
    def checkandclearOSWP(self,build):
        action='activateOSWP'
        oswp_info = self._get_oswp_info()
        res = True
        if oswp_info:
            oswp_index = self._get_oswp_index(build)
            if len(oswp_info) >= 1 and not oswp_info[0]['oswpIndex'] == oswp_index:
                db_print("target oswp %s is not the active one:%s, skip step:%s" %(oswp_index,oswp_info[0]['oswpIndex'],action))
                res = False
        self.clearOSWP()
                
        return res
    
    def adjust_link_speed(self):
        global loginCmd
        shelfIp=self.dutIP
        password=self.dutPassword
        retDict={}
        retDict['res']=True
        errorCode = '502'
        systemup = True
        #exp = pexpect.spawn(loginCmd[self.conType]+shelfIp)
        #exp.timeout = 60
        #exp.logfile_read = sys.stdout        
        if not self.login():
            db_print("########################################")
            db_print("Login OAM failed.Please check your ENV",'send',shelfIp)
            db_print("########################################")
            systemup = False
            return retDict
        exp = self.oamIntf
        exp.sendline("show equipment slot")
        index4 = exp.expect(['fant-','(ag|na)nt-','rant-','srnt-(\w)',pexpect.TIMEOUT])
        if index4 == 0:
            db_print("FX platform")
            db_print("No need to adjust link speed",'send',shelfIp)
            self.logout()
        elif index4 == 1:
            db_print("FD platform")
            exp.sendline("info configure system max-lt-link-speed detail")
            index5 = exp.expect(['no link-speed','twodotfive-gb','ten-gb','twenty-gb','forty-gb',pexpect.TIMEOUT])
            if index5 < 2:
                db_print('FD platform max linkspeed is too low,change speed to 10G and reboot...','send',shelfIp)
                exp.sendline("configure system max-lt-link-speed link-speed ten-gb")
                time.sleep(3)
                exp.sendline("admin equipment reboot-isam without-self-test")
                exp.expect(["#","$",pexpect.EOF,pexpect.TIMEOUT])
                time.sleep(30)
                self.logout()
                systemup = False
                time.sleep(120)
                for trytimes in range (0,60):
                    if not self.pingIp(shelfIp):
                        db_print('%s is not reachable, waiting longer...' % shelfIp)
                        time.sleep(30)
                    else:
                        systemup = True
                        break
                if systemup == False:
                    db_print("30mins passed and OAM is not reachable after config max link speed",'send',shelfIp)
                    retDict['error'] = errorCode
                    self.logout()
                    return retDict
                time.sleep(150)
                systemup = False
                for trytimes in range (0,60):
                    if  not self.login():
                        db_print("Login OAM failed.skip testing")
                        db_print("wait for 30 seconds and retry")
                        time.sleep(30)
                    else:
                        systemup = True
                        break
                if systemup:
                    db_print("link speed adjust successfully with warm reboot!",'send',shelfIp)
                self.logout()
        try:
            self.logout()
        except Exception as inst:
            pass
        retDict['res']=systemup
        if not systemup:
            retDict['error'] = errorCode
        return retDict
    
def extractExtraOptions(ExtraOptions,ProposalBuildFlag):
    extraKeyList = ['NT','NT_gici','LT_gici','LT','BUILDTYPE','METRICSUSER','BOARD',\
                    'transMode','dutNetconfPort','dutTracePort','dutOamPasswd','indexDesc',\
                    'saveTrace','UPDATEBUILD','caseMode','domainMode','LTCheck','LTSWCheck','redund','Team',\
                    'fwdVlanMode','NonFwCaseList','batchType','PCTA','vectorType','STC','purgeRepo','connectType',\
                    'updatePlugin','updateAV','avVersion','Site','Shelf','Inband','SWMgmt','userName',\
                    'passWord','Platform','Boards']
    #if no Team passed, Other will be used

    SimpleExtraOptions = ['transMode', 'dutNetconfPort', 'dutTracePort', 'dutOamPasswd', 'indexDesc', \
                        'saveTrace', 'caseMode', 'domainMode', 'LTCheck', 'LTSWCheck','redund', 'Team',\
                        'fwdVlanMode', 'NonFwCaseList', 'batchType', 'PCTA','vectorType','STC','purgeRepo',\
                        'connectType','updatePlugin','updateAV','avVersion', 'Site','Shelf','Inband','SWMgmt','userName',\
                        'passWord','Platform']
    metrics_user = ''
    board = ''
    trace_server_list = []
    LT_check_list = []
    update_build =''
    LT_Dict = {}
    dUpgradeOptions={}
    for key in SimpleExtraOptions:
        #cmd_set_value = "%s=''" %key
        #exec(cmd_set_value)
        dUpgradeOptions[str(key).strip()]=''
    #for SimpleExtraOptions, only Team default value is Other
    Team = 'Other'
    oam_type='None'
    dUpgradeOptions['Boards']=[]
    try:
        dExtraOptions = json.loads(ExtraOptions)
        #print dExtraOptions
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
                    dUpgradeOptions['board']=board
                    dUpgradeOptions['oamType']=oam_type
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
                    dUpgradeOptions['board']=board
                    dUpgradeOptions['oamType']=oam_type
                elif extraKey == 'LT':
                    #dExtraOptions['LT'] = dict(map(lambda (k, v): (str(k).strip(), str(v).strip().upper()), dExtraOptions['LT'].iteritems()))
                    dExtraOptions['LT'] = dict(map(lambda (k, v): (str(k).strip(), str(v).strip()), dExtraOptions['LT'].iteritems()))
                    try:    
                        LT_check_list=dExtraOptions['LT'].values()
                        LT_check_list=[x.strip(' ') for x in LT_check_list]
                        LT_check_list=json.dumps(LT_check_list)
                    except Exception as inst:
                        db_print("Invalid LT value format")
                        LT_check_list=[]
                    LT_Dict = dExtraOptions['LT']
                    dUpgradeOptions['ltDict']=copy.deepcopy(LT_Dict)
                    dUpgradeOptions['ltCheckList']=copy.deepcopy(LT_check_list)
                elif extraKey == 'Shelf':
                    try:
                        multidut=dExtraOptions['Shelf']
                    except Exception as inst:
                        db_print("Invalid Shelf value format")
                        multidut=[]
                    dUpgradeOptions['multiDut']=copy.deepcopy(multidut)
                elif extraKey == 'BUILDTYPE' and dExtraOptions['BUILDTYPE'].strip():
                    build_type=str(dExtraOptions['BUILDTYPE']).strip()
                    if ProposalBuildFlag:
                        build_type = 'LIS'
                    dUpgradeOptions['buildType']=build_type
                elif extraKey == 'UPDATEBUILD' and dExtraOptions['UPDATEBUILD'].strip():
                    dUpgradeOptions['updateBuild']=str(dExtraOptions['UPDATEBUILD']).strip()
                elif extraKey == 'METRICSUSER' and dExtraOptions['METRICSUSER'].strip():
                    dUpgradeOptions['metricUser']=str(dExtraOptions['METRICSUSER']).strip()
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
                        elif 'NTIO' in key and dExtraOptions[extraKey][key].strip():
                            slotPos = key
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
                        dUpgradeOptions['traceServerList']=copy.deepcopy(trace_server_list)
                elif extraKey == 'Boards':
                    dUpgradeOptions['Boards']=copy.deepcopy(dExtraOptions[extraKey])
                elif  extraKey in SimpleExtraOptions:
                    #cmd_set_value = '%s=str(dExtraOptions[extraKey]).strip()' %extraKey
                    #exec(cmd_set_value)
                    newKey = str(extraKey).strip()
                    if type(dExtraOptions[extraKey]) == bool:
                        dUpgradeOptions[newKey]=dExtraOptions[extraKey]
                    else:
                        dUpgradeOptions[newKey]=str(dExtraOptions[extraKey]).strip()
                        
                        #saveTrace,LTCheck,LTSWCheck,redund
                        if dUpgradeOptions[newKey].lower() == 'true':
                            dUpgradeOptions[newKey] = True
                        elif dUpgradeOptions[newKey].lower() == 'false':
                            dUpgradeOptions[newKey] = False
    except Exception as inst:
        db_print("wrong extraoptions passed:%s" %inst)
    return dUpgradeOptions

def getDutInfo(shelf_list):
    dutlist=[]
    LT_Dict={}
    extraKeyList = ['NT','NT_gici','LT_gici','LT']
    oam_type="None"
    if not shelf_list:
        return dutlist
    else:
        try:
            for dExtraOptions in shelf_list:
                board = ''
                trace_server_list=[]
                LT_Dict={}
                for extraKey in extraKeyList:
                    if extraKey in dExtraOptions:
                        #for target, using NT
                        if extraKey == 'NT':
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
                            dExtraOptions['oam_type']=oam_type
                        elif extraKey == 'LT':
                            dExtraOptions['LT'] = dict(map(lambda (k, v): (str(k).strip(), str(v).strip()), dExtraOptions['LT'].iteritems()))
                            try:
                                LT_check_list=dExtraOptions['LT'].values()
                                LT_check_list=[str(x.strip(' ')) for x in LT_check_list]
                                dExtraOptions['ltCheckList']=LT_check_list
                            except Exception as inst:
                                db_print("Invalid LT value format")
                                dExtraOptions['ltCheckList']=[]
                            LT_Dict = dExtraOptions['LT']
                            dExtraOptions['LT_Dict']=LT_Dict
                        elif extraKey == 'NT_gici' or extraKey == 'LT_gici':
                            dExtraOptions[extraKey] = dict(map(lambda (k, v): (str(k).strip(), str(v).strip()), dExtraOptions[extraKey].iteritems()))
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
                                elif 'NTIO' in key and dExtraOptions[extraKey][key].strip():
                                    slotPos = key
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
                            dExtraOptions['traceServerList']=trace_server_list
                dutlist.append(dExtraOptions)
        except Exception as inst:
            db_print("wrong extraoptions passed:%s" %inst)
        return dutlist
    
def getMoswaDict(build,SERVER_IP,HOST,product,build_type,LIS_DIR,ntimestamp):
    MOSWA_DICT = {}
    if not product in ['SDFX','SDOLT','NCDPU']:
        return MOSWA_DICT
    (protocol,build_ip,build_dir,build_user,build_pazwd) = _parse_build_server(HOST)
    tmpList = SERVER_IP.split(':')
    MOSWA_DICT['build_name'] = build
    MOSWA_DICT['update_ip'] = tmpList[0]
    MOSWA_DICT['update_port'] = tmpList[1]
    MOSWA_DICT['update_user'] = tmpList[2]
    MOSWA_DICT['update_pazwd'] = tmpList[3]
    MOSWA_DICT['protocol'] = protocol
    MOSWA_DICT['build_ip'] = build_ip
    MOSWA_DICT['build_dir'] = build_dir
    MOSWA_DICT['build_ftp_dir'] = build_dir
    MOSWA_DICT['no_fallback'] = True
    if build_type == 'LIS':
        MOSWA_DICT['update_abs_dir'] = LIS_DIR
        MOSWA_DICT['alias_dir'] = ntimestamp
        MOSWA_DICT['build_type'] = 'LIS'
    trans_mode = ''
    file_index = ''
    if build_user:
        MOSWA_DICT['build_user'] = build_user
    if build_pazwd:
        MOSWA_DICT['build_pazwd'] = build_pazwd
    dut_port = '830'
    dut_trace_port = '2222'
    if product == 'SDFX':
        trans_mode = 'http'
        file_index = 'AG'
        dut_port = '830'
        dut_trace_port = '2222'
    elif product == 'SDOLT':
        trans_mode = 'http'
        file_index = 'AG'
        dut_port = '830'
        dut_trace_port = '22'
    elif product == 'NCDPU':
        trans_mode = 'tftp'
        file_index = 'AF'
        dut_trace_port = '2222'
    MOSWA_DICT['trans_mode'] = trans_mode
    MOSWA_DICT['nt_type'] = file_index
    MOSWA_DICT['dut_port'] = dut_port
    MOSWA_DICT['db_port'] = dut_trace_port
    return MOSWA_DICT

def putMoswaDict(buildInstance,dutInstance):
    moswa_dict=buildInstance.moswaDict
    if dutInstance.dutPort:
        moswa_dict['dut_port'] = dutInstance.dutPort
    if dutInstance.nt_type:
        moswa_dict['nt_type'] = dutInstance.nt_type
    if dutInstance.transMode:
        moswa_dict['trans_mode'] =  dutInstance.transMode
    if dutInstance.db_port:
        moswa_dict['db_port'] = dutInstance.db_port
    if dutInstance.dutIP:
        moswa_dict['dut_ip'] = dutInstance.dutIP
    if dutInstance.dutUser.strip():
        moswa_dict['dut_user'] = dutInstance.dutUser.strip()
    if dutInstance.dutPassword.strip():
        moswa_dict['dut_password'] = dutInstance.dutPassword.strip()

def checkProposalbuild(build):
    try :
        prop_flag=False
        b = build.split('.')
        i1 = b[0][0:2]
        i2 = b[1]
        if re.search('p',i2):
            prop_flag=True
        return prop_flag
    except Exception as inst:
        db_print("build check exception :%s!" % str(inst))
        return False
    
def postfix2script(aScript,postfix):
    if postfix:
        return re.sub(r'(\.[^\.]+)$','.' + postfix + r'\1',aScript)
    else:
        return aScript

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("--buildServer", dest="buildServer",default='', help="action (eg. 135.251.206.97,etc)")
    parser.add_argument("--ftpServer", dest="ftpServer",default='', help="action (eg. 135.251.206.69)")
    parser.add_argument("--extraOptions", dest="ExtraOptions",default='', help="pass extra variable such as NT TYPE NT-A:NANT-A")
    parser.add_argument("--platformType", dest="platformType",default='GPON', help="GPON or other")
    parser.add_argument("--build", dest="build",default="", help="Build version")
    parser.add_argument("--release", dest="release",default='', help="rerun robot cases after 1st run")
    #parser.add_argument("--linuxPORT", dest="linuxPORT",default='22', help="ssh port of linux machine")
    #parser.add_argument("--linuxIP", dest="linuxIP",default='', help="ip of machine to run LTB")
    parser.add_argument("--loadinfo", dest="loadinfo",default='', help="noload or ''")
    parser.add_argument("--extraTar", dest="extraTar",default='', help="used to pass -K /tftpboot/atx/loads/5601.472.extra.tar")
    parser.add_argument("--action", dest="action",default='all', help="all or ''")
    parser.add_argument("--jksBuild", dest="jksBuild",default='', help="all or ''")
    parser.add_argument("--jksNewBuild", dest="jksNewBuild",default='', help="all or ''")
    parser.add_argument("--platform", dest="job_name",default='', help="all or ''")
    parser.add_argument("--defaultDB", dest="defaultDB",default='', help="when domainSplit set True,also want to clean DB after each LTB run")

    options = parser.parse_args()
    SCRIPT_PATH='/var/jenkins_home/scripts'
    extraTar = options.extraTar
    if extraTar == 'true':
        extraTar = True
    if extraTar == 'false':
        extraTar = False    
    
    buildServer = 'ftp:135.251.206.97:/ftpserver/loads:asblab:asblab' if not options.buildServer else options.buildServer
    job_name=options.job_name
    workspace=os.path.join('/var/jenkins_home/workspace',job_name)
    tftpServer = options.ftpServer     
    product = options.platformType
    loadinfo = options.loadinfo
    ProposalBuildFlag = False
    OswpCheckFlag = False
    build = options.build
    if checkProposalbuild(build):
        ProposalBuildFlag = True
    release = options.release
    jks_build_id = options.jksBuild
    jks_build_id_new = options.jksNewBuild
    action = options.action
    ExtraOptions=options.ExtraOptions
    upgradeDict = extractExtraOptions(ExtraOptions,ProposalBuildFlag)
    LTCheck = upgradeDict.get('LTCheck',False)
    LTSWCheck = upgradeDict.get('LTSWCheck',False)
    build_type=upgradeDict.get('buildType','LIS')
    #'saveTrace', 'caseMode', 'domainMode', 'LTCheck', 'LTSWCheck','redund'
    redund  = upgradeDict.get('redund',False)
    LT_check_list  = upgradeDict.get('ltCheckList',[])
    LT_Dict = upgradeDict.get('ltDict',[])
    board= upgradeDict.get('board','')
    oam_type = upgradeDict.get('oamType','')
    connectType = upgradeDict.get('connectType','TELNET')
    multidut = upgradeDict.get('multiDut','')
    dutList = getDutInfo(multidut)
    SERVER_IP=tftpServer
    HOST=buildServer
    tmpList = SERVER_IP.split(':')
    linuxIP = tmpList[0]    
    linuxPort = tmpList[1]
    linuxUser = tmpList[2]
    linuxPasswd = tmpList[3]
    destDir = tmpList[4]
    postfix = re.sub('^.*tftpboot\/?','',destDir)
    LIS_DIR=destDir
    ntimestamp=postfix
    MOSWA_DICT=getMoswaDict(build,tftpServer,buildServer,product,build_type,LIS_DIR,ntimestamp)
    buildinfo = {}
    buildinfo['buildSource']=HOST
    buildinfo['buildAgent']=SERVER_IP
    buildinfo['buildID']=build
    buildinfo['buildType']='LIS'
    buildinfo['moswaDict']=MOSWA_DICT
    buildinfo['buildRease']=release
    buildinfo['destDir']=destDir  
    cmdLocation = {}

    cmdLocation['linuxIP'] = linuxIP
    cmdLocation['linuxUser'] = linuxUser
    cmdLocation['linuxPasswd'] = linuxPasswd
    cmdLocation['linuxPORT'] = linuxPort
    buildInstance = BUILD(buildinfo)
    dutInstanceList = []
    firstUpgradeDut = False            
    for dutTest in dutList:
        dutTest['product'] = product
        dutTest['connectType'] = connectType
        #wrap site info for each dut, since used by nbn4f
        if product == "NBN-4F":
            dutInstance = nbn4fDUT(dutTest)
            if not firstUpgradeDut  and dutTest.get('Upgrade',True):
                firstUpgradeDut = True
                oam_ip = dutTest.get('DutOamIP','')
        elif product in ['NCDPU','SDFX','SDOLT']:
            dutTest['clrDB'] = True
            dutInstance = moswaDUT(dutTest)
            dutInstance.setMoswaList(buildInstance=buildInstance)
        else:
            dutInstance = snmpDUT(dutTest)
        dutInstanceList.append(dutInstance)
    if product in ['NCDPU','SDFX','SDOLT'] and dutInstanceList:
        #put dut level port/transmode info into buildInstance for prepareOswp
        putMoswaDict(buildInstance,dutInstanceList[0])
    defaultDB = options.defaultDB
    dbMode = 'default'
    if action == 'all':
        actions = [STEP1,STEP2,STEP3,STEP4]
    else:
        actions = action.split(',')
    resDict = {}
    resDict['res'] = True
    #print(actions)
    if STEP1 in actions:
        action = STEP1
        db_print("step:%s" %action)
        if not DUT.dutPreCheck(dutInstanceList):
            db_print("Failure in dut precheck")
            resDict['errors'] = [{'res':False,'error':ERROR_CODES[action]}]
            db_print('Image Flash Result:%s' %json.dumps(resDict))
            sys.exit(1)
        if DUT.compareOSWP(dutInstanceList,buildInstance=buildInstance,build=build):
            db_print("Compare OSWP - Build exists in system skip prepareOSWP:%s" %action)
            db_print('Image Flash Result:%s' %json.dumps(resDict))
            sys.exit()
        DUT.configDUT(dutInstanceList,cmdType='banner',action='add',platform=job_name,cmdLocation = cmdLocation)
        #only support non NBN 4f setup
        res=DUT.prepareOSWP(dutInstanceList,buildInstance=buildInstance,extraTar=extraTar,JKS_BuildID=jks_build_id,JKS_BuildIDNew=jks_build_id_new,loadinfo=loadinfo)
        if not res['res']:
            db_print("prepareOSWP failure")
            resDict.update(res)
            print(resDict)
            db_print('Image Flash Result:%s' %json.dumps(resDict))
            #db_print('Image Flash Result:' %str(resDict))
            sys.exit(1)
    if STEP2 in actions:
        action = STEP2
        db_print("step:%s" %action)
        if loadinfo == 'load':
            res = DUT.downloadParallel(dutInstanceList,buildInstance = buildInstance,cmdLocation = cmdLocation)
            if not res['res']:
                db_print("downloadOSWP failure")
                resDict.update(res)
                print(resDict)
                db_print('Image Flash Result:%s' %json.dumps(resDict))
            #db_print('Image Flash Result:' %str(resDict))
                sys.exit(1)

    if STEP3 in actions:
        action = STEP3
        db_print("step:%s" %action)
        if loadinfo == 'load':
            res = DUT.activateParallel(dutInstanceList,defaultDB=defaultDB,buildInstance=buildInstance,mode='default')
        elif loadinfo == 'cleandb':
            if product in ['NCDPU','SDFX','SDOLT']:
                res = DUT.cleanDBParallel(dutInstanceList,buildInstance=buildInstance,cmdLocation=cmdLocation,mode='default')
            else:
                res = DUT.activateParallel(dutInstanceList,defaultDB=True,buildInstance=buildInstance,mode='default',active=False)
        else:
            db_print("loadinfo is noload,do not activate oswp")
            db_print('Image Flash Result:%s' %json.dumps(resDict))
            sys.exit()
        if not res['res']:
            db_print("activateOSWP failure")
            resDict.update(res)
            print(resDict)
            db_print('Image Flash Result:%s' %json.dumps(resDict))
            #db_print('Image Flash Result:' %str(resDict))
            sys.exit(1)
    if STEP4 in actions:
        action = STEP4
        db_print("step:%s" %action)
        if loadinfo == 'load' or loadinfo == 'cleandb':
            res = DUT.initializeParallel(dutInstanceList,buildInstance=buildInstance,SCRIPT_PATH=SCRIPT_PATH,cmdLocation=cmdLocation,workspace=workspace,redund=redund)
            print(res)
        else:
            db_print("loadinfo is noload,do not activate oswp")
            db_print('Image Flash Result:%s' %json.dumps(resDict))
            #db_print('Image Flash Result:' %str(resDict))
            sys.exit()

        if not res['res']:
            db_print("initializeDUT failure")
            resDict.update(res)
            print(resDict)
            db_print('Image Flash Result:%s' %json.dumps(resDict))
            sys.exit(1)

        if not DUT.dutPostActCheck(dutInstanceList,buildInstance=buildInstance,ltcheck=LTCheck,ltswcheck=LTSWCheck,cmdLocation = cmdLocation,workspace=workspace):
            resDict['res'] = False
            resDict['errors'] = [{'res':False,'error':ERROR_CODES[action]}]
            db_print('Image Flash Result:%s' %json.dumps(resDict))
            sys.exit(1)
        #add security login banner after activation
        DUT.configDUT(dutInstanceList,cmdType='banner',action='add',platform=job_name,cmdLocation = cmdLocation)

        db_print('Image Flash Result:%s' %json.dumps(resDict))
        sys.exit()

#!/usr/bin/env python3.6

#coding:utf-8

import requests, sys, re, datetime, json, time, calendar, logging, ast
from requests.auth import HTTPBasicAuth
from prettytable import PrettyTable
from argparse import ArgumentParser,ArgumentTypeError
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

URL='https://smartservice.int.nokia-sbell.com'

#def checkJobStatus(data,tp,tsID=0):
#    if tsID and len(tp)==1:
#        status = list(map(lambda x:x['currentStatus'] if x['jobName'] in tp and x['id']==tsID else None,data))
#    else:
#        status = list(map(lambda x:x['currentStatus'] if x['jobName'] in tp else None,data))
#    instantStatus = ['Running', 'oswppreparing', 'downloading', 'activating', 'initializing', 'dryrunning', 'batchrunning', 'domainrunning', 'postcleaning','Queue','CondQueue']
#    if list(set(instantStatus).intersection(set(status))):
#        return True
#    else:
#        return False

def praseTestsummary(content,data):
  sOut = content.split('\n')
  for line in sOut:
      if len(line)==0:
          continue
      elif re.search("Total tests\s+=", line):
          data['Total'] = line.split('=')[1]
      elif re.match("Failed tests\s+=", line):
          data['Fail'] = line.split('=')[1]
      elif re.match("Passed tests\s+=", line):
          data['Pass'] = line.split('=')[1]
      elif re.match("Suspended tests\s+=", line):
          data['Suspend'] = line.split('=')[1]
      elif re.match("Total TCL-ERROR\s+=", line):
          data['Error'] = line.split('=')[1]

def checkJobStatus(data,tsID=[]):
    for x in tsID:
        for k,v in x.items():
            status = list(map(lambda x:x['currentStatus'] if x['jobName'] == k and x['id'] == v else None,data))
            instantStatus = ['Running', 'oswppreparing', 'downloading', 'activating', 'initializing', 'dryrunning', 'batchrunning', 'domainrunning', 'postcleaning','Queue','CondQueue']
            if list(set(instantStatus).intersection(set(status))):
                return True
    return False

def maxTS(logFileList):
    mon = list(set(dict(logFileList).values()))
    abbr = {v: k for k,v in enumerate(calendar.month_abbr)}
    monNum = max([abbr[i] for i in mon])
    monMax = dict(enumerate(calendar.month_abbr))[monNum]
    mList = [k for k,v in dict(logFileList).items() if v == monMax]
    ts = max(mList)
    return ts

def isBoolean(v):
    if isinstance(v, bool):
        return True
    elif v.lower() in ('yes', 'true', 't', 'y', '1','no', 'false', 'f', 'n', '0'):
        return True
    else:
        return False

def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
       raise ArgumentTypeError('Boolean value expected')
       #raise AssertionError("Boolean Type Error")

#logging.basicConfig(format='%(asctime)s %(message)s',level=logging.INFO)
logging.basicConfig(level=logging.INFO,format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',datefmt='%a, %d %b %Y %H:%M:%S')

parser = ArgumentParser()
parser.add_argument("--URL", dest="URL",default=URL, help="Smart Server URL")
parser.add_argument("--buildID", dest="buildID",default='', help="build ID (eg. 60.069)")
parser.add_argument("--Release", dest="Release",default="", help="6.0")
parser.add_argument("--jobName", dest="jobName",default="", help="job Name.Comma separated if you specify multi job (eg - NFXSF_FANTG_CLOCK_II_01,NFXSF_FANTG_CLOCK_II_02)")
parser.add_argument("--Coverage", dest="Coverage",choices=['Weekly','Daily','Smoke','None','weekly','daily','smoke','none'],default="Weekly", help="Coverage")
parser.add_argument("--Datetime", dest="Datetime",default=str(datetime.datetime.utcnow().replace(microsecond=0)), help="Trigger time.default is Now")
parser.add_argument("--HostOrTarget", dest="HostOrTarget",choices=['target','host'],default="target", help="host Or target")
parser.add_argument("--domainMode", dest="domainMode",choices=['include_domain','exclude_domain','default_domain'],default="include_domain", help="Domain Mode :include_domain | exclude_domain | default_domain")
parser.add_argument("--caseMode", dest="caseMode",choices=['run_ATCs','skip_ATCs'],default="run_ATCs", help="Case Mode")
parser.add_argument("--caseFile", dest="caseFile",default="", help="Case File")
parser.add_argument("--RobotCaseList", dest="RobotCaseList",default="", help="Robot Case List")
parser.add_argument("--RobotOptions", dest="RobotOptions",default="", help="RobotOptions")
parser.add_argument("--domainType", dest="domainType",choices=['normal','Special'],default="normal", help="domainType")
parser.add_argument("--domainList", dest="domainList",default="", help="domainList")
parser.add_argument("--email_input", dest="email_input",default="", help="email_input")
parser.add_argument("--priority", dest="priority",type=str2bool,default=False, help="priority")
parser.add_argument("--Load", dest="Load",choices=['true','True','load','Load','cleanDB','noload','noLoad','false','False'],default=True, help="Load")
parser.add_argument("--webTIA", dest="webTIA",type=str2bool,default=True, help="web tia")
parser.add_argument("--triggerType", dest="triggerType",choices=['Immediate','CondQueue','Queue','Schedule','Periodic'],default="Immediate", help="triggerType")
parser.add_argument("--periodic", dest="periodic",default="0 0 * * *", help="periodic")
parser.add_argument("--rangeStart", dest="rangeStart",default="", help="rangeStart")
parser.add_argument("--endStart", dest="endStart",default="", help="endStart")
parser.add_argument("--rerun_flag", dest="rerun_flag",type=str2bool,default=False, help="rerun_flag")
parser.add_argument("--batchCommand", dest="batchCommand",default="", help="batchCommand")
parser.add_argument("--olt", dest="olt",default="", help="olt")
parser.add_argument("--ont", dest="ont",default="", help="ont")
parser.add_argument("--ontsw", dest="ontsw",default="", help="ontsw")
parser.add_argument("--custdb", dest="custdb",default="", help="custdb")
parser.add_argument("--testProduct", dest="testProduct",default="nothing", help="testProduct")
parser.add_argument("--ltbOptions", dest="ltbOptions",default="", help="ltbOptions")
parser.add_argument("--ftpType", dest="ftpType",default="Public", help="ftpType")
parser.add_argument("--clnDB", dest="clnDB",type=str2bool,default=False, help="Clean DB betwwen every domain")
parser.add_argument("--sideBuild", dest="sideBuild",default='', help="sideBuild")
parser.add_argument("--username", dest="username",default="wwang046", help="csl")
parser.add_argument("--password", dest="password",default="123456", help="password")
parser.add_argument("--testGroup", dest="testGroup",type=str2bool,default=False, help="Test Group Option")
parser.add_argument("--groupName", dest="groupName",default="", help="Test Group Name")
parser.add_argument("--filterFlag", dest="filterFlag",default="Default", help="filterFlag")
parser.add_argument("--CSTag", dest="CSTag",default="", help="CSTag")
parser.add_argument("--updateRepo", dest="updateRepo",type=str2bool,default=False, help="updateRepo")
parser.add_argument("--buildType", dest="buildType",choices=['official','LIS'],default='official', help="buildType:official or LIS")
parser.add_argument("--groupPlatformList", dest="groupPlatformList",default=[], help="Group Platform List")
parser.add_argument("--metricUser", dest="metricUser", default='', help="valid csl to be used for area batch statistics")
parser.add_argument("--Board", dest="Board", default="", help="Board for Host")
parser.add_argument("--linuxIP", dest="linuxIP", default="", help="linuxIP for Host")
parser.add_argument("--repoPath", dest="repoPath", default="", help="repoPath for Host")
parser.add_argument("--waitUntilComplete", dest="waitUntilComplete",type=str2bool, default=False, help="Wait until job completed")
parser.add_argument("--tBuild", dest="tBuild", default='', help="tBuild id")
parser.add_argument("--traceflag", dest="traceflag",type=str2bool, default=False, help="traceflag")
parser.add_argument("--ltflag", dest="ltflag",type=str2bool, default=False, help="ltflag")
parser.add_argument("--ltswflag", dest="ltswflag",type=str2bool, default=False, help="ltswflag")
parser.add_argument("--extraTar", dest="extraTar",type=str2bool, default=False, help="extraTar")
parser.add_argument("--fwdVlan", dest="fwdVlan", default='', help="ftpInfo")
parser.add_argument("--vectorType", dest="vectorType", default='', help="ftpInfo")
parser.add_argument("--standCaseInfo", dest="standCaseInfo", default='', help="ftpInfo")
parser.add_argument("--ftpInfo", dest="ftpInfo", default='', help="ftpInfo")
parser.add_argument("--purgeRepo", dest="purgeRepo",type=str2bool, default=False, help="purgeRepo")
parser.add_argument("--listDomain", dest="listDomain",type=str2bool, default=False, help="listDomain")
parser.add_argument("--featureInfo", dest="featureInfo", default='', help="featureInfo")
parser.add_argument("--updatePlugin", dest="updatePlugin",type=str2bool, default=False, help="updatePlugin")
parser.add_argument("--updateAV", dest="updateAV",type=str2bool, default=False, help="updateAV")
parser.add_argument("--avVersion", dest="avVersion", default='', help="avVersion")
parser.add_argument("--ciType", dest="ciType",choices=['perDay','perWeek','perHour'], default='perDay', help="ciType")
parser.add_argument("--scopeType", dest="scopeType",choices=['subSystem','Area','ltbLabel','Domain',''], default='', help="scopeType")
parser.add_argument("--Scope", dest="Scope", default='', help="Scope")
parser.add_argument("--Revision", dest="Revision",default='', help="Revision (eg. 1fa159b8689b)")
parser.add_argument("--triggerSource", dest="triggerSource",default='AI', help="triggerSource (eg. AI/CI)")
parser.add_argument("--sharedSetup", dest="sharedSetup",default='NO', help="sharedSetup (eg. NO/IWF)")
parser.add_argument("--selectionType", dest="selectionType",default='Board', help="selectionType (eg. 'Board')")

options = parser.parse_args()
release = options.Release
test_platform = options.jobName.split(',')
domainList = options.domainList.split(',')
email_input = options.email_input.split(',')

if not all([release,test_platform]):
    logging.info("Invalid arguments")
    logging.info("Please input at least Release & jobName...")
    sys.exit(1)

if not re.search('^([2-9]\.\d\.0[1-6]|[2-9]\.\d|\d{2}\.\d{2})$',release):
#if not re.search('^([2-9]\.\d\.0[1-6]|[2-9]\.\d)$',release):
    logging.info("Release format is incorrect :%s. should be like 6.2|6.2.01|6.2.02|20.09" % release)
    sys.exit(1)

if re.search('^\s*(pack_|packageme_)?(\d{2,4}\.\d{3}(p\d{2,4})?|latest|\d{4}\.\d{3,6}(p\d{2,4})?|\s*)\s*$',options.buildID) or options.buildID=='':
#if re.search('^\s*(pack_|packageme_)?(\d{2,4}\.\d{3}(p\d{1,4})?|latest|\s*)\s*$',options.buildID) or options.buildID=='':
    if options.buildID in ['','latest']:
        logging.info("Did not specify the build ID.will use the latest build of Release :%s" % release)
else:
    logging.info("Build ID format is incorrect :%s. should be like 62.112|6201.306|latest|6201.309p11|2009.188" % options.buildID)
    sys.exit(1)

if options.testGroup and not re.search('^[a-zA-Z0-9\-]+$',options.groupName):
    logging.info("groupName invalid :%s" % options.groupName)
    sys.exit(1)

coverage=options.Coverage
if options.Load in [True,'true','True','load','Load']:
    LoadInfo='load'
elif options.Load == 'cleanDB':
    LoadInfo='cleanDB'
else:
    LoadInfo='noload'

if options.triggerType == 'Queue':
    options.triggerType = 'CondQueue'
logging.info({key:value for key,value in vars(options).items() if key != 'password'})


userAgent="Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"

payload1 = {
        "username": options.username,
        "password": options.password
    }


payload2 = {
    'releaseID' : release,
    'buildID' : options.buildID,
    'Coverage' : coverage.capitalize(),
    'testPlatform': test_platform,
    'Date': options.Datetime,
    'hostTarget': options.HostOrTarget,
    'domainMode': options.domainMode,
    'caseMode': options.caseMode,
    'caseFile': options.caseFile,
    'robotCaseList': options.RobotCaseList,
    'robotOptions': options.RobotOptions,
    'domainType': options.domainType,
    'domainInfo': domainList,
    'emailInput': options.email_input,
    'Priority': options.priority,
    'loadInfo': LoadInfo,
    'webTIA': options.webTIA,
    'triggerType': options.triggerType,
    'Periodic': options.periodic,
    'rangeStart': options.rangeStart,
    'endStart': options.endStart,
    'rerunFlag': options.rerun_flag,
    'batchCommand': options.batchCommand,
    'OLT': options.olt,
    'ONT': options.ont,
    'ontSW': options.ontsw,
    'custDB': options.custdb,
    'clnDB': options.clnDB,
    'sideBuild': options.sideBuild,
    'testProduct': options.testProduct,
    'ltbOptions': options.ltbOptions,
    'ftpType': options.ftpType,
    'Username': options.username,
    'testGroup': options.testGroup,
    'groupName': options.groupName,
    'filterFlag': options.filterFlag,
    'CSTag': options.CSTag,
    'updateRepo': options.updateRepo,
    'buildType': options.buildType,
    'groupPlatformList': options.groupPlatformList,
    'metricUser': options.metricUser,
    'Board': options.Board.upper(),
    'linuxIP': options.linuxIP,
    'repoPath': options.repoPath,
    'tBuild': options.tBuild,
    'traceFlag': options.traceflag,
    'ltFlag': options.ltflag,
    'ltswFlag': options.ltswflag,
    'extraTar': options.extraTar,
    'ftpInfo': options.ftpInfo,
    'fwdVlan': options.fwdVlan,
    'vectorType': options.vectorType,
    'standCaseInfo': options.standCaseInfo,
    'purgeRepo': options.purgeRepo,
    'listDomain': options.listDomain,
    'featureInfo': options.featureInfo,
    'updatePlugin': options.updatePlugin,
    'updateAV': options.updateAV,
    'avVersion': options.avVersion,
    'ciType': options.ciType,
    'scopeType': options.scopeType,
    'Scope': options.Scope,
    'Revision': options.Revision,
    'triggerSource': options.triggerSource,
    'sharedSetup': options.sharedSetup,
    'selectionType': options.selectionType,
    }

header1 = {
    "Referer": URL,
    'User-Agent': userAgent
}
header2 = {
    "Referer": URL+'/Launch/',
    'User-Agent': userAgent
}

postURL1 = URL + '/api/logintest'
postURL0 = URL + '/ajax/login_session'
postURL2 = URL + '/api/launchtest'
getURL0 = URL + '/jobStatus'
client = requests.session()
client.verify = False
login = client.post(postURL1, data=payload1,headers = header1,timeout=30)

if login.status_code == 200:
    rlogin = json.loads(login.text)
    if rlogin['seq_nbr'] == 300:
        payload0 = {
                "username": options.username,
                "level": rlogin['auth_level'],
                "short_name": options.username,
                "mail": rlogin['mail'],
                "cil": rlogin['cil'],
                "timezone": 'Asia/Shanghai'
        }
        loginSess = client.post(postURL0, data=payload0,headers = header1,timeout=60)
        if loginSess.status_code == 200:
            logging.info('Username :%s Login successfully' % options.username)
            r = client.post(postURL2, data=json.dumps(payload2),headers = header2,timeout=300)
            if r.status_code == 200:
                v = json.loads(r.text)
                logging.info('v = %s' % r.text)
                if v['seq_nbr'] == 300:
                    tsID = v['tsID']
                    logging.info('launch job %s successfully' % ','.join([list(i.keys())[0] for i in tsID]))
                    logging.info('Please see your job status :%s/TestStatus/' % URL)
                    if options.waitUntilComplete:
                        time.sleep(15)
                        tsTimeout = 0
                        while True:
                            try:
                                testStatus = client.get(getURL0,verify=False, timeout=300)
                                ct = json.loads(testStatus.content)
                                data = ct['data']
                                tsL = list(filter(lambda x:x if x['id'] in [k for j in [x.values() for x in tsID] for k in j] else '',data))
                                for tsDict in tsL:
                                    jenkinsURL = tsDict['jenkinsURL']
                                    v['buildID'] = tsDict['buildID']
                                    if jenkinsURL not in ['','NA']:
                                        logging.info('Jenkins console URL : %s' % jenkinsURL)
                                CTS = checkJobStatus(data,tsID)
                            except Exception as e:
                                if tsTimeout == 0:
                                    tsTimeout = time.time() + 60*5
                                logging.info('Check Job Status exception :' + str(e))
                                if time.time() > tsTimeout:
                                    logging.info('Can not get Job status in 5 mins')
                                    break
                                else:
                                    logging.info('Wait 30 seconds and check again...')
                                    time.sleep(30)
                                    continue
                            if CTS:
                                logging.info('Job not finished.Sleep for 60 seconds...')
                                tsTimeout = 0
                                time.sleep(60)
                            else:
                                logging.info('Job finished')
                                table = PrettyTable(['platformName','buildID','Domain','Team','logUrl','resultUrl','Total','Pass','Fail','Desc','Status'])
                                for x in tsID:
                                    logging.info('tsID =%s' % tsID)
                                    rStatus,DM,Desc,tsFolder,resUrl,Team = 'NOK','','','','',''
                                    TPF = {'Total':0,'Pass':0,'Fail':0}
                                    for k,n in x.items():
                                        if k == 'Board':
                                            continue
                                        tsDL = list(filter(lambda x:x if x['id']==n else '',data))
                                        if not tsDL:
                                            logging.info('No match record. skip...')
                                            break
                                        tsDict = tsDL[0]
                                        jobNum = tsDict['jobNum']
                                        currentStatus = tsDict['currentStatus']
                                        try:
                                            teamUrl='%s/Resource/?platformName=%s&action=view' % (URL,k)
                                            payloadT = {
                                                "platform": k,
                                                "username": options.username
                                            }
                                            headerT = {
                                                "Referer": teamUrl,
                                                'User-Agent': userAgent
                                            }
                                            rInfo = client.post(URL+'/resource/view/',data=payloadT,headers = headerT,timeout=30)
                                            tInfo = json.loads(rInfo.content)
                                            TeamInfo = tInfo['resourceInfo']['Team']
                                            Team = TeamInfo if TeamInfo else 'Other'
                                            logging.info('Team = %s' % Team)
                                            logUrl = 'http://smartlab-service.int.net.nokia.com:9000/log/%s/%s/%s/' %  (Team,re.sub('pack_','',v['buildID']),k)
                                            logging.info('logUrl = %s' % logUrl)
                                            resUrl='%s/Result/?target=%s_%s' % (URL,k,jobNum)
                                            logging.info('resultUrl = %s' % resUrl)
                                            if currentStatus == 'Completed':
                                                try:
                                                    domainT = tsDict['domainT']
                                                    if domainT:
                                                        domainD = {i.split(':')[0]:i.split(':')[1] for i in domainT.split(';')}
                                                        logging.info('domainD = %s' % domainD)
                                                        for domain,timestamp in domainD.items():
                                                            tsFolder = logUrl + 'SB_Logs_' + timestamp + '_' + domain + '/'
                                                            testsummary = tsFolder + 'testsummary.log'
                                                            ret = requests.get(testsummary,timeout=60)
                                                            if ret.status_code == 200:
                                                                console = requests.get(testsummary,timeout=60).content
                                                                logging.info('####################Test summary(%s) :#######################' % domain)
                                                                logging.info(console.decode())
                                                                logging.info('###############################################################')
                                                                logging.info('Console log details :\n%s' % jenkinsURL)
                                                                logging.info('ATC log details :\n%s' % tsFolder)
                                                                logging.info('###############################################################')
                                                                DM = domain
                                                                praseTestsummary(console.decode(),TPF)
                                                                rStatus = 'OK'
                                                            else:
                                                                Desc = "No testsummary file"
                                                                logging.info('No testsummary file on Log Server :' + tsFolder)
                                                #           table.add_row([k,v['buildID'],DM,Team,tsFolder,resUrl,TPF['Total'],TPF['Pass'],TPF['Fail'],Desc,rStatus])
                                                    else:
                                                        pDict = ast.literal_eval(tsDict['Progress'])
                                                        logging.info('Progress = %s' % pDict)
                                                        timestamp = list(pDict.keys())[0]
                                                        tsFolder = logUrl + 'SB_Logs_' + timestamp + '/'
                                                        testsummary = tsFolder + 'testsummary.log'
                                                        ret = requests.get(testsummary,timeout=60)
                                                        if ret.status_code == 200:
                                                            console = requests.get(testsummary,timeout=60).content
                                                            logging.info('########################Test summary :#########################')
                                                            logging.info(console.decode())
                                                            logging.info('###############################################################')
                                                            logging.info('Console log details :\n%s' % jenkinsURL)
                                                            logging.info('ATC log details :\n%s' % tsFolder)
                                                            logging.info('###############################################################')
                                                            praseTestsummary(console.decode(),TPF)
                                                            rStatus = 'OK'
                                                        else:
                                                            Desc = "No testsummary file"
                                                            logging.info('No testsummary file on Log Server :' + tsFolder)
                                                except Exception as e:
                                                    Desc = "Get testsummary content failed"
                                                    logging.info('Get testsummary content failed :' + str(e))
                                            elif currentStatus == 'Aborted':
                                                Desc = "Job was aborted"
                                                logging.info('Fail Reason = Job was aborted')
                                            elif currentStatus == 'Incompleted':
                                                Desc = tsDict.get('Desc','')
                                                if not Desc:
                                                    Desc = 'Other failures'
                                                logging.info('Fail Reason = %s' % Desc)
                                            else:
                                                Desc = 'Job status unknown'
                                                logging.info('Job current status unknown.please check it on smartlab server')
                                            break
                                        except Exception as e:
                                            Desc = 'Get Team/logUrl/resUrl failed'
                                            logging.info('Get Team/logUrl/resUrl failed :' + str(e))
                                    table.add_row([k,v['buildID'],DM,Team,tsFolder,resUrl,TPF['Total'],TPF['Pass'],TPF['Fail'],Desc,rStatus])
                                print(table)
                                print(table.get_html_string())
                                logging.info('All tasks Completed')
                                break
                else:
                    logging.info('Launch job %s failed, Fail Reason = %s' % (test_platform,v['result']))
                    sys.exit(1)
            else:
              logging.info('Launch backend error :%s' % r.status_code)
              sys.exit(1)
        else:
            logging.info('Login session error :%s' % loginSess.status_code)
            sys.exit(1)
    else:
        logging.info('Login failed,reason :%s' % rlogin['result'])
        sys.exit(1)
else:
    logging.info('Login backend error :%s' % login.status_code)
    sys.exit(1)


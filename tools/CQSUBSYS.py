import pandas as pd
import numpy as np
from io import StringIO
from requests.auth import HTTPBasicAuth
import logging,requests
import paramiko
from optparse import OptionParser
import os, re, sys
import pickle, ftplib
from gensim import corpora, models, similarities

MEDIA_ROOT = '/root/k8s/CQSUBSYS/traceAnalyzerFiles'

def retrieveFRinfoFromCQ(ISR,username,password):
    cq_report_url = 'http://aww.sh.bel.alcatel.be/tools/dslam/cq/cgi-bin/cqReport.cgi'

    pd.set_option('expand_frame_repr', False)
    auth = HTTPBasicAuth(username, password)

   #filter_range ='''DetectedInProductRelease eq %s and Type eq FR and State in (New,Accepted)''' % ISR
    filter_range ='''PlannedRelease eq %s and Type eq FR and State in (New,Accepted)''' % ISR
    payload = {
        'type' : 'FR_IR',
        'display' : 'id,State,DetailedDescription,DetailedRCAReport,ClonedFrom.id',
        'format' : 'csv',
        'header' : 'yes',
        'maximum': 10000,
        'filter' : filter_range
        }

    r = requests.get(cq_report_url, auth=auth, params=payload)
    datastr = r.content.decode()

    if 'Invalid field reference' in datastr:
        logging.info('@@@@@@@@@@ query FR failed @@@@@@@@@@@@')
        return None
    if '401 Authorization Required' in datastr:
        logging.info('login failed, use CSL as username')
        return None
    csvbuf = StringIO(datastr)

    df = pd.read_csv(csvbuf,delimiter='\t',error_bad_lines=False)
    df = df.replace(np.nan, '', regex=True)
   #df=df.loc[(~ df['ClonedFrom.id'].str.startswith('ALU',na=False)) | (df['ClonedFrom.id'].isnull())]
    return df

def multiReplace(string, rep_dict):
    pattern = re.compile("|".join([re.escape(k) for k in list(rep_dict.keys())]), re.M)
    return pattern.sub(lambda x: rep_dict[x.group(0)], to_str(string))

def ssh2(ip,username,passwd,cmd,returnResult = False):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip,22,username,passwd,timeout=5)
        if isinstance(cmd,str) :
            cmd = [cmd]
        logging.info("======begin execute below command using ssh2======")
        logging.info("======cmd is %s======" % cmd)
        results = ''
        for m in cmd:
            transport = ssh.get_transport()
            transport.set_keepalive(15)
            channel = transport.open_session()
            channel.get_pty()
            channel.exec_command(m)
            while True:
                if channel.exit_status_ready():
                    break
                try:
                    recv = channel.recv(2048)
                   #logging.info(recv)
                    if returnResult:
                        results += recv
                except Exception as int:
                    channel.close()
        channel.close()
        transport.close()
        ssh.close()

        logging.info(('%s\tOK\n'%(ip)))
        ssh.close()
        if returnResult:
            return results
        else:
            return ''
    except Exception as e:
      logging.info(('%s\tError :%s\n'%(ip,e)))


def newReference(query0,qType='Text'):
    currentPath=os.path.abspath(os.path.dirname(__file__))
    modelPath=currentPath + '/model'
    dataPath=currentPath + '/data'
    referPath=currentPath + '/refer'
    from refer import fr2subs
    
    logging.info('Load AI Analysis Model')
    dictionary=corpora.Dictionary.load_from_text(modelPath+r'/olt_dictionary.dict')
    lsi=models.LsiModel.load(modelPath+r'/olt_lsi_mode.mo')
    index=similarities.MatrixSimilarity.load(modelPath+r'/olt_lsi_index.ind')
    tfidf=models.TfidfModel.load(modelPath+r'/olt_tfidf.ti')
    
    fr2detail={}
    f = open(referPath+r'/fr2detail.txt','rb')
    fr2detail = pickle.load(f)
    f.close()
    
    frkeylist=list(fr2detail.keys())
    fr2testcase={}
    f = open(referPath + '/fr2testcase.txt', 'rb')
    fr2testcase=pickle.load(f)
    f.close
    
    fr2subsystem=fr2subs.fr2subs
    # Analysis target data
    query = ''
    logging.info('Start Analysis')
    if qType == 'File':
        if isinstance(query0, list):
            queryfile = []
            local_tmp_dir="/var/www/html/repo/atxuser/cases/"

            for fn in query0:
                localFile = local_tmp_dir + fn
                with open(localFile, 'r') as f:
                    fileContent = f.read()
                    queryfile.append(fileContent)
            query=str(' '.join(queryfile)).strip()
    else:
        query=str(query0).strip()
    logging.info("query = %s" % query)
    regL = ['|',r'\n',r'\t',r',',r'-',r'#',r'=',r'*',r'\\',r'(',r')',r'[',r']',r'!',r'"',r'>',r'<',r': ',r'::',r'........']
    for reg in regL:
        query = query.replace(re.escape(reg),' ')
    query_bow = dictionary.doc2bow(query.lower().split())
    query_lsi = lsi[query_bow]
    sims = index[query_lsi]
    sort_sims = sorted(enumerate(sims), key=lambda item: -item[1])
    highpri=list()
    lowpri=list()
    candidatelist=list()
    for seq in range(0,150,1):
      x1 = sort_sims[seq][0]
      simvalue=sort_sims[seq][1]
      y1 = fr2subsystem[frkeylist[x1]]
      highmark=0
      for value in y1:
        if query.find(value[0:5])>-1 and str(highpri).find(value)<0:
          highmark=2
    
      if highmark==0 and y1 not in lowpri:
        for value in y1:
          if str(lowpri).find(value)<0:
            lowpri.append(y1)
      if highmark==2 and y1 not in highpri:
        for value in y1:
          if str(highpri).find(value) < 0:
            highpri.append(y1)
    
    highpri.extend(lowpri)
    candidatelist.extend(highpri)
    candidatelistnumber=len(candidatelist)
   #logging.info(("candidatelist length= %s" % len(candidatelist)))
    output =list()
    for j in range(0,candidatelistnumber,1):
      if candidatelist[j] not in output and str(candidatelist[j])!="['']":
        output.append(candidatelist[j])
    return output[0:10]

def traceAnalyzer(dfEF,dfTECT,dfTEF,FRID):
    logging.info("Start to using traceAnalyzer for :%s" % FRID)
    ret = ''
    traceAnalyzerEF = {k: f.groupby('is_in_model')['feature'].apply(lambda x:list(set(x))).to_dict() for k, f in dfEF.groupby('element')}

    traceAnalyzerTECT = dfTECT.groupby('element \\ tag(sim-value)')['TOP1','TOP2','TOP3'].apply(lambda g: list(filter(None,g.values.tolist()[0]))).to_dict()
    traceAnalyzerTEF = {k: f.groupby('is_in_model')['feature'].apply(lambda x:list(set(x))).to_dict() for k, f in dfTEF.groupby('element')}

    if any(FRID in x for x in [traceAnalyzerEF,traceAnalyzerTECT,traceAnalyzerTEF]):
        ret += r'''Analysis by 'trace analyzer' tool (accuracy is ~59%):\n'''
        if FRID in traceAnalyzerTECT:
            ret += r'         Suspicious subsystems are: ' + ','.join(traceAnalyzerTECT[FRID]) + r'\n'
        if FRID in traceAnalyzerTEF:
            if 0.0 in traceAnalyzerTEF[FRID]:
                ret += r'         It is first time that the following new traces show up:\n                     ' + r'\n                     '.join(traceAnalyzerTEF[FRID][0.0]) + r'\n'

        if FRID in traceAnalyzerEF:
            if 0.0 in traceAnalyzerEF[FRID]:
                if re.search('It is first time that the following new traces show up',ret):
                    ret += '                     ' + r'\n                     '.join(traceAnalyzerEF[FRID][0.0]) + r'\n'
                else:
                    ret += r'         It is first time that the following new traces show up:\n                     ' + r'\n                     '.join(traceAnalyzerEF[FRID][0.0]) + r'\n'
    logging.info("traceAnalyzer output = %s" % ret)
    return ret
   
def ftpReadFile(host,usr,pwd,port,filePath,filename):                                
    ftp = ftplib.FTP(host,usr,pwd)
    ftp.cwd(filePath)
    files = ftp.dir()
   
    gFile = open('%s/%s' % (MEDIA_ROOT, filename), "wb")                             
    ftp.retrbinary('RETR %s'%filename, gFile.write)                                  
    gFile.close()
    ftp.quit()
    
    gFile = open('%s/%s' % (MEDIA_ROOT, filename), "r")                              
    buff = gFile.read()                                                              
 
    gFile.close()

if __name__=='__main__':
    logging.basicConfig(format='%(asctime)s %(message)s',level=logging.INFO)
    parser = OptionParser()
    parser.add_option("-r","--Release", dest="Release",default='', help="release to be executed.  eg:ISR6101")
    parser.add_option("-c","--CQServer", dest="CQServer",default='isam-cq.web.alcatel-lucent.com', help="CQ server ip to be executed on")
    parser.add_option("-u","--username", dest="username",default='', help="username to login CQ")
    parser.add_option("-p","--passwd", dest="passwd",default='', help="password to login CQ")

    (options, args) = parser.parse_args(sys.argv[1:])
    username = options.username
    passwd = options.passwd
    CQServer = options.CQServer.strip()
    Release = options.Release.strip()
    validOptions = [CQServer,Release,username,passwd]
    
    if all(validOptions):
        df = retrieveFRinfoFromCQ(Release,username,passwd)
        logging.info("Data frame length = %s",len(df))
        logging.info("Data frame = %s",df)
        ftpReadFile('135.252.245.46','ftp','Gpon_atc01',21,'AI','element_features.csv')
        ftpReadFile('135.252.245.46','ftp','Gpon_atc01',21,'AI','task_element_contribution_topk.csv')
        ftpReadFile('135.252.245.46','ftp','Gpon_atc01',21,'AI','task_element_features.csv')

        dfEF = pd.read_csv(MEDIA_ROOT + '/element_features.csv',error_bad_lines=False)
        dfEF = dfEF.replace(np.nan, '', regex=True)

        dfTECT = pd.read_csv(MEDIA_ROOT + '/task_element_contribution_topk.csv',error_bad_lines=False)
        dfTECT = dfTECT.replace(np.nan, '', regex=True)
        dfTEF = pd.read_csv(MEDIA_ROOT + '/task_element_features.csv',error_bad_lines=False)
        dfTEF = dfTEF.replace(np.nan, '', regex=True)

        for index, row in df.iterrows():
            FRID = row["id"]
            ref = newReference(row["DetailedDescription"],'FR')
            logging.info("############################# %s #################################" % FRID)
            DetailedRCA = row["DetailedRCAReport"].strip()
            sDetailedRCA = DetailedRCA.replace('\r\n','').replace('\n','')
            traceAnalysis = traceAnalyzer(dfEF,dfTECT,dfTEF,FRID)
            RCAInfo2 = r'''Traces for Bug Fix (please fill in Traces used in bug fix and the missing ones to be implemented in domain/subsystems if any).\n\n[useful traces]:\n\n[missing traces]:\n\n------------------------------------------------------\nAI recommended subsystem:\n===\n''' + r'\n'.join([str(i) for i in ref]) + r'\n\n' + traceAnalysis
            RCAInfo = r'''Traces for Bug Fix (please fill in Traces used in bug fix and the missing ones to be implemented in domain/subsystems if any).\n\n[useful traces]:\n\n[missing traces]:\n\n------------------------------------------------------\n''' + traceAnalysis + r'\n\nAI recommended subsystem:\n===\n' + r'\n'.join([str(i) for i in ref])
            sRCAInfo = RCAInfo.replace('\\n','').replace('\n','')
            sRCAInfo2 = RCAInfo2.replace('\\n','').replace('\n','')
            if re.match(re.escape(sRCAInfo),sDetailedRCA) or re.match(re.escape(sRCAInfo2),sDetailedRCA):
                logging.info("Skip to fill")
            else:
                DetailedRCA = re.sub(r'Traces for Bug Fix \(p.*\'\](.*subsystems if any\)\.)?','',DetailedRCA,flags=re.S)
                RCAInfo = RCAInfo + r'\n\n' + DetailedRCA.replace('\n','\\n')
                logging.info("Origin RCA content = %s" % DetailedRCA)
                logging.info("%s :Start to fill \nRCAinfo = %s" % (FRID,RCAInfo))
               #CQcmd = [r'''/opt/rational/clearquest/sun5/bin/cqperl CQbatchbug.pl -u aisubsys -p welcome -a Modify -f DetailedRCAReport="%s" -f NoEmailForThisAction="Y" %s''' % (RCAInfo, FRID)]
                CQcmd = [r'''/opt/rational/clearquest/sun5/bin/cqperl /ap/wwwdata/tools/dslam/cq/CQbatchbug.pl -u aisubsys -p welcome -a Modify -f DetailedRCAReport="%s" -f NoEmailForThisAction=Y %s''' % (RCAInfo, FRID)]
                ssh2(CQServer,'cqadm','',CQcmd)
                logging.info("%s :End to fill" % FRID)
            logging.info("############################# %s #################################\n" % FRID)
    else:
        logging.info("Invalid arguments")
        logging.info("Please input Release & username & password...") 

import os, re, sys, time
from io import StringIO
import pandas as pd
import numpy as np
import logging,requests,xlwt
from optparse import OptionParser
from requests.auth import HTTPBasicAuth

def getFrInfoByField(FRs,field,user,passwd):
    url = 'http://aww.sh.bel.alcatel.be/tools/dslam/cq/cgi-bin/cqReport.cgi'
    FRs = FRs if isinstance(FRs,list) else FRs.split(',')
    validFRs=[x for x in FRs if re.match(r'ALU\d{8}',x)]
    unknownFRs=[x for x in FRs if not re.match(r'ALU\d{8}',x)]
    logging.debug('validFRs=%s' % validFRs)
    logging.debug('unknownFRs=%s' % unknownFRs)
    if not validFRs:
        df = pd.DataFrame(columns=field.split(','))
    else:
        filter_id = '''id in (%s)''' % ','.join(validFRs),
        payload = {'type' : 'FR_IR',
              'display' : field,
              'format' : 'csv',
              'header' : 'yes',
              'filter' : filter_id }
        auth = HTTPBasicAuth(user, passwd)
        r = requests.get(url, auth=auth, params=payload)
        logging.info(r.url)
        logging.info(r.content.decode('utf-8'))
        datastr = r.content.decode()
        if 'Invalid field reference' in datastr:
            logging.info('@@@@@@@@@@ query FR failed for filter %s @@@@@@@@@@@@' % filter_id)

        if '401 Authorization Required' in datastr:
            logging.error('login failed, use CIL as username')
        
        csvbuf = StringIO(datastr)
        logging.debug('csvbuf = %s' % csvbuf)
        df = pd.read_csv(csvbuf,sep='\t',error_bad_lines=False,dtype='object')

    for i in unknownFRs:
        df=df.append({'id': i}, ignore_index=True)
    df = df.replace(np.nan, '', regex=True)
    logging.debug('df=%s' % df)
    return df


if __name__=='__main__':
    logging.basicConfig(format='%(asctime)s %(levelname)s %(module)s:%(lineno)d | %(message)s',level=logging.INFO)
   #logging.basicConfig(format='%(asctime)s %(message)s',level=logging.INFO)

    parser = OptionParser()
    parser.add_option("-i","--FR", dest="FR",default='', help="FR list")
    parser.add_option("-f","--field", dest="field",default='id,BriefDescription,DetailedDescription', help="FR field")
    parser.add_option("-u","--username", dest="username",default='', help="CSL")
    parser.add_option("-p","--passwd", dest="passwd",default='', help="Password")

    (options, args) = parser.parse_args(sys.argv[1:])
    username = options.username
    passwd = options.passwd
    FRs = options.FR.strip()
    field = options.field.strip()
    validOptions = [FRs,field,username,passwd]
    if all(validOptions):
        df = getFrInfoByField(FRs,field,username,passwd)
        filePrefix = username.replace(' ','_') + '_' + str(time.strftime('%y%m%d%H%M%S',time.localtime(time.time())))
        excelNewFile = filePrefix + r'.xls'
        writer = pd.ExcelWriter(excelNewFile)
        df.to_excel(writer, sheet_name='FR Desc')
        writer.save()
        cmd = "sshpass -p 'asbasb' scp -o StrictHostKeyChecking=no %s root@135.252.245.46:/ftp/FRStatistics/" % excelNewFile
        logging.debug('cmd=%s' % cmd)
        ret_code = os.system(cmd)
        logging.debug('cmd return value = %s' % ret_code)
        frReportExcel = 'http://135.252.245.46/GPON/FRStatistics/' + os.path.basename(excelNewFile)
    else:
        logging.info("Invalid arguments")
        logging.info("Please input Release & username & password...")

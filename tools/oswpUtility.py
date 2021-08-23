#! /usr/bin/python
# coding:utf-8
# Author: Wang Weiwei <Weiwei.Wang@alcatel-sbell.com.cn>

import ftplib
import tarfile
import time
import re
import os
import sys
import commands
from urlDaily import *
from optparse import OptionParser
import copy
#import yaml
import shutil
#HOST = '135.251.206.97'
REMOTEHOST = '172.21.128.21'
LOCAL_LOAD_PATH = '/tftpboot/atx/loads'
DIRN = '/loads'
PUBLIC_DAILY_BUILD_SERVER = 'http:aww.dsl.alcatel.be/ftp/pub/outgoing/ESAM/DAILY/'
BUILD_ID_MAP_FILE = 'BuildIDMapping.yaml'


def ssh_scp_get(**params):
    try:
        import paramiko
    except Exception:
        db_print('--Host scp:XXXX need paramiko module on tftp/http server, fail to import python lib paramiko')
    ip = params.setdefault('ip','127.0.0.1')
    username = params.setdefault('username','atxuser')
    pazwd = params.setdefault('password','alcatel01')
    port = int(params.setdefault('port',22))
    timeout = params.setdefault('timeout',5)
    local = params.setdefault('local','~')
    remote = params.setdefault('remote','~')
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip,port,username,pazwd,timeout=timeout)
    sftp = paramiko.SFTPClient.from_transport(ssh.get_transport())
    sftp.get(remote,local) 


def db_print(printStr, debugType="normal"):
    if debugType == "recv":
        print ("<<<" + printStr)
    elif debugType == "send":
        print (">>>" + printStr)
    else:
        print ("---" + printStr)


def build_to_num(argument):

    a = {
        '51': 850,
        '52': 950,
        '53': 950,
        '54': 1050,
        '55': 1200,
        '56': 1400,
        '57': 1650,
        '58': 1900,
        '59': 2000,
        '60': 2000,
        '61': 2300,
        '62': 2500
    }
    return a.get(argument, 1800)


def getdirsize(dir):
    size = 0L
    for root, dirs, files in os.walk(dir):
        size += sum([os.path.getsize(os.path.join(root, name))
                     for name in files])
    return size


def _existsBuildLocal(build, destDir='/tftpboot', tarOnly=False):
    #build for normal tar is just build id, for extra tar, it is tar name
    #two kinds of input like 62.478 or SD_62.478.tar ,lightspan_62.478.tar
    if '.tar' in build:
        tarFile = build
    else:
        tarFile = "SD_%s.tar" % build
    build = build.replace('SD_','').replace('lightspan_','').replace('.tar','')
    b = build.split('.', 1)
    i1 = b[0][0:2]
    i2 = b[1][-3:]
    if re.search('p',i2):
        i2=i2.split('p')[0]    
    os.chdir(destDir)

    numsize = build_to_num(i1)

    
    print('main release=%s numsize=%s' % (i1, numsize))
    #for extra tar, the tar file name is used here
    if tarOnly:
        tarReady = False
        if os.path.exists(tarFile):
            filesize = os.path.getsize(tarFile)
            if re.search(r'^ZAGRAA',tarFile):
                filesize = filesize / 1024 / 1024 * 10
            elif re.search(r'\.extra\.tar$',tarFile):
                if b[0] > '4000':
                    #legacy
                    filesize = filesize / 1024 / 1024 * 10
                else:
                    #normal tar
                    filesize = filesize / 1024 / 1024 * 10 * 10
            else:
                filesize = filesize / 1024 / 1024
            if filesize > numsize and isTarComplete(destDir, tarFile):
                db_print("extra tar %s exits" % tarFile)
                tarReady = True
            else:
                time.sleep(15)
                #filesize2 = getdirsize('SD_%s' % build)
                filesize2 = os.path.getsize(tarFile)
                if filesize2 != filesize:
                    db_print(
                        "Already has Job downloading the OSWP extra tar,Wait and skip download...")
                    time.sleep(1200)
                    return True
                else:
                    db_print(
                        "wrong format local extra file,starting to download new image...")
                    return False
        return tarReady
    # for normal tar check
    if os.path.exists('L6GPAA%s.%s' % (i1, i2)) and os.path.exists('l6gpaa%s.%s' % (i1, i2)):
        #    if os.path.exists('L6GPAA%s.%s' % (i1,i2)):
        db_print("L6GPAA.. file exists,check SD file size")
        filesize = getdirsize('SD_%s' % build)
        db_print('There are %.2f Mb in SD_%s' %
                 (filesize / 1024 / 1024, build))
        #print('numsize is %s' % numsize)
        #print('/tftpboot/SD_%s/L6GQAA%s.%s' % (build, i1, i2))
        #print(os.path.exists('/tftpboot/SD_%s/L6GQAA%s.%s' % (build, i1, i2)))
        if (filesize / 1024 / 1024) > numsize and os.path.exists('/tftpboot/SD_%s/L6GQAA%s.%s' % (build, i1, i2)):
            db_print("skip download file exists")
            return True
        else:
            time.sleep(15)
            filesize2 = getdirsize('SD_%s' % build)
            if filesize2 != filesize:
                db_print(
                    "Already has Job downloading the OSWP,Wait and skip download...")
                time.sleep(1200)
                return True
            else:
                db_print(
                    "wrong format local file,starting to download new image...")
                return False
    else:
        return False


dict_m_d_map = {'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04', 'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08', 'Sep': '09', 'Oct': '10',
                'Nov': '11', 'Dec': '12'}


def _findLocalBuild(ver, **dic):
    (ver1, ver2) = ver.split('.')
    if not dic.has_key(ver1):
        return False
    else:
        oswpList = dic[ver1]
        result = False
        for oswp in oswpList:
            if oswp == ver2:
                result = True
                break
        return result

# PUB_SHA_HOST='ftp:135.251.206.97:/ftpserver:asblab:asblab'
# PUB_IND_HOST='ftp:172.21.128.21:'


def _downloadBuild(build_prot, tar_file, build_dir, dest_dir, ver, host_ip, ftp_user, ftp_pazwd):
    '''
    dest_dir : e.g. /tftpboot/SD_51.045
    return a list if fail or else empty list
    '''
    db_print('Connected to ftp server"%s"' % host_ip)
    downloadlist = [tar_file]
    if build_prot in ['ftp']:
        try:
            f = ftplib.FTP(host_ip)
        except Exception as inst:
            db_print('Cannot connect to ftp server"%s" with %s' %
                     (host_ip, inst))
            db_print(
                'check build from %s failure,retry other build source' % host_ip)
            return False
        db_print('Connected to ftp server"%s"' % host_ip)
        try:
            f.login(ftp_user, ftp_pazwd)
        except Exception as inst:
            db_print('login failed:%s' % inst)
            f.quit()
            return False
        db_print('login sucessfully')

        try:
            f.cwd(build_dir)
        except ftplib.error_perm:
            db_print('failed to listed files')
            db_print(
                'check build from %s failure,retry other build source' % host_ip)
            f.quit()
            return False
        try:
            os.chdir(dest_dir)
            f.set_pasv(0)
            for FILE in downloadlist:
                db_print(FILE)
                db_print('Starting to download build, Please wait ...')
                fp = open(FILE, 'wb')
                f.retrbinary('RETR ' + FILE, fp.write, 1024)
                db_print('file"%s"download successfully' % FILE)

        except Exception as inst:
            db_print('cannot read"%s" from ftpserver retry from urlwebpage:%s' % (FILE,inst))
            f.quit()
            #if not file,no need to unlink
            #os.unlink(FILE)
            return False
        f.quit()
    elif build_prot in ['http','https']:
        os.chdir(dest_dir)
        if not (build_dir.startswith('http:') and  build_dir.startswith('https:')):
            build_dir = build_prot + '://' + build_dir
        try:
            for FILE in downloadlist:
                db_print(FILE)
                db_print('Starting to download build, Please wait ...')
                db_print("build_dir:%s" %build_dir)
                db_print("dest_dir:%s"  %dest_dir)
                result = subprocess.Popen('/bin/ping -c 3 aww.dsl.alcatel.be', stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True).communicate()
                print(result)
                downloadBuild(FILE, build_dir, 6, dest_dir)
                time.sleep(10)
                db_print('file"%s"download successfully' % FILE)
        except Exception as inst:
            db_print(
                'cannot retrieve "%s" from urlwebpage retry from remoteserver:%s' % (FILE,inst))
            return False
    elif build_prot in ['scp','sftp']:
        try:
            for FILE in downloadlist:
                remote = build_dir + '/' + FILE
                local = dest_dir + '/' + FILE
                ssh_scp_get(ip=host_ip,username=ftp_user,password=ftp_pazwd,local=local,remote=remote,timeout=1800)
                db_print('file"%s"download successfully' % FILE)
        except Exception as inst:
            db_print('fail to scp tar file:%s' %inst)
    else:
        db_print('un supported protocol type:%s' % build_prot)
        return False
    return True


def _parseBuildInfo(build_info):
    tmpListHost = build_info.split(':', 1)
    buildProt = ''
    DIRN = ''
    HOST = ''
    ftp_user = ''
    ftp_pazwd = ''
    if len(tmpListHost) < 2:
        db_print("wrong build server without protocol")
        db_print("quit")
        return [buildProt, DIRN, HOST, ftp_user, ftp_pazwd]
    # change FTP to be ftp/sftp/http/https
    buildProt = tmpListHost[0].lower()
    if buildProt in ['http', 'https']:
        tmpListHost[1] = re.sub(r'^http[s]?\:\/\/','',tmpListHost[1])
        tmpListPath = tmpListHost[1].split(':')
        DIRN = tmpListPath[0]
        if len(tmpListPath) >=2:
            if tmpListPath[1]:
                 DIRN = DIRN + '/' + tmpListPath[1].strip()
        print("http path is%s" %DIRN)
    elif buildProt in ['ftp','scp']:
        tmpListBuild = tmpListHost[1].split(':')
        HOST = tmpListBuild[0]
        DIRN = tmpListBuild[1]
        if len(tmpListBuild) > 2:
            ftp_user = tmpListBuild[2]
            ftp_pazwd = tmpListBuild[3]
        else:
            if buildProt == 'ftp' :
                ftp_user = 'anonymous'
                ftp_pazwd = 'anonymous'
            else :
                ftp_user = 'atxuser'
                ftp_pazwd = 'alcatel01'
    elif buildProt in ['sftp']:
        tmpListBuild = tmpListHost[1].split(':')
        HOST = tmpListBuild[0]
        DIRN = tmpListBuild[1]
        if len(tmpListBuild) > 2:
            ftp_user = tmpListBuild[2]
            ftp_pazwd = tmpListBuild[3]
        else:
            ftp_user = 'anonymous'
            ftp_pazwd = 'anonymous'
    else:
        db_print("wrong build server definition")
        buildProt = ''
        return [buildProt, DIRN, HOST, ftp_user, ftp_pazwd]
    return [buildProt, DIRN, HOST, ftp_user, ftp_pazwd]


def prepareOSWP(ver, serverip, destDir='/tftpboot', extraTar=None, HOST='ftp:135.251.206.97:/ftpserver/loads:asblab:asblab', buildType='official',dr4Flag = False):
    #m_HOST = re.search('([\d\.:]+):(.*?):(\w+):(.*)$',HOST)
    # if m_HOST:
    #    HOST = str(m_HOST.group(1))
    #    ftp_user = str(m_HOST.group(3))
    #    ftp_pazwd = str(m_HOST.group(4))
    #    DIRN = str(m_HOST.group(2))
    if HOST == '135.251.206.97':
        HOST = 'ftp:135.251.206.97:/ftpserver/loads:asblab:asblab'
    (buildProt, DIRN, host_ip, ftp_user, ftp_pazwd) = _parseBuildInfo(HOST)
    print(buildProt, DIRN, host_ip, ftp_user, ftp_pazwd)
    if not any([buildProt, DIRN, host_ip, ftp_user, ftp_pazwd]):
        db_print("build server infomation parsing failure")
        return False
    tarFileReady = False
    # LIS build validations
    if buildType == 'LIS':
        platTimestamp = destDir.split('/')[2]
        oam_ip = platTimestamp.split('_')[0]
        #db_print('LIS DIRECTORY: %s' % destDir)
        #db_print('LIS TIMESTAMP: %s' % platTimestamp)
        
    b = ver.split('.')
    i1 = b[0][0:2]
    i3 = b[1]
    if re.search('p',i3):
        i3=i3.split('p')[0]
    
    if not destDir:
        destDir = '/tftpboot'
    if extraTar:
        if not _existsBuildLocal(extraTar, destDir, True):
            retryNum = 0
            maxRetry = 5
            while retryNum < maxRetry:
                _downloadBuild(buildProt, extraTar,DIRN, destDir, ver, host_ip, ftp_user, ftp_pazwd)
                if not isTarComplete(destDir, extraTar):
                    db_print("tar file on build server is not complete yet, wait for 300s")
                    time.sleep(300)
                    retryNum = retryNum + 1
                else:
                    copyQualityTar(destDir, extraTar,dr4Flag)
                    return True
            return False
        else:
            return True
        return True
    
    #moswaMigrVer = i1 + '.' + i3
    migrRes = False
    moswaMigrVer=ver
    if b[0] > '4000' and b[0] < '6204':      
        if not _existsBuildLocal('ZAGRAA' + moswaMigrVer  + '.tar', destDir, True):
            migrRes = _downloadBuild(buildProt, 'ZAGRAA' + moswaMigrVer + '.tar',
                           DIRN, destDir, ver, host_ip, ftp_user, ftp_pazwd)
    # below is for normal tar file
    if _existsBuildLocal(ver, destDir):
        return True
    # try:
    #    fileLoads = '%s/SD_%s.tar' %(LOCAL_LOAD_PATH,ver)
    #    if os.path.exists(fileLoads) and os.path.getsize(fileLoads) >= 1221281280:
    #        tarFileReady = True
    # except Exception as inst:
    #    db_print('check file with exception:%s and retry from other ftp source' %inst)

    # if tarFileReady:
    #    os.system("tar -vxf %s" % fileLoads)
    #    db_print('all files download successfully')
    #    return True

    os.chdir(destDir)
    b = ver.split('.')
    i1 = b[0][0:2]

    i2 = b[1]
    if re.search('p',i2):
        i2=i2.split('p')[0]
    #considering new LSR impact, use highest 3 digits
    i2 = i2[0:3]
    fileModeChg = ''

    if buildType == 'official':
        if os.path.exists('SD_%s' % ver):
            __import__('shutil').rmtree('SD_%s' % ver)
            os.system("rm -rf L6GPAA%s.%s" % (i1, i2))
            os.system("rm -rf l6gpaa%s.%s" % (i1, i2))
            os.system("rm -rf SD_%s" % ver)
            os.system("rm -rf L6GPAB%s.%s" % (i1, i2))
            os.system("rm -rf L6GPAC%s.%s" % (i1, i2))
            os.system("rm -rf L6GPAE%s.%s" % (i1, i2))
            os.system("rm -rf L6GPAF%s.%s" % (i1, i2))
            os.system("rm -rf L6GPAG%s.%s" % (i1, i2))
            os.system("rm -rf L6GPAH%s.%s" % (i1, i2))
            os.system("rm -rf L6GPAD%s.%s" % (i1, i2))
            os.system("rm -rf L6GPAJ%s.%s" % (i1, i2))

        fd = open('L6GPAA%s.%s' % (i1, i2), "w+")        
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAA%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines(
            '   ASAM-CORE    : SD_%s/L6GQAA%s.%s %s 0.0.0.0;\n' % (ver, i1, i2, serverip))
        fd.writelines("END\n")
        fd.close()
        fileModeChg += ' ' + destDir + '/' + 'L6GPAA%s.%s' % (i1, i2)
        fd2 = open('l6gpaa%s.%s' % (i1, i2), "w+")
        fd2.writelines("OVERALL-DESCRIPTOR-FILE L6GPAA%s.%s\n\n" % (i1, i2))
        fd2.writelines("BEGIN\n\n")
        fd2.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd2.writelines(
            '   ASAM-CORE    : SD_%s/L6GQAA%s.%s %s 0.0.0.0;\n' % (ver, i1, i2, serverip))
        fd2.writelines("END\n")
        fd2.close()
        fileModeChg += ' ' + destDir + '/' + 'l6gpaa%s.%s' % (i1, i2)
        fd = open('L6GPAB%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAB%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines(
            '   ASAM-CORE    : SD_%s/L6GQAB%s.%s %s 0.0.0.0;\n' % (ver, i1, i2, serverip))
        fd.writelines("END\n")
        fd.close()
        fileModeChg += ' ' + destDir + '/' + 'L6GPAB%s.%s' % (i1, i2)
        fd = open('L6GPAC%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAC%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines(
            '   ASAM-CORE    : SD_%s/L6GQAC%s.%s %s 0.0.0.0;\n' % (ver, i1, i2, serverip))
        fd.writelines("END\n")
        fd.close()
        fileModeChg += ' ' + destDir + '/' + 'L6GPAC%s.%s' % (i1, i2)
        fd = open('L6GPAE%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAE%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines(
            '   ASAM-CORE    : SD_%s/L6GQAE%s.%s %s 0.0.0.0;\n' % (ver, i1, i2, serverip))
        fd.writelines("END\n")
        fileModeChg += ' ' + destDir + '/' + 'L6GPAE%s.%s' % (i1, i2)
        fd = open('L6GPAF%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAF%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines(
            '   ASAM-CORE    : SD_%s/L6GQAF%s.%s %s 0.0.0.0;\n' % (ver, i1, i2, serverip))
        fd.writelines("END\n")
        fileModeChg += ' ' + destDir + '/' + 'L6GPAF%s.%s' % (i1, i2)
        fd = open('L6GPAG%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAG%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines(
            '   ASAM-CORE    : SD_%s/L6GQAG%s.%s %s 0.0.0.0;\n' % (ver, i1, i2, serverip))
        fd.writelines("END\n")
        fileModeChg += ' ' + destDir + '/' + 'L6GPAG%s.%s' % (i1, i2)
        fd = open('L6GPAH%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAH%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines(
            '   ASAM-CORE    : SD_%s/L6GQAH%s.%s %s 0.0.0.0;\n' % (ver, i1, i2, serverip))
        fd.writelines("END\n")
        fileModeChg += ' ' + destDir + '/' + 'L6GPAH%s.%s' % (i1, i2)
        fd = open('L6GPAD%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAD%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines(
            '   ASAM-CORE    : SD_%s/L6GQAD%s.%s %s 0.0.0.0;\n' % (ver, i1, i2, serverip))
        fd.writelines("END\n")
        fileModeChg += ' ' + destDir + '/' + 'L6GPAD%s.%s' % (i1, i2)
        fd = open('L6GPAI%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAI%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines(
            '   ASAM-CORE    : SD_%s/L6GQAI%s.%s %s 0.0.0.0;\n' % (ver, i1, i2, serverip))
        fd.writelines("END\n")
        fd.close()
        fileModeChg += ' ' + destDir + '/' + 'L6GPAI%s.%s' % (i1, i2)
        fd = open('L6GPAJ%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAJ%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines(
            '   ASAM-CORE    : SD_%s/L6GQAJ%s.%s %s 0.0.0.0;\n' % (ver, i1, i2, serverip))
        fd.writelines("END\n")
        fd.close()
        fileModeChg += ' ' + destDir + '/' + 'L6GPAJ%s.%s' % (i1, i2)
        cmd = 'chmod 666%s' %fileModeChg
        db_print(cmd)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        db_print(result)
        if migrRes:
            try:
                moswaMigrTar = 'ZAGRAA%s.tar' %moswaMigrVer
                t = tarfile.open(moswaMigrTar)
                t.extractall()
                #os.remove(moswaMigrTar)
            except Exception as inst:
                db_print("handle moswa nt migration tar file failure:%s" %inst)
                
    os.chdir(destDir)
    Dir = 'SD_%s' % ver
    os.mkdir(Dir)
    os.chdir(destDir + '/' + Dir)

    retryNum = 0
    maxRetry = 5
    while retryNum < maxRetry:
        if not _downloadBuild(buildProt, 'SD_' + ver + '.tar', DIRN, destDir + '/' + Dir, ver, host_ip, ftp_user, ftp_pazwd):
            db_print("first try faiure")
            if not PUBLIC_DAILY_BUILD_SERVER in HOST:
                app_DIRN=''
                #if 'packageme_' in DIRN:
                #    app_DIRN = 'packageme_%s' %ver 
                (buildProt, DIRN, host_ip, ftp_user, ftp_pazwd) = _parseBuildInfo(
                    PUBLIC_DAILY_BUILD_SERVER)
                #if app_DIRN:
                #    DIRN = DIRN + '/' + app_DIRN
                
                if not _downloadBuild(buildProt, 'SD_' + ver + '.tar', DIRN, destDir + '/' + Dir, ver, host_ip, ftp_user, ftp_pazwd):
                    db_print("retry public daily build url download failure")
                    return False
            else:
                db_print("retry public faiure")
                db_print("download failure")
                return False
        if not isTarComplete(destDir + '/' + Dir, 'SD_' + ver + '.tar'):
            db_print("tar file on build server is not complete yet, wait for 300s")
            time.sleep(300)
            retryNum = retryNum + 1
        else:
            #SD_61.127.tar will be under /tftpboot/SD_61.127
            copyQualityTar(destDir, ver,dr4Flag)
            db_print("tar file is complete,removing tar files")
            try:
                os.chdir(destDir + '/' + Dir)
                t = tarfile.open('SD_' + ver + '.tar')
                t.extractall()
                os.remove('SD_' + ver + '.tar')
                os.chmod(destDir + '/' + Dir,0755)
            except Exception as inst:
                db_print(
                    "handle oswp tar file and extract failure with :%s" % inst)
                return False
            break
    if retryNum >= maxRetry:
        db_print("download failure")
        return False

    os.chdir(destDir)

    if buildType == 'LIS':
        newDir = destDir + '/' + Dir
        test_cmd = 'ls' + ' ' + newDir + ' ' + '|' + ' ' + 'grep' + ' ' + 'L6GQA'
        status, new_ver = commands.getstatusoutput(test_cmd)
        if not new_ver:
            print("no sw index file inside")
            return False
        sw_index_list = new_ver.split('\n')
        #out = new_ver.split('.')
        out = sw_index_list[0].split('.')
        i3 = out[0][6:8]
        i4 = out[1]
        fd = open('L6GPAA%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAA%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines('   ASAM-CORE    : %s/SD_%s/L6GQAA%s.%s %s 0.0.0.0;\n' %
                      (platTimestamp, ver, i3, i4, serverip))
        fd.writelines("END\n")
        fd.close()
        fileModeChg += ' ' + destDir + '/' + 'L6GPAA%s.%s' % (i1, i2)
        fd2 = open('l6gpaa%s.%s' % (i1, i2), "w+")
        fd2.writelines("OVERALL-DESCRIPTOR-FILE L6GPAA%s.%s\n\n" % (i1, i2))
        fd2.writelines("BEGIN\n\n")
        fd2.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd2.writelines('   ASAM-CORE    : %s/SD_%s/L6GQAA%s.%s %s 0.0.0.0;\n' %
                       (platTimestamp, ver, i3, i4, serverip))
        fd2.writelines("END\n")
        fd2.close()
        fileModeChg += ' ' + destDir + '/' + 'l6gpaa%s.%s' % (i1, i2)
        fd = open('L6GPAB%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAB%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines('   ASAM-CORE    : %s/SD_%s/L6GQAB%s.%s %s 0.0.0.0;\n' %
                      (platTimestamp, ver, i3, i4, serverip))
        fd.writelines("END\n")
        fd.close()
        fileModeChg += ' ' + destDir + '/' + 'L6GPAB%s.%s' % (i1, i2)
        fd = open('L6GPAC%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAC%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines('   ASAM-CORE    : %s/SD_%s/L6GQAC%s.%s %s 0.0.0.0;\n' %
                      (platTimestamp, ver, i3, i4, serverip))
        fd.writelines("END\n")
        fd.close()
        fileModeChg += ' ' + destDir + '/' + 'L6GPAC%s.%s' % (i1, i2)
        fd = open('L6GPAE%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAE%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines('   ASAM-CORE    : %s/SD_%s/L6GQAE%s.%s %s 0.0.0.0;\n' %
                      (platTimestamp, ver, i3, i4, serverip))
        fd.writelines("END\n")
        fileModeChg += ' ' + destDir + '/' + 'L6GPAE%s.%s' % (i1, i2)
        fd = open('L6GPAF%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAF%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines('   ASAM-CORE    : %s/SD_%s/L6GQAF%s.%s %s 0.0.0.0;\n' %
                      (platTimestamp, ver, i3, i4, serverip))
        fd.writelines("END\n")
        fd.close()
        fileModeChg += ' ' + destDir + '/' + 'L6GPAF%s.%s' % (i1, i2)
        fd = open('L6GPAG%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAG%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines('   ASAM-CORE    : %s/SD_%s/L6GQAG%s.%s %s 0.0.0.0;\n' %
                      (platTimestamp, ver, i3, i4, serverip))
        fd.writelines("END\n")
        fd.close()
        fileModeChg += ' ' + destDir + '/' + 'L6GPAG%s.%s' % (i1, i2)
        fd = open('L6GPAH%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAH%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines('   ASAM-CORE    : %s/SD_%s/L6GQAH%s.%s %s 0.0.0.0;\n' %
                      (platTimestamp, ver, i3, i4, serverip))
        fd.writelines("END\n")
        fd.close()
        fileModeChg += ' ' + destDir + '/' + 'L6GPAH%s.%s' % (i1, i2)
        fd = open('L6GPAD%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAD%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines('   ASAM-CORE    : %s/SD_%s/L6GQAD%s.%s %s 0.0.0.0;\n' %
                      (platTimestamp, ver, i3, i4, serverip))
        fd.writelines("END\n")
        fd.close()
        fileModeChg += ' ' + destDir + '/' + 'L6GPAD%s.%s' % (i1, i2)
        fd = open('L6GPAI%s.%s' % (i1, i2), "w+")
        fd.writelines("OVERALL-DESCRIPTOR-FILE L6GPAI%s.%s\n\n" % (i1, i2))
        fd.writelines("BEGIN\n\n")
        fd.writelines("   SYNTAX-VERSION : 02.00;\n")
        fd.writelines('   ASAM-CORE    : %s/SD_%s/L6GQAI%s.%s %s 0.0.0.0;\n' %
                      (platTimestamp, ver, i3, i4, serverip))
        fd.writelines("END\n")
        fd.close()
        fileModeChg += ' ' + destDir + '/' + 'L6GPAI%s.%s' % (i1, i2)
        cmd = 'chmod 666%s' %fileModeChg
        db_print(cmd)
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        db_print(result)
    #else:
    #    copyQualityBuild(destDir, ver,dr4Flag)
    return True


def isTarComplete(tarDir, tarFile):
    cmd = 'tar -tf %s/%s' % (tarDir, tarFile)
    result = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, shell=True).communicate()
    # tar -tf will return Error is not recoverable error
    # db_print(str(result))
    if len(result) == 2 and 'Error is not recoverable' in result[1]:
        return False
    else:
        return True

#destDir is not with SD_6101.478 directory
#for extra tar, it is located in /tftpboot directly
#for normal tar,it is located in /tftpboot/SD_6101.478 
def copyQualityTar(destDir, ver,dr4Flag):
    if dr4Flag:
        try:
            os.chdir(destDir)
            dr4_dir = destDir + '/DR4'
            if not os.path.exists(dr4_dir):
                os.mkdir(dr4_dir)
            tarfile = 'SD_' + ver + '.tar'
            if 'extra' in ver:
                srcFile = os.path.join(destDir, tarfile)
            else:
                srcFile = os.path.join(destDir, 'SD_' + ver,tarfile)
            destFile = os.path.join(dr4_dir, tarfile)
            shutil.copy(srcFile, destFile)
        except Exception as inst:
            db_print('copy p7 build failed with:%s' % inst)
        db_print('copy p7 build:%s successfully to %s' % (tarfile, dr4_dir))

def copyQualityBuild(destDir,ver,dr4Flag):
    if dr4Flag:
        try:
            os.chdir(destDir)
            dr4_dir = destDir + '/DR4'
            if not os.path.exists(dr4_dir):
                os.mkdir(dr4_dir)
            tarfile = 'SD_' + ver
            srcDir = os.path.join(destDir, tarfile)
            db_print("copy build files to DR4")
            cmd = 'copy -rf %s %s' %(srcDir,dr4_dir)
            result = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, shell=True).communicate()
            db_print(str(result))
            cmd = 'copy -rf %s/?6??%s %s' %(destDir,ver,dr4_dir)
            result = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, shell=True).communicate()
            db_print(str(result))
        except Exception as inst:
            db_print('copy p7 build failed with:%s' % inst)
        db_print('copy p7 build:%s successfully to %s' % (tarfile, dr4_dir))

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("--action", dest="action",
                      default='', help="oswp action")
    parser.add_option("--build", dest="build", default='',
                      help="oswo build version")
    parser.add_option("--serverip", dest="serverip",
                      default='', help="serverip")
    parser.add_option("--extraTar", dest="extraTar",
                      default='', help="used to pass -K /tftpboot/atx/loads/5601.472.extra.tar")
    parser.add_option("--destDir", dest="destDir", default='', help="destDir")
    parser.add_option("--Host", dest="Host",
                      default='135.251.206.97', help="Host")
    parser.add_option("--build_type", dest="build_type",
                      default='official', help="build_type")
    parser.add_option("--dr4", dest="dr4Flag",action="store_true",
                      default=False, help="means store dr4 build")

    (options, args) = parser.parse_args(sys.argv[1:])
    prepareOSWP(options.build, options.serverip, options.destDir,
                options.extraTar, options.Host, options.build_type,options.dr4Flag)

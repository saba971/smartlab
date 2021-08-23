#!/usr/bin/env python
""" 
    The script for upgrading oswp using netconf yang  
    
    INPUT FROMAT: ./sw_update.py \
    --logDirectory /tftpboot/atx/atxuser/SB_Logs_08032016-113020 \
    --ip  135.251.247.198 \
    --build SD_55.797p0.tar

    ${ROBOTREPO}/ULKS/MOSWA/NCY_USER_KW/sw_update.py -l /tftpboot/atx/atxuser/SB_Logs_08032016-113020 -i 135.251.247.198 -b SD_55.797p0.tar

    --logDirectory: the directory to write log
    --ip:  DUT OAM ip
    --build:  the tar file name of the updated build 

Author:  
zhou jin 	Developed
2016.8
"""

import os, re, sys, getopt, time , logging
#import pexpect
import subprocess
if 'ROBOTREPO' in os.environ:
    lib_path = os.environ['ROBOTREPO'] +'/LIBS/COM_NETCONF'
else:
    lib_path = '/repo/atxuser/robot/LIBS/COM_NETCONF'
    print ("environment varialbe ROBOTREPO not found,fall back to /repo/atxuser/robot")
if lib_path not in sys.path:
    sys.path.append(lib_path)

BASEIC_NS_1_0 = "urn:ietf:params:xml:ns:netconf:base:1.0"
SW_NS_1_0 = "urn:broadband-forum-org:yang:bbf-software-image-management"
CURRENT_TIME = time.strftime("%Y%m%d%H%M%S",time.localtime())
TEM_DIR = '/tftpboot/atx/atxuser/'
SW_VERSION_FILE = ""
TFTP_IP = ""
destDir = '/tftpboot/'
new_build = ""
#sys.path.append(os.environ['ROBOTREPO'] +'/PACKAGES/lib/python2.7/site-packages/robot/libraries')
sys.path.append('/repo/TEST_PACKAGES/robot/PACKAGES/lib/python2.7/site-packages/robot/libraries')

logging.basicConfig(level=logging.INFO)
def db_print(printStr, debugType="normal"):
    if debugType=="recv" :
        print  ("<<<" + printStr)
    elif debugType=="send" :
        print  (">>>" + printStr)
    else:
        print  ("---" + printStr)

def getbuildpackageDir(DIRN):
    try:
        out=re.search('packageme\_\d+\.\d+',DIRN)
        if out is None:
            db_print("Invalid directory structure")
            return ""
        else:
            return out.group(0)
    except Exception as inst:
        db_print("package directory not exists:%s" %inst)
        return ""
    
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
    elif build_prot in ['scp','sftp']:
        try:
            for FILE in downloadlist:
                remote = build_dir + '/' + FILE
                local = dest_dir + '/' + FILE
                ssh_scp_get(ip=host_ip,username=ftp_user,password=ftp_pazwd,local=local,remote=remote,timeout=1800)
                db_print('file"%s"download successfully' % FILE)
        except Exception as inst:
            db_print('fail to scp tar file:%s' %inst)
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
    else:
        db_print('un supported protocol type:%s' % build_prot)
        return False
    return True

def check_image_dir(build,loadpath):
    try:
        cmd = "ls -d %s" %loadpath
        result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        if not result.strip() == loadpath:
            db_print("Directory not found in PCTA")
            return False
        else:
            db_print("Directory found in PCTA")
            os.chdir(loadpath)
            cmd = "ls %s" %build
            result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
            if not result.strip() == build:
                db_print("Image %s not found" %build)
                return False
            else:
                db_print("Image %s found" %build)
                return True
    except Exception as inst:
        db_print("Image not found in load directory:%s" %inst)
        return False

def prepare_build_atx (build,nttype,ip,site='Chennai',destDir='/tftpboot/atx/atxuser') :
    global new_build
    global SW_VERSION_FILE,CURRENT_TIME,TEM_DIR,TFTP_IP
    print TEM_DIR
    build_list = build.split(".")
    release = build_list[0].split("_")[1]
    #build_name = 'SD_'+ build_list[0][3:5] +'.'+ build_list[1][0:3] + '.' + 'tar'
    build_name = 'SD_'+ release +'.'+ build_list[1][0:3] + '.' + 'tar'
    print build_name
    logging.info ("original build name is  %s" % (build_name))
    logging.info ("new build name is  %s" % (build_name))
    cmd = '/sbin/ifconfig -a | grep inet | grep -v 127.0.0.1 | grep -v inet6 | awk ' + '"' + '{print \$2}' + '" ' + '| tr -d ' + '"' + \
    'addr:' + '" ' + '| head -1'
    ret1 = os.popen(cmd).readlines()
    TFTP_IP = ret1[0].rstrip()
    if '/' in build :
        if (not os.path.isfile(build)) :
            print ("find %s fail,No such file or directory" % (build))
            logging.info ("find %s fail,No such file or directory" % (build))
            return False
        else :
            full_path = build
            path = os.path.split(build)
            file_path = path[0]
            build = path[1]
    else :
        build_id = release +'.'+ build_list[1][0:3]
        '''
        if site.lower() == 'Chennai':
            path = "/ftpserver/RLAB"
        else:
            DIRN = 'FTP:135.251.206.97:/loads/packageme_%s:asblab:asblab' %build_id
            if "packageme" in DIRN:
                val=getbuildpackageDir(DIRN)
                if val != "":
                    path = "/tftpboot/atx/loads/%s" %val
                else:
                    path = ""
            else:
                path = "/tftpboot/atx/loads"
        if ip == "135.251.200.144" :
            path = "/tftpboot/atx/loads"
        elif ip == "135.251.192.22" :
            path = "/tftpboot/atx/loads"
        '''
        buildPattern1=os.path.join(destDir,build)
        buildPattern2=os.path.join(destDir,'packageme_' + build_id,build)
        buildPath = destDir
        if not destDir == '/tftpboot/atx/atxuser':
            if os.path.exists(buildPattern1):
                buildPath = destDir
            elif os.path.exists(buildPatten2):
                buildPath = os.path.join(destDir,'packageme_' + build_id)
            else:
                print ("find %s fail,No such file or directory" % (buildPath))
                logging.info ("find %s fail,No such file or directory" % (buildPath))
                return False
        full_path = os.path.join(buildPath,build)
        print ("full path is %s " % (full_path))

    #p_folder = TEM_DIR + '*.tar'
    p_folder = TEM_DIR + new_build
    if os.path.exists(p_folder) :
        rm_cmd = 'rm -rf ' + p_folder
        if os.system(rm_cmd) :
             print ("%s fail, cannot remove previous tar file" % (rm_cmd))
             logging.info ("%s fail, cannot remove previous tar file" % (rm_cmd))            
             return False
        else :
             print ("%s pass, remove previous tar file" % (rm_cmd))
             logging.info ("%s pass, remove previous tar file" % (rm_cmd))            
    tmp_file = TEM_DIR + new_build
    cp_cmd = 'cp ' + full_path + ' ' + tmp_file
    logging.info ("copy tar file to /tftpboot/atx/atxuser folder %s" % (cp_cmd))
    if os.system(cp_cmd) :
        print ("%s fail, copy file fail" % (cp_cmd))
        logging.info ("%s fail, copy file fail" % (cp_cmd))            
        return False
    search_cmd='ls ' + tmp_file
    print search_cmd
    if os.system(search_cmd) :
        print ("%s can't access.No such file or directory" % (search_cmd))
        logging.info ("%s can't access.No such file or directory" % (search_cmd))   
        return False
    else :
        logging.info("%s -> search tmp file successfully\n" %(search_cmd))
	return True


             
def _check_error(data):
    """
        check if failure info existing in the input data
    """
    return_val = "PASS"
    error_syntax = '.*Error :.*|.*Error:.*|.*ERROR:.*|.*Error,.*'
    error_syntax = error_syntax + '|.*File exists.*|.*No such file or directory.*|.*cannot create directory.*|.*not found.*'   
    error_syntax = error_syntax + '|.*cannot access.*|.*Not a directory.*'
    error_syntax = error_syntax + '|.*Permission denied.*|.*None.*'
    val = re.search(error_syntax,data)
    if val :
        return_val = "FAIL"
        logging.info("Gotten failure info in command response: %s" % (val.group(0)))
    return  return_val

def check_result (ret):
    if '<rpc-error>' in ret:
        return ('FAIL','RPCError')
    elif '<rpc-reply' in ret:
        return ('PASS','RPCReply')
    elif '<notification' in ret:
        return ('PASS','Notification')
    else:
        return ('FAIL','Other')

def update_ont_build_to_csv (build,ip,csv=None,site='Chennai',destDir='/tftpboot/atx/loads') :
    global new_build

    sw_path=os.path.join(destDir,build)
    
    if not check_image_dir(build,destDir):
        logging.info ("Failed to find loadpath  %s" % (destDir))
        return 'FAIL'

    #print sw_path
    #cmd="tar -tvf "+ sw_path + "| grep NWL3AA* | awk {'print $6'}"
    cmd="tar -tf "+ sw_path + "| grep -e 'NWL3AA.*'"
    output= os.popen(cmd)
    #print output
    logging.info ("output information is  %s" % (output))
    rst = output.read()
    nwl_path = rst.replace('\n','').replace('\r','')
    #print nwl_path
    #print isinstance(nwl_path,str)
    build_list = nwl_path.split(".")
    rel = build_list[0]
    #print build_list
    build_list1 = build.split(".")
    #release = build_list1[0].split("_")[1]
    release = rel[6:len(rel)]
    build_name = release +'.'+ build_list[1]
    logging.info ("build name is  %s" % (build_name))
    #print build_name
    #open csv file and replace ont build number
    ip_list = ip.split(".")
    ip_name = ip_list[2]+"_"+ip_list[3]
    if csv:
        if csv == os.path.basename(csv):
            cmd="ls /repo/atxuser/robot/SETUPS/"+ csv
        else:
            cmd="ls "+ csv
    else:
        cmd="ls /repo/atxuser/robot/SETUPS/NBN_4F_*"+ip_name+".csv"

    ret2 = os.popen(cmd).readlines()
    csv_file = ret2[0].rstrip()
    #print csv_file
    #csv_file="/repo/atxuser/robot/SETUPS/NBN_4F_CFASJ_SRNTM_SMOKE_SETUPFILE_"+ip_name+".csv"
    logging.info ("csv_file is  %s" % (csv_file))
    #print csv_file
    cp_cmd = "cp "+ csv_file +" "+ csv_file+".bak"
    if os.system(cp_cmd) :
        #print ("%s fail, cannot backup csv file" % (cp_cmd))
        logging.info ("%s fail,  cannot backup csv file" % (cp_cmd))            
        return 'FAIL'
    else :
        #print ("%s pass, backup csv file" % (cp_cmd))
        logging.info ("%s pass, backup csv file" % (cp_cmd)) 
    new_build="SD_"+build_name+".tar"
    try : 
        bak_file = csv_file+'.bak'
        f=open(bak_file, 'r')
        f2=open(csv_file,'w')
        #print bak_file
        all_lines = f.readlines()
        ont_line=all_lines[24]
        res= re.search('\,(SD_[\d]+\.[\d]+\.tar)',ont_line)
        old_build = res.group(1)
        #print old_build
        #print new_build
        logging.info ("old build is %s " % (old_build)) 
        logging.info ("new build is %s " % (new_build)) 
        for line in all_lines :
            line = str.replace(line, old_build, new_build)
            #print line
            f2.write(line)
        f.close()
        f2.close()
        logging.info ("replace build number in csv file pass")
        cp_cmd = "cp -rf "+ csv_file +" /tmp"
        os.system(cp_cmd)
        logging.info("copy modified csv file to /tmp")
    except Exception,e :
        #print e
        logging.info ("modify csv file fail, error information %s " % (e))
        return 'FAIL' 



if __name__ == '__main__' :
    

    import logging
    result_pass ='SX 4F download is pass'
    result_fail ='SX 4F download is fail'
    result = True
    try:
        opts, args = getopt.getopt \
        (sys.argv[1:],"hl:i:s:b:t:f:S:c::",["logDirectory=","ip=","build=","type=","ftpserver=","Site=","csv=","help"])  
    except getopt.GetoptError:
        print ("illegal options: %s" % str(sys.argv[1:]))
        sys.exit(result_fail)

    if "-h" in sys.argv[1:] or "--help" in sys.argv[1:] :
        print ("Usage:")
        print ("./sw_update.py --logDirectory /tftpboot/atx/atxuser/SB_Logs_08032016-113020 --ip 135.251.247.198 \
        --build SD_55.797p0.tar --type AF ") 
        print ("./sw_update.py -l /tftpboot/atx/atxuser/SB_Logs_08032016-113020 -i 135.251.247.198 \
        -b SD_55.797p0.tar -t AF ")
        print ("./sw_update.py --logDirectory /tftpboot/atx/atxuser/SB_Logs_08032016-113020 --ip 135.251.247.198 \
        --build SD_55.797p0.tar --type AF --ftpserver ftp:135.251.206.97:/ftpserver/loads:asblab:asblab") 
        print ("./sw_update.py -l /tftpboot/atx/atxuser/SB_Logs_08032016-113020 -i 135.251.247.198 \
        -b SD_55.797p0.tar -t AF -f ftp:135.251.206.97:/ftpserver/loads:asblab:asblab")  
        sys.exit(0)   
    
    # default values
    nt_type = "AF"
    logFile = "sw_update.txt"
    csv = ''
    site= 'Chennai'
    host = ''
    for opt, value in opts:
        if "-l" == opt or "--logDirectory" == opt:
            logDir = value.rstrip ("/")
        elif "-i" == opt or "--ip" == opt:
            ip = value   
        elif "-b" == opt or "--build" == opt:
            build = value
        elif "-t" == opt or "--type" == opt:
            nt_type = value
        elif "-f" == opt or "--ftpserver" == opt:
            host = value
        elif "-S"  == opt or "--Site" == opt:
            site = value
        elif "-c" == opt or "--csv" == opt:
            csv = value 

    print ("check the existing of basic robot path ...")
    try:
        robotRepo = os.environ['ROBOTREPO']
    except Exception as inst:
        print ("exception: %s" % (inst))
        print ("ROBOTREPO WAS NOT SET in ~/.bashrc") 
        print ("pls add : export ROBOTREPO=/repo/$USER/robot in .bashrc")          
        sys.exit(result_fail)

    print ("check logDirectory is a directory ...")    
    if not os.path.isdir(logDir):
        print ("logDirectory %s is not a directory!" % (logDir))
        sys.exit(result_fail)

    print ("check .tar file ...")
    m = re.search('.tar',build)
    if not m :
        print (" %s is not a build file!" % (build))      
        sys.exit(result_fail) 

    log_Dir = logDir + '/' + logFile
    logging.basicConfig (filename=log_Dir,level=1)
    logging.info("----logging info")      

    sDate=os.popen('date').readline()
    sDate=sDate.strip('\r\n')
    print (("%s : Prepare load %s") % (sDate,build))
    print (">>>>>>>>>>>>>>>>>> 1.STARTUP. Build Preparation <<<<<<<<<<<<<<<<<<<<")       
    logging.info (">>>>>> 1.STARTUP. Build Preparation <<<<<<")
    try :
        destDir='/tftpboot/atx/loads'
        if host and not site == 'Chennai':
            (buildProt, DIRN, host_ip, ftp_user, ftp_pazwd) = _parseBuildInfo(host)
            destDir='/tftpboot/atx/atxuser'
            retryNum = 0
            maxRetry = 5
            res = re.search(r'lightspan-omci_([\d]{2,4}\.[\d]{3,6})',build)
            if not res:
                logging.info("wrong build format")
                sys.exit(result_fail)
            ver = res.group(1)
            while retryNum < maxRetry:
                if not _downloadBuild(buildProt,build, DIRN, destDir, ver, host_ip, ftp_user, ftp_pazwd):
                    db_print("first try failure")
                elif not isTarComplete(destDir, build):
                    db_print("tar file on build server is not complete yet, wait for 300s")
                else:
                    db_print("build download successfully")
                    result = True
                    break
                retryNum = retryNum + 1
                time.sleep(300)
            if retryNum >= maxRetry:
                result = False
        if not result:
            db_print("download failure")
            sys.exit(result_fail)  
        result=update_ont_build_to_csv (build=build,ip=ip,csv=csv,site=site,destDir=destDir)
        if result == 'FAIL':
            logging.info ("Prepare build file failed ! Stop the script !")
            sys.exit(result_fail)
        else:
            result = True
        result = prepare_build_atx(build=build,nttype=nt_type,ip=ip,site=site,destDir=destDir)



    except Exception as inst :
        print (("Prepare build file failed! Stop the script! exception: %s") % (inst))
        logging.info ("prepare build file failed! stop the script! exception: %s" % (inst))
        sys.exit(result_fail)   
    if not result :
        print ("Prepare build file failed! Stop the script!")
        logging.info ("Prepare build file failed ! Stop the script !")
        sys.exit(result_fail)
    else :
        print ("Prepare build file successfully ! Continue...")
        logging.info ("Prepare build file successfully ! Continue...")
        #print (result_pass)
        #logging.info (result_pass)
        #sys.exit(result_pass)



#! /usr/bin/python                                                                                                      
#coding:utf-8

import re, os, sys,subprocess
import paramiko,time,random
import logging,socket
import json
from optparse import OptionParser
HOST = '135.251.206.97'
REMOTEHOST='172.21.128.21'
LOCAL_LOAD_PATH='/tftpboot/atx/loads'
DIRN = '/loads'
PUBLIC_HOST_BUILD_SERVER = 'http:aww.dsl.alcatel.be/ftp/pub/outgoing/ESAM/DAILY' 
IMAGE_DIR_PATTERN = {\
    'drnt-b':'vobs/esam/build/host/moswa/images/drnt-b',\
    'sfhm-b':'vobs/esam/build/host/moswa/images/sfhm-b',\
    'drnt-d':'vobs/esam/build/spum-l/OS/images/drnt-b',\
    'srnt-d':'vobs/esam/build/spum-l/OS/images/srnt-d',\
    'fglt-b':'vobs/esam/build/host/SDFX/images/fglt-b',\
    'fwlt-b':'vobs/esam/build/host/SDFX/images/fwlt-b',\
    'cfmb-a':'vobs/esam/build/host/SDOLT/images/cfmb-a'\
}
YANG_DIR_PATTERN = {\
    'drnt-b':'vobs/esam/build/host/moswa/SD-DPU/CFER-C/CFER-C.tgz',\
    'sfhm-b':'vobs/esam/build/host/moswa/SD-DPU/CFAS-H/CFAS-H.tgz',\
    'srnt-m':'vobs/esam/build/host/moswa/SD-DPU/CFAS-J/CFAS-J.tgz',\
    'cfmb-a':'vobs/esam/build/host/SDOLT/SD-OLT/CFXR-B/CFXR-B.tgz',\
    'fglt-b':'vobs/esam/build/host/SDFX/SD-FX/FGLT-B/FGLT-B.tgz',\
    'fwlt-b':'vobs/esam/build/host/SDFX/SD-FX/FWLT-B/FWLT-B.tgz',\
}
# local directory for yang tar SD-FX/FWLT-B
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

def _generateHostCsv(targetIp,newDir):
    try:
        setupFile = os.environ['SETUPFILENAME']
        newSetupFile = newDir + '/' + os.path.basename(setupFile)
        os.environ['SETUPFILENAME'] = newSetupFile
        cmd = "cat %s | sed 's/HOST_IP/%s/g' > %s" %(setupFile,targetIp,newSetupFile)
        os.system(cmd)
    except Exception as inst:
        print('SETUPFILENAME not set with exception:%s,pls set it and retry' %inst)
        return False
    return True

def startHost(targetIp,guestIp,board,build,giciPort,timeStamp):
    try:
        os.environ['PATH'] = '/ap/local/devtools/bin:%s' %os.environ['PATH']
    except Exception as inst:
        print('add devtools into path failure with exception: %s' %inst)
        return None
    resJson = {}
    try:
        print('check whether targetIp has been existing')
        cmd = 'ping -c 4 %s' %targetIp
        results = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0] 
        for result in results:
            if not result.find('bytes from %s' %targetIp) == -1:
                print('targetIp has been existing and is up')
                sysUp = True
                break
        print('check whether tap for current guest ip is existing, if yes,delete it')
        cmd = 'ip addr |grep %s' %guestIp
        results = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]   
        print( str(results))
        if results: 
            qemutap = results.strip().split(' ')[-1]
            if 'qemu' in qemutap :
                cmd = 'sudo ip link set %s down' %qemutap
                results = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
                cmd = 'sudo ip link del %s' %qemutap
                results = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
    except Exception as inst:
        print('remove existing qemu tap config failure with: %s' %inst)
        return resJson
    workdir = '/tmp/' + timeStamp
    cmd = 'mkdir %s' %workdir
    results = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0] 
    qemu_cmd = 'start-isam-qemu --board ' + board + ' --build ' + build + ' --ip ' + guestIp + ':' + targetIp + '/255.255.255.0 --gici-on-telnet %s --work-dir %s > %s/startqemu.log 2>&1 &' %(giciPort,workdir,workdir)
    print( qemu_cmd)
    oldresults = []
    try:
        cmd = 'ps -ef |grep start-isam-qemu |grep -v grep'    
        oldresults = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].strip().split('\n')
        print( 'oldresults')
        print( len(oldresults))
        cmd = 'mkdir %s' %workdir
        results = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0] 
        time.sleep(10)
        #stdin,stdout,stderr = ssh.exec_command('echo $!')
    except Exception as inst:
        print('start qemu with exception:%s' %inst)
        return resJson
    try:
        #oldpath = os.environ['PATH']
        #newpath = '/ap/local/devtools/bin:%s' %oldpath
        #print( newpath
        #os.system('which start-isam-qemu')
        #cmd = ['start-isam-qemu', '--board', board, '--build', build, '--ip', guestIp + ':' + targetIp + '/255.255.255.0', '>' + logDir + '/startqemu.log 2>&1 &']
        #cmd = 'start-isam-qemu --board ' + board + ' --build ' + build + ' --ip ' + guestIp + ':' + targetIp + '/255.255.255.0 > ' + logDir + '/startqemu.log 2>&1 &'
        cmd = 'start-isam-qemu --board ' + board + ' --build ' + build + ' --ip ' + guestIp + ':' + targetIp + '/255.255.255.0'
        print( cmd)
        childpid =subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except Exception as inst:
        print('start host failure with %s' %inst)
        return None
    return childpid

def startHostBySSH(targetIp,guestIp,board,build,giciPort,timeStamp,linuxIp,username='atxuser',passwd='alcatel01',port=22):

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(linuxIp,port,username,passwd,timeout=5)

    resJson = {}
    try:
        cmd = 'ping -c 4 %s' %targetIp
        stdin,stdout,stderr = ssh.exec_command(cmd)
        results = stdout.readlines()   
        for result in results:
            if not result.find('bytes from %s' %targetIp) == -1:
                sysUp = True
                break
        cmd = 'ip addr |grep %s' %guestIp
        stdin,stdout,stderr = ssh.exec_command(cmd)
        results = stdout.readlines()  
        print( str(results))
        if results: 
            qemutap = results[-1].strip(' ').strip('\n').split(' ')[-1]
            if 'qemu' in qemutap :
                cmd = 'sudo ip link set %s down' %qemutap
                stdin,stdout,stderr = ssh.exec_command(cmd)
                cmd = 'sudo ip link del %s' %qemutap
                stdin,stdout,stderr = ssh.exec_command(cmd)
    except Exception as inst:
        print('remove existing qemu tap config failure with: %s' %inst)
        return resJson
    workdir = '~/' + username + '-' + timeStamp
    try:
        ssh.exec_command('mkdir -p %s' %workdir)
        print('Creating %s' %workdir)
    except Exception:
        print('make working_dir failure')
        return resJson
    try:
        build = build.rstrip('/')
        (build_id,build_ip) = build.split(':',1)
    except Exception:
        build_id = build
        build_ip = ''
    release = build_id.split('.')[0]
    if build_ip:
        (build_prot,build_path) = build_ip.split(':',1)
        build_prot = build_prot.lower()
        #for public www daily host, it will be aww.dsl.alcatel.be/ftp/pub/outgoing/ESAM/DAILY:::
        build_path=build_path.rstrip(':')
        build_ip = build_prot + ':' + build_path
    #if build is build_id or build is HTTP:aww.dsl.alcatel.be/ftp/pub/outgoing/ESAM/DAILY then means public host
    if PUBLIC_HOST_BUILD_SERVER == build_ip:
        print('using public host image')
        build_ip = ''
    src_yang = ''
    yang_tar = ''

    if board in YANG_DIR_PATTERN:
        src_yang = PUBLIC_HOST_BUILD_SERVER.replace('http:','http://') + '/build_results/%s/%s/%s' %(release,build_id,YANG_DIR_PATTERN[board])
        tmpList = YANG_DIR_PATTERN[board].split('/')
        yang_tar = tmpList[-1]
        #like SD-DPU/CFER-C
        family_yang = tmpList[-3]
        dest_yang = workdir + '/yangtar/' + tmpList[-3] + '/' + tmpList[-2]
        dir_yang = workdir + '/yangtar'
        ssh_cmd = 'mkdir -p %s' %dest_yang
        stdin,stdout,stderr = ssh.exec_command(ssh_cmd,timeout=20)
    if not build_ip:
        print('using public host image')
        build = build_id
    else:
        #for private image, use SD_*.extra.tar directly
        yang_tar = 'SD_%s.extra.tar' %build_id
        build = workdir + '/sw/'
        if not board in IMAGE_DIR_PATTERN:
            print('private build for this board:%s is not supported' %board)
            return resJson
        build_dir = build + IMAGE_DIR_PATTERN[board]
        tmpList = build_ip.split(':')

        if not tmpList[0] in ['ftp','sftp']:
            print('unsupported host image path protocol')
            return resJson
        #wget_path = tmpList[0] + '://' + tmpList[1] + '/../' + tmpList[2] + '/'
        #wget_auth = ''
        build_prot= tmpList[0]

        if len(tmpList) == 5:
            #wget_auth = '--ftp-user %s --ftp-password %s' %(tmpList[3],tmpList[4])
            ftp_auth = tmpList[3] + ':' + tmpList[4] + '@'
        else:
            ftp_auth = ''
        src_yang = '%s://%s%s%s/%s' %(build_prot,ftp_auth,tmpList[1],tmpList[2],yang_tar)
        try:
            cmd = 'mkdir -p ' + build_dir
            stdin,stdout,stderr = ssh.exec_command(cmd,timeout=10)
            print(cmd)
            time.sleep(2)
            destFile = build_dir
            srcFile = '%s://%s%s%s/bzImage' %(build_prot,ftp_auth,tmpList[1],tmpList[2])
            if not _download_image(ssh,destFile,srcFile):
                print('download private host image failure with: %s' %inst)
                return resJson
            destFile = build_dir
            srcFile = '%s://%s%s%s/host-target-persistent.tar.gz' %(build_prot,ftp_auth,tmpList[1],tmpList[2])
            if not _download_image(ssh,destFile,srcFile):
                print('download private host image failure with: %s' %inst)
                return resJson
        except Exception as inst:
            print('download private host image failure with: %s' %inst)
            return resJson
    yang_file = _prep_yang_tar(ssh,dest_yang,src_yang,family_yang,dir_yang,build_id)
    if not yang_file:
        print('prepare yang tar file failed')
        #return resJson
    print('LTB extraTar file:%s' %yang_file) 
    qemu_cmd = 'start-isam-qemu --board ' + board + ' --build ' + build + ' --ip ' + guestIp + ':' + targetIp + '/255.255.255.0 --gici-on-telnet %s --work-dir %s > %s/startqemu.log 2>&1 &' %(giciPort,workdir,workdir)
    print( qemu_cmd)
    oldresults = []
    pid = ''
    try:
        cmd = 'ps -ef |grep start-isam-qemu |grep %s |grep -v grep' %workdir
        stdin,stdout,stderr = ssh.exec_command(cmd)
        oldresults = stdout.readlines()
        print( 'oldresults')
        print( len(oldresults))

        qemu_cmd = 'export PATH=/ap/local/devtools/bin:$PATH;' + qemu_cmd
        stdin,stdout,stderr = ssh.exec_command(qemu_cmd)
        #print stdout.readlines()
        #print stderr.readlines()
        time.sleep(10)
        #stdin,stdout,stderr = ssh.exec_command('echo $!')
    except Exception as inst:
        print('start qemu with exception:%s' %inst)
        return resJson
    #results = stdout.readlines()
    #if results:
    #    pid = results[-1].strip()
    sysUp = False

    current_time = time.mktime(time.localtime())
    check_time = 1800
    end_time = current_time + check_time
    wget_time = 0
    qemu_time = 0
    pid = ''
    while current_time <= end_time:
        try:
            if not pid:
                cmd = 'ps -ef |grep start-isam-qemu |grep %s |grep -v grep' %workdir 
                stdin,stdout,stderr = ssh.exec_command(cmd)
                results = stdout.readlines()
                #print(cmd)
                print( 'results for pid')
                print(str(results))
                print(len(results) - len(oldresults))
             
                if len(results) - len(oldresults) == 0:
                    logging.error('start-isam-qemu exit abnormally immediately!')
                    stdin,stdout,stderr = ssh.exec_command('cat %s/startqemu.log' %workdir)
                    print(str(stdout.readlines()))
                    break
                res = re.search('([\d]+)',results[-1].strip())
                if res:
                    pid = res.group(1)
                else:
                    logging.error('start-isam-qemu exit abnormally:can not fetch pid!')
                    stdin,stdout,stderr = ssh.exec_command('cat %s/startqemu.log' %workdir)
                    print(str(stdout.readlines()))
                    break
            cmd = 'pstree -pA %s' %pid
            stdin,stdout,stderr = ssh.exec_command(cmd)
            results = stdout.readlines()
            print( 'pstree output')
            print(str(''.join(results)))
            if not results:
                logging.error('start-isam-qemu with pid:%s exit abnormally!' %pid)
                break
            res = re.search('(axel|wget|qemu-system-i386)\(([\d]+)\)',results[0])
            if res :
                if res.group(1) == 'wget' or res.group(1) == 'axel':
                    print('wait for host image download with pid:%s ......' %res.group(2))
                    time.sleep(30)
                    current_time = time.mktime(time.localtime())
                    #if not wget_time:
                    #    wget_time = 1800
                    #    end_time = current_time + wget_time
                    continue
            
            cmd = 'ping -c 4 %s' %targetIp
            stdin,stdout,stderr = ssh.exec_command(cmd)
            results = stdout.read()
            print( 'ping results')
            print(str(results))
            if not str(results).find('bytes from %s' %targetIp) == -1:
                cmd = 'grep \"confd_ready\" %s/startup_notifications.log' %workdir
                stdin,stdout,stderr = ssh.exec_command(cmd)
                if 'confd_ready' in stdout.read():
                    time.sleep(5)
                    sysUp = True
                    break           
        except Exception as inst:
            print( "start isam qemu fail with exception:%s" %inst) 
            ssh.close()
            break 
        if sysUp:
            print sysUp
            print 'sys is up'
            break
        cmd = 'grep \"Unexpected EOF in archive\" %s/startqemu.log ' %workdir 
        try:
            stdin,stdout,stderr = ssh.exec_command(cmd)
            if "Unexpected EOF" in stdout.read():
                sysUp = False
                break
        except Exception as inst:
            pass
        time.sleep(10)
        current_time = time.mktime(time.localtime())
    if sysUp: 
        print('qemu is up with %s' %qemu_cmd) 
        print('you can shutdown it by ssh -p 2222 root@%s' %targetIp)
        print('or kill pid with %s' %pid)
        stdin,stdout,stderr = ssh.exec_command('cat %s/running_config.json' %workdir)
        resJson = json.loads(stdout.read())
        resJson['pid'] = pid
    else:
        print('start isam qemu failed with %s' %qemu_cmd)
        if pid:
            print('kill qemu')
            stdin,stdout,stderr = ssh.exec_command('kill -9 %s' %pid)
        stdin,stdout,stderr = ssh.exec_command('cat %s/startqemu.log' %workdir)
        print(stdout.read())
        #ssh.exec_command('rm -rf %s' %workdir)
        #print('remove working_dir')
    ssh.close()
    return resJson

def _download_image(ssh,destFile,srcFile):
    try:
        #ftp_cmd = 'axel -q -o %s %s' %(destFile,srcFile)
        ftp_cmd = 'axel --no-proxy --num-connections 5 --alternate --output %s %s' %(destFile,srcFile)
        stdin,stdout,stderr = ssh.exec_command(ftp_cmd,timeout=20)
        print(ftp_cmd)
        #wait_time = 0
        #while(not stdout.channel.exit_status_ready() and wait_time <= 6):
        #    time.sleep(2)
        #    wait_time = wait_time + 2
        time.sleep(5)
        result = stdout.read()
        if not 'Downloaded' in result:
            print(result)
            return False
    except Exception as inst:
        print('download image failure with exception:%s' %inst)
        return False
    return True

def _prep_yang_tar(ssh,dest_yang,src_yang,family_yang,dir_yang,build_id):

    if 'extra.tar' in src_yang:
        dest_yang = '%s/SD_%s.extra.tar' %(dir_yang,build_id)
        if not _download_image(ssh,dest_yang,src_yang):
            return ''
        return dest_yang
    elif not _download_image(ssh,dest_yang,src_yang):
        print('download yang tar file failed')
        return ''
    try:
        print('prepare extra yang tar file')
        ssh_cmd = 'cd %s' %dir_yang

        ssh_cmd += ';tar -czf NWEJAA%s.tgz %s' %(build_id,family_yang)
        ssh_cmd += ';tar -cf SD_%s.yang.tar NWEJAA%s.tgz;ls -al' %(build_id,build_id)
        stdin,stdout,stderr = ssh.exec_command(ssh_cmd,timeout=20)
        wait_time = 0
        while(not stdout.channel.exit_status_ready() and wait_time <= 6):
            time.sleep(2)
            wait_time = wait_time + 2
        print stdout.read()
        print('remove temp files')
        ssh_cmd = 'cd %s' %dir_yang
        ssh_cmd += ';rm -rf NWEJAA%s.tgz' %build_id
        ssh_cmd += ';rm -rf %s;ls -al' %family_yang
        stdin,stdout,stderr = ssh.exec_command(ssh_cmd,timeout=20)
        wait_time = 0
        while(not stdout.channel.exit_status_ready() and wait_time <= 6):
            time.sleep(2)
            wait_time = wait_time + 2
        print stdout.read()
    except Exception as inst:
        print('parepare extra yang tar with exception:%s' %inst)
        return ''
    return '%s/SD_%s.yang.tar' %(dir_yang,build_id)

def _modifyBatchCommand(targetIp,batchCommand):
    pass

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("--action", dest="action",default='', help="oswp action")
    parser.add_option("--build", dest="build", default='',help="oswo build version")
    parser.add_option("--linuxIP", dest="linuxIp", default='',help="linuxIp")
    parser.add_option("--board", dest="board", default='',help="board type")
    parser.add_option("--targetIP",dest="targetIp",default='',help="oamIp")
    parser.add_option("--guestIP",dest="guestIp",default='',help="oamIp")
    parser.add_option("--debug",dest="debug",action='store_true',default=False,help="debug")
    parser.add_option("--user",dest="user",default='atxuser',help="username if not atxuser")
    parser.add_option("--password",dest="password",default='alcatel01',help="password if not alcatel01")
    (options, args) = parser.parse_args(sys.argv[1:])
    linuxIp = options.linuxIp
    build = options.build

    board = options.board 
    action = options.action
    user = options.user
    password = options.password
    if options.debug:
        logging.basicConfig(level=logging.DEBUG,format='%(asctime)s: %(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=logging.INFO,format='%(asctime)s: %(levelname)s: %(message)s')
    timeStamp=time.strftime('%b%d%H%M%S',time.localtime())
    if not board or not build:
        print('board or build not provisioned,exit')
        sys.exit()
    try:
        targetIp = options.targetIP
        guestIp = options.guestIP
    except Exception as inst:
        print('targetIP and guestIP not provisioned,generate uniq ip address based in linuxIP')
        (targetIp,guestIp) = _generateIpAddr(linuxIp)
    print('linuxIp is %s' %linuxIp)
    print('targetIp is %s' %targetIp)
    print('guestIp is %s' %guestIp)
    try:
        hostname = socket.gethostname()
        localIp = socket.gethostbyname(hostname)
    except Exception as inst:
        localIp = ''
    print('localhost ip is %s' %localIp)
    giciPort=str(2000 + int(timeStamp[-4:]))[-4:]
    if localIp == linuxIp:
        hostPid = startHost(targetIp,guestIp,board,build,giciPort,timeStamp)
        pid = hostPid.pid
        print('with pid:%s' %hostPid.pid)
        if hostPid:
            while True:
                try:
                    out = hostPid.stdout.readline()
                    print(str(out))
                    if not out:
                        break
                    if not out.find('ystem initialized successfully') == -1:
                        print( "target is up with ip:%s" %targetIp)
                        print( "if you would like to shutdown it pls log on it and shutdown")
                        break
                except Exception as inst:
                    print( "IOError with:%s" %inst)
                    print( "kill host instance")
                    hostPid.terminate()
            hostExit = hostPid.poll()
            if hostExit:
                print('host pid %s exit with %s' %(pid,hostExit))
            #else:
                #hostPid.stdin.flush()
                #hostPid.stdout.flush()
            print('with pid:%s' %hostPid.pid)
            sys.stdout.flush()
            sys.stdin.flush()
    else:
        pidDict = startHostBySSH(targetIp,guestIp,board,build,giciPort,timeStamp,linuxIp,user,password)
        if pidDict:
            print('with pid:%s' %pidDict['pid'])

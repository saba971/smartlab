#! /usr/bin/python
# coding:utf-8
# Author: Hong G Yang <hong.g.yang@nokia-sbell.com>
from oswpUtility import *
#import requests

def print_log(strr):
    print(strr)


#####################class#######################################
class prepareOSWP_class(object):
    def __init__(self, args):
        self.args = args
        print_log(str(self.args))
        self.noFallback = self.args.setdefault('noFallback', False)
        self.build_server = {}
        self.update_server = {}
        self.build_info = {}
        #self.build_product = 'ZACEAA'
        self.build_product = 'lightspan'
        self.PUBLIC_DAILY_BUILD_SERVER = 'aww.dsl.alcatel.be/ftp/pub/outgoing/ESAM/DAILY/' 
        #build server info
        self.build_server['ip'] = self.args.setdefault('build_ip','172.21.128.21')
        self.build_server['port'] = self.args.setdefault('build_port','22')
        self.build_server['user'] = self.args.setdefault('build_user','rmtlab')
        self.build_server['password'] = self.args.setdefault('build_pazwd','rmtlab')
        self.build_server['build_dir'] = self.args.setdefault('build_dir','/ftpserver/RLAB1')
        self.build_server['build_id_dir'] = self.args.setdefault('build_id_dir','')
        self.build_server['protocol'] = self.args.setdefault('protocol','ftp')
        #update server info
        self.update_server['ip'] = self.args.setdefault('update_ip','135.252.245.44')
        self.update_server['port'] = self.args.setdefault('update_port','22')
        self.update_server['user'] = self.args.setdefault('update_user','atxuser')
        self.update_server['password'] = self.args.setdefault('update_pazwd','alcatel01')
        self.update_server['abs_dir'] = self.args.setdefault('update_abs_dir','/tftpboot')
        self.update_server['alias_dir'] = self.args.setdefault('alias_dir','')
        #build id info
        self.build_info['build_id'] = self.args.setdefault('build_id', '')
        self.build_info['build_id_short'] = self.args.setdefault('build_id_short', '')
        self.build_info['build_id_head'] = self.args.setdefault('build_id_head', '')
        self.build_info['build_file'] = self.args.setdefault('build_file', '')
        self.build_info['build_file_untar'] = self.args.setdefault('build_file_untar', '')
        self.build_info['build_type'] = self.args.setdefault('build_type','official')#proposal,wild,iwf,trans
        self.destDir = ''
        self._url = ''
        if True :
            #legacy interface
            self.build = self.args.setdefault('build', '')
            self.serverip = self.args.setdefault('serverip','')
            self.destDir = self.args.setdefault('destDir','')
            self.extraTar = self.args.setdefault('extraTar','')
            self.Host = self.args.setdefault('Host','')
            self.build_type = self.args.setdefault('build_type','')
            self.dr4Flag = self.args.setdefault('dr4Flag','')
            self.build_product = self.args['product'] if self.args['product'] else 'lightspan'
            #initialization
            self._parse_host_string()
            self._parse_build_id()
        self._update_server_init()
        print_log("build server %s" % str(self.build_server))
        print_log("update server %s" % str(self.update_server))
        print_log("build info %s" % str(self.build_info))
        self.capacity = {'SD':
                             {'51': 850,
                              '52': 950,
                              '53': 950,
                              '54': 1050,
                              '55': 1200,
                              '56': 1400,
                              '57': 1650,
                              '58': 1900,
                              '59': 2000,
                              '60': 2000,
                              '61': 2500,},
                        'ZACEAA':
                              {'61':900},
                        'lightspan':
                              {'61':900,
                               '62':1000,},
                        } 


    def _build_capacity(self,bid,btype):
        return self.capacity[btype].get(bid,900)


    def _update_server_init(self):
        if (self.build_product == 'ZACEAA' or self.build_product == 'lightspan') and not self.destDir :
            self.update_server['abs_dir'] = '/tftpboot/official_moswa_build'
        elif self.destDir :
            self.update_server['abs_dir'] = self.destDir 
            if not os.path.exists(self.destDir):
                os.makedirs(self.destDir)


    def _parse_host_string(self):
        host_string = self.Host
        if (not host_string) or host_string == 'ftp:172.21.128.21':
            self.build_server['protocol'] = 'ftp' 
            self.build_server['ip'] = '172.21.128.21'
            self.build_server['build_dir'] = '/ftpserver/RLAB'
            self.build_server['user'] = 'rmtlab'
            self.build_server['password'] = 'rmtlab'
        else:
            host_string_list = host_string.split(':')
            self.build_server['protocol'] = host_string_list[0] 
            if (self.build_server['protocol'] == 'http' or self.build_server['protocol'] == 'https') and self.noFallback :
                self.build_server['ip'] = host_string_list[1] 
                if len(host_string_list) == 6:
                    self.build_server['ip'] = self.build_server['ip'] + ':' + host_string_list[2]
                self.build_server['build_dir'] = ''
                self.build_server['user'] = ''
                self.build_server['password'] = ''
                self.build_server['build_id_dir'] = ''
                self.build_server['build_dir2'] = ''
                return
            if len(host_string_list) > 4 :
                self.build_server['protocol'] = host_string_list[0] 
                self.build_server['ip'] = host_string_list[1] 
                self.build_server['build_dir'] = host_string_list[2] 
                self.build_server['user'] = host_string_list[3] 
                self.build_server['password'] = host_string_list[4] 
            elif len(host_string_list) > 2 :
                self.build_server['protocol'] = host_string_list[0] 
                self.build_server['ip'] = host_string_list[1] 
                self.build_server['build_dir'] = host_string_list[2] 
                if self.build_server['protocol'] == 'ftp' or self.build_server['protocol'] == 'sftp':
                    self.build_server['user'] = 'anonymous'
                    self.build_server['password'] = 'anonymous' 
                elif self.build_server['protocol'] == 'scp':
                    self.build_server['user'] = 'atxuser'
                    self.build_server['password'] = 'alcatel01' 
                else :
                    print_log("fail to parse --Host option with len 3")
            elif len(host_string_list) > 1 :
                self.build_server['protocol'] = host_string_list[0] 
                if self.build_server['protocol'] == 'http' or self.build_server['protocol'] == 'https':
                    self.build_server['ip'] = host_string_list[1] 
                else :
                    print_log("fail to parse --Host option with len 2")
            else :
                print_log("fail to parse --Host option")


    def _parse_build_id(self):
        m = re.match('(\d\d)(\d\d)?\.(\d\d\d(\d\d\d)?(p\d+)?)$',self.build)

        if m and m.group(2) :
            self.build_info['build_id'] = self.build
            self.build_info['build_id_short'] = m.group(1) + '.' + m.group(3)
            self.build_info['build_id_head'] = m.group(1)
            if self.build_product == 'ZACEAA':
                self.build_info['build_file'] = self.build_product +  self.build_info['build_id_short'] + '.tar'
            elif self.build_product == 'lightspan':
                self.build_info['build_file'] = self.build_product + '_' + self.build_info['build_id'] + '.tar'
            elif self.build_product == 'SD':
                self.build_info['build_file'] = self.build_product + '_' + self.build_info['build_id'] + '.tar'
        elif m :
            self.build_info['build_id'] = self.build
            self.build_info['build_id_short'] = self.build
            self.build_info['build_id_head'] = m.group(1)
            if self.build_product == 'ZACEAA':
                self.build_info['build_file'] = self.build_product +  self.build_info['build_id_short'] + '.tar'
            elif self.build_product == 'lightspan':
                self.build_info['build_file'] = self.build_product + '_' + self.build_info['build_id'] + '.tar'
            elif self.build_product == 'SD':
                self.build_info['build_file'] = self.build_product + '_' + self.build_info['build_id'] + '.tar'
        else :
            self.build_info['build_id'] = self.build
            self.build_info['build_id_short'] = self.build
            self.build_info['build_id_head'] = self.build
            self.build_info['build_file'] = self.build 
            self.build_info['build_type'] = self.args.setdefault('build_type','wild')
        self.build_info['build_file_untar'] = re.sub('\.tar$','',self.build_info['build_file'])
        if not self.noFallback:
            if m:
                self.build_server['build_id_dir'] = '/packageme_' + self.build_info['build_id']
            #if lightspan tar in the ftp server dir directly, following line should be comment
            self.build_server['build_dir2'] = self.build_server['build_dir'] + self.build_server['build_id_dir']
        else:
            self.build_server['build_dir2'] = self.build_server['build_dir']
        self.PUBLIC_DAILY_BUILD_SERVER = self.PUBLIC_DAILY_BUILD_SERVER +  '/' + self.build_server['build_id_dir']

    def _update_build_dir(self,source_dir):
        self.build_server['build_dir'] = source_dir

    def _getdirsize(self,my_dir):
        size = 0L
        for root, dirs, files in os.walk(my_dir):
            size += sum([os.path.getsize(os.path.join(root, name))
                     for name in files])
        return size

    def _check_increasing(self,dir_location):
        try:
            check_size = os.path.getsize if os.path.isfile(dir_location) else self._getdirsize
            filesize = check_size(dir_location)
            time.sleep(3)
            filesize2 = check_size(dir_location)
            while filesize2 > filesize :
                filesize = check_size(dir_location)
                time.sleep(5)
                filesize2 = check_size(dir_location)
        except Exception as inst:
            print_log(str(inst))
        return True

    def _existsBuildLocal(self):
        if self.build_info['build_type'] == 'official' :
            max_size = self._build_capacity(self.build_info['build_id_head'],self.build_product)
        else :
            max_size = 0
        print_log("tar file %s , min capacity %s" % (self.build_info['build_file'],str(max_size))  ) 
        untar_dir = os.path.join(self.update_server['abs_dir'],self.build_info['build_file_untar']) 
        tar_dir = os.path.join(self.update_server['abs_dir'],self.build_info['build_file']) 
        seq_tar_dir = tar_dir + '_0'
        if os.path.exists(untar_dir) :
            filesize = self._getdirsize(untar_dir) if self._check_increasing(untar_dir) else 0
            if filesize > max_size :
                print_log("untar file folder check OK")
            else :
                print_log("untar file capacity abnormal")
                return False
        elif os.path.exists(tar_dir) :
            filesize = os.path.getsize(tar_dir) if self._check_increasing(tar_dir) else 0
            if filesize > max_size :
                print_log("tar file download")
            time.sleep(2) 
            filesize = self._getdirsize(untar_dir) if self._check_increasing(untar_dir) else 0
            if filesize > max_size :
                print_log("tar file untar successfully")
            else :
                print_log("tar file capacity abnormal")
                return False
        elif os.path.exists(seq_tar_dir) :
            while os.path.exists(seq_tar_dir) :
                time.sleep(1)  
            time.sleep(20) 
            filesize = self._getdirsize(untar_dir) if self._check_increasing(untar_dir) else 0
            if filesize > max_size :
                print_log("http tar file untar successfully")
            else :
                print_log("http tar file capacity abnormal")
                return False
        else :
            print_log("tar file not exits")
            return False
        self._url = untar_dir
        return True

    
    def _isTarCompelete(self,**args):
        _tar_dir = os.path.join(self.update_server['abs_dir'],self.build_info['build_file']) 
        tar_dir = args.setdefault('tar_dir',_tar_dir)
        tar_size = os.path.getsize(tar_dir)           
        print_log("tar_size %s" % str(tar_size))
        if tar_size < 850:
            print_log("Pls check your build server for size of %s" %os.path.basename(tar_dir))
            return False
        cmd = 'tar -tf %s' % tar_dir
        result = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, shell=True).communicate()
        # tar -tf will return Error is not recoverable error
        if len(result) == 2 and ('Error is not recoverable' in result[1] or 'Unexpected EOF in archive' in result[1]):
            return False
        else:
            print_log('tar file is intergrity')
            return True


    def _untarFile(self,**args):
        _path = args.setdefault('path',self.update_server['abs_dir'])
        un_file = args.setdefault('un_file',self.build_info['build_file_untar'])
        tar_file = args.setdefault('tar_file',self.build_info['build_file'])
        unfolder = os.path.join(_path,un_file)
        abs_tar_file = os.path.join(_path,tar_file)
        if not os.path.exists(unfolder):
            os.mkdir(unfolder)
        os.chdir(unfolder)
        t = tarfile.open('../' + tar_file)
        t.extractall()
        time.sleep(10)
        try:
            os.remove('../' + tar_file)
        except Exception as inst:
            print_log("parellel trigger:" + str(inst)) 
        self._url = unfolder
        return True

    def ssh_scp_get(self,**params):
        try:
            import paramiko
        except Exception as inst:
            print_log('--Host scp:XXXX need paramiko module on tftp/http server, fail to import python lib paramiko %s' % str(inst) )
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

    def _downloadBuild(self,**args):
        b_protocol = args.setdefault('protocol',self.build_server['protocol'])
        wanted_tar = args.setdefault('tar_file',self.build_info['build_file'])
        source_dir = args.setdefault('source_dir',self.build_server['build_dir'])
        dest_dir = args.setdefault('dest_dir',self.update_server['abs_dir'])
        ftp_ip = args.setdefault('ftp_ip',self.build_server['ip'])
        ftp_user = args.setdefault('ftp_user',self.build_server['user'])
        ftp_pazwd = args.setdefault('ftp_pazwd',self.build_server['password'])
        b_protocol = b_protocol.lower()
        print_log("Connect to ftp server...")
        downloadlist = [wanted_tar]
        temp_file = ''
        if b_protocol in ['ftp']:
            try:
                f = ftplib.FTP(ftp_ip)
            except Exception as inst:
                print_log('Cannot connect to ftp server"%s" with %s' %
                     (ftp_ip, inst))
                print_log('check build from %s failure,retry other build source' % ftp_ip)
                return False
            print_log('Connected to ftp server"%s"' % ftp_ip)

            try:
                f.login(ftp_user, ftp_pazwd)
            except Exception as inst:
                print_log('login failed:%s' % inst)
                f.quit()
                return False
            print_log('login sucessfully')

            try:
                f.cwd(source_dir)
                print_log('tonia:%s' %source_dir)
            except ftplib.error_perm:
                print_log('failed to listed files under %s' %source_dir)
                f.quit()
                return False

            try:
                os.chdir(dest_dir)
                print_log('tonia:%s' %dest_dir)
                f.set_pasv(0)
                for FILE in downloadlist:
                    temp_file = FILE
                    print_log(FILE)
                    print_log('Starting to download build, Please wait ...')
                    fp = open(FILE, 'wb')
                    f.retrbinary('RETR ' + FILE, fp.write, 1024)
                    print_log('file"%s"download successfully' % FILE)
            except ftplib.error_perm:
                print_log('cannot read"%s" from ftpserver retry from urlwebpage' % temp_file)
                f.quit()
                os.unlink(FILE)
                return False
            f.quit()
        elif b_protocol in ['http','https']:
            os.chdir(dest_dir)
            source_dir = b_protocol + '://' + source_dir
            if self.noFallback:
                print_log("build server %s" % str(self.build_server))
                if not re.search(r'https?:\/\/',ftp_ip):
                    source_dir = b_protocol + '://' + ftp_ip
                else:
                    source_dir = ftp_ip
            print_log('for http/https,try maximum 3 times in case network issue')
            retryNum = 0
            maxRetry = 3
            dldResult=True
            while retryNum < maxRetry:
                print_log("count:%s" %retryNum)
                print_log('try source:%s' %source_dir)
                try:
                    for FILE in downloadlist:
                        temp_file = FILE
                        print_log(FILE)
                        print_log('Starting to download build, Please wait ...')
                        downloadBuild(FILE, source_dir, 6, dest_dir)
                        time.sleep(10)
                        print_log('file"%s"download successfully' % FILE)
                except Exception as inst:
                    print_log('cannot retrieve "%s" from urlwebpage retry from remoteserver with exception:%s' % (temp_file,str(inst)))
                    dldResult = False
                    if "Not Found" in inst.reason:
                        return False
                    retryNum = retryNum + 1
                    print_log("retry and sleep 300s")
                    time.sleep(300)
                break
            return dldResult
        elif b_protocol in ['scp','sftp']:
            try:
                for FILE in downloadlist:
                    remote = source_dir + '/' + FILE
                    local = dest_dir + '/' + FILE
                    self.ssh_scp_get(ip=ftp_ip,username=ftp_user,password=ftp_pazwd,local=local,remote=remote,timeout=1800)
                    print_log('file"%s"download successfully' % FILE)
            except Exception as inst:
                print_log('fail to scp tar file:%s' % str(inst))
                if 'Authentication failed' in inst:
                    return False
                try:
                    for FILE in downloadlist:
                        remote = source_dir + '/' + FILE
                        local = dest_dir + '/' + FILE
                        self.ssh_scp_get(ip=ftp_ip,username=ftp_user,password=ftp_pazwd,local=local,remote=remote,timeout=1800)
                        print_log('file"%s"download successfully' % FILE)
                except Exception as inst:
                    print_log('fail to scp tar file:%s' % str(inst))
                    return False
        else:
            print_log('un supported protocol type:%s' % b_protocol)
            return False
        return True

    #def _existHttpBuild(self,source_dir,build_file):
    #    cont = requests.get(source_dir).content
    #    res = re.findall(r'href="(%s)' %build_file,cont.decode())
    #    if res:
    #        return True
    #    else:
    #        return False
    #direct property
    @property
    def url(self):
        return self._url

    @property
    def build_dir(self):
        return self.build_server['build_dir']

    @build_dir.setter
    def build_dir(self,value):
        self.build_server['build_dir'] = str(value)


##################main seq#######################################
def seq1(options):
    try :
    #if True :
        args = {}
        args['build'] = options.build
        args['serverip'] = options.serverip
        args['destDir'] = options.destDir
        args['extraTar'] = options.extraTar
        args['Host'] = options.Host
        args['build_type'] = options.build_type
        args['dr4Flag'] = options.dr4Flag
        args['product'] = options.product
        seq_ins = prepareOSWP_class(args)
        if seq_ins._existsBuildLocal() or ((seq_ins._downloadBuild() or seq_ins._downloadBuild(source_dir=seq_ins.build_server['build_dir2'])) and seq_ins._isTarCompelete() and seq_ins._untarFile() ):
            print_log("download to http/tftp server finished!")
        else :
            seq_ins._downloadBuild(protocol='http',source_dir=seq_ins.PUBLIC_DAILY_BUILD_SERVER)
            if seq_ins._isTarCompelete():
                seq_ins._untarFile()
            if seq_ins._existsBuildLocal() :
                print_log("download build from DAILY SERVER to http/tftp server finish!")
        print_log("url->%s@\npackageme build download success" % seq_ins.url)
        #raise Exception("packageme build download fail!")
    except Exception as inst:
        print_log(str(inst))
        print_log('================================\nstart try legacy utility...')
        destDir = '/tftpboot' if options.destDir == '/tftpboot/official_moswa_build' else options.destDir
        prepareOSWP(options.build, options.serverip, destDir,
                options.extraTar, options.Host, options.build_type,options.dr4Flag)
        print_log("legacy build download")


def seq2(options):
    try :
    #if True :
        args = {}
        args['build'] = options.build
        args['serverip'] = options.serverip
        args['destDir'] = options.destDir
        args['extraTar'] = options.extraTar
        args['Host'] = options.Host
        args['build_type'] = options.build_type
        args['dr4Flag'] = options.dr4Flag
        args['product'] = options.product
        args1 = _parse_host_str(options.Host)
        args.update(args1)
        seq_ins = prepareOSWP_class(args)
        seq_ins.build_dir = args1['build_dir']
        if seq_ins._existsBuildLocal() or ((seq_ins._downloadBuild() or seq_ins._downloadBuild(source_dir=self.build_server['build_dir2'])) and seq_ins._isTarCompelete() and seq_ins._untarFile() ):
            print_log("download to http/tftp server finished!")
        else :
            seq_ins._downloadBuild(protocol='http',source_dir=seq_ins.PUBLIC_DAILY_BUILD_SERVER)
            if seq_ins._isTarCompelete():
                seq_ins._untarFile()
            if seq_ins._existsBuildLocal() :
                print_log("download build from DAILY SERVER to http/tftp server finish!")
        print_log("url->%s@\npackageme build download success" % seq_ins.url)
    except Exception as inst:
        print_log(str(inst))
        print_log('================================\nstart try legacy utility...')
        destDir = '/tftpboot' if options.destDir == '/tftpboot/private_moswa_build' else options.destDir
        prepareOSWP(options.build, options.serverip, destDir,
                options.extraTar, options.Host, options.build_type,options.dr4Flag)
        print_log("legacy build download")

def seq3(options):
    try :
    #if True :
        args = {}
        args['build'] = options.build
        args['serverip'] = options.serverip
        args['destDir'] = options.destDir
        args['extraTar'] = options.extraTar
        args['Host'] = options.Host
        args['build_type'] = options.build_type
        args['dr4Flag'] = options.dr4Flag
        args['product'] = options.product
        args['noFallback'] = options.noFallback
        seq_ins = prepareOSWP_class(args)
        if seq_ins._existsBuildLocal() or (seq_ins._downloadBuild() and seq_ins._isTarCompelete() and seq_ins._untarFile()) :
            print_log("download to http/tftp server finished!")
        else :
            print_log("download to http/tftp server failed!")
            return
        print_log("url->%s@\npackageme build download success" % seq_ins.url)
        #raise Exception("packageme build download fail!")
    except Exception as inst:
        print_log(str(inst))
        print_log("download failed with exception:%s" %inst)
        return

#################seq tool####################################################
def _parse_host_str(host_str) :
    host_dict = {}
    host_str_list = host_str.split(':')
    host_dict['protocol'] = host_str_list[0] 
    host_dict['build_ip'] = host_str_list[1] 
    host_dict['build_dir'] = host_str_list[2] 
    host_dict['build_user'] = host_str_list[3] 
    host_dict['build_pazwd'] = host_str_list[4] 
    return host_dict


################main interface###############################################
if __name__ == '__main__':
    '''
    sample:
        /tmp/.jenkins/packagemeUtility_u.py --action prepareOSWP --build SD_6101.066-cfmb-a.tar --serverip 135.252.245.44 --Host SFTP:135.251.206.186:/home/buildmgr/images:marvel:pazwd --destDir /tftpboot/private_moswa_build/temp --build_type private
        /tmp/.jenkins/packagemeUtility.py --action prepareOSWP --build 6101.326 --serverip 135.252.245.44 --destDir /tftpboot/official_moswa_build --Host ftp:172.21.128.21:/ftpserver/loads:asblab:asblab
    '''
    parser = OptionParser()
    parser.add_option("--action", dest="action",
                      default='', help="oswp action")
    parser.add_option("--build", dest="build", default='',
                      help="oswo build version")
    parser.add_option("--serverip", dest="serverip",
                      default='', help="serverip")
    parser.add_option("--extraTar", dest="extraTar", action="store_true",
                      default=False, help="used to pass -K /tftpboot/atx/loads/5601.472.extra.tar")
    parser.add_option("--destDir", dest="destDir", default='', help="destDir")
    parser.add_option("--Host", dest="Host",
                      default='172.21.128.21', help="Host")
    parser.add_option("--build_type", dest="build_type",
                      default='official', help="build_type")
    parser.add_option("--dr4", dest="dr4Flag",action="store_true",
                      default=False, help="means store dr4 build")
    parser.add_option("--product", dest="product",
                      default='', help="product line")
    parser.add_option("--noFallback", dest="noFallback", action="store_true",
                      default=False, help="means only try download once and do not fallback")

    (options, args) = parser.parse_args(sys.argv[1:])
    if options.noFallback:
        seq3(options)
    elif options.build_type == 'official' :
        seq1(options)
    else :
        seq2(options)

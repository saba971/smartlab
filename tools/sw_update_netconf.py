#!/usr/bin/env python
# coding:utf-8
# Author: Yang Hong <hong.g.yang@nokia-sbell.com>

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter
import time,sys,os,re,shutil,tarfile, json, copy, subprocess
from lxml import etree
import urlNetconf,paramiko


log_ins = None
#http_ip_sh_site = '135.251.206.149' #pulic http/tftp server for all shanghai user
#http_port_sh_site = '8090'
http_ip_sh_site = '135.252.245.38'
http_port_sh_site = ''
nt_ncy_port = '832'
lt_ncy_port = '830'

def current_time():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def print_time(strpr):
    strr = str(current_time() + '>>>' + str(strpr))
    print(strr)
    if log_ins :
        log_ins.writelines(strr + '\n')


###################################COMMON TOOL##################################################
def seq(func_type=''):
    def decorator(func):
        def wrapper(*args,**kwargs):
            self_ins = args[0]
            if self_ins.pboard_id:
                self_ins.print_log(">"*10 + '[' + self_ins.pboard_id + ']  ' + self_ins._step_by_step() + '.' + str(func.__name__) + "<"*10)
            else:
                self_ins.print_log(">"*10 + self_ins._step_by_step() + '.' + str(func.__name__) + "<"*10)
            if func_type == 'netconf':
                if self_ins._check_netconf_state():
                    self_ins._gen_hardcode_xml()
                    return func(*args,**kwargs)
                else:
                    raise AssertionError("fail to connect dut %s:%s!" % (str(self_ins.dut_info['ip']),str(self_ins.dut_info['port'])))
            else :
                return func(*args,**kwargs)
        return wrapper
    return decorator


def turn_str_to_bool(sstr) :
    if isinstance(sstr,bool):
        return sstr
    elif (isinstance(sstr,str) or isinstance(sstr,unicode)):
        sstr = str(sstr)
        if sstr.lower() == 'false':
            return False
        elif sstr.lower() == 'true':
            return True
        else:
            print_time("unknow input %s for bool format" % str(sstr))
            return sstr


def parse_buildserver_str(sstr) :
    ret_dict = {}
    m = re.search('([\w\-]+)@(\d+\.\d+\.\d+\.\d+):([^,]+),(.*)',sstr)
    if m:
        ret_dict['build_ip'] = m.group(2)
        ret_dict['build_user'] = m.group(1)
        ret_dict['build_pazwd'] = m.group(4)
        build_path,build_file = os.path.split(m.group(3))
        ret_dict['build_dir'] = build_path
        ret_dict['build_name'] = build_file
    else:
        temp_list = sstr.split(':')
        ret_dict['build_ip'] = temp_list[0]
        ret_dict['build_port'] = temp_list[1]
        ret_dict['build_user'] = temp_list[2]
        ret_dict['build_pazwd'] = temp_list[3]
        ret_dict['build_dir'] = temp_list[4]
        ret_dict['build_ftp_dir'] = temp_list[5]
    print_time("get build tar info: %s" % str(ret_dict))
    return ret_dict


def parse_updateserver_str(sstr) :
    ret_dict = {}
    temp_list = sstr.split(':')
    ret_dict['update_ip'] = temp_list[0]
    ret_dict['update_port'] = temp_list[1]
    ret_dict['update_user'] = temp_list[2]
    ret_dict['update_pazwd'] = temp_list[3]
    ret_dict['update_abs_dir'] = temp_list[4]
    ret_dict['alias_dir'] = temp_list[5]
    ret_dict['server_port'] = temp_list[6]
    return ret_dict


def parse_std_format(sstr) :
    ret_dict = {}
    temp_list = sstr.split(':')
    ret_dict['ip'] = temp_list[0]
    ret_dict['port'] = temp_list[1]
    ret_dict['user'] = temp_list[2]
    ret_dict['pazwd'] = temp_list[3]
    ret_dict['dir'] = temp_list[4]
    ret_dict['file'] = temp_list[5]
    return ret_dict 


def to_str_dict(uni_dic) :
    str_dic = {}
    for k,vlist in uni_dic.items():
        kn = str(k)
        vnlist = []
        for v in vlist:
            vn = {}
            kv = v.keys()[0]
            vv = str(v[kv])
            kv = str(kv)
            vn[kv] = vv
            vnlist.append(vn)
        str_dic[kn] = vnlist
    return str_dic

#ssh interface object
class Ssh_Client(object):
    '''
    Sample:
    temP = Ssh_Client()
    temP.connect()
    temp1 = temP.send_cmd('ls')
    temP.connect(ip='169.254.1.3') # nat jump,inner ip
    temp1 = temP.send_cmd('ifconfig')
    temP.disconnect()
    '''

    def __init__(self,**args):
        self.INVOKE_BUFF = 99999999
        self.print_log = args.setdefault('print_log',print_time)
        self.ip = args.setdefault('ip','10.9.69.47')
        self.user = args.setdefault('user','root')
        self.pazwd = args.setdefault('password','2x2=4')
        self.port = args.setdefault('port','923')
        self.timeout = args.setdefault('timeout','3')
        self.cmd_timeout = args.setdefault('cmd_timeout',int(self.timeout)*10)
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.current_client = self.client
        self.sftp_file_client = None
        self.terminal = None


    def connect(self,**args):
        ret = False
        ip = args.setdefault('ip',None)
        user = args.setdefault('user','root')
        pazwd = args.setdefault('password','2x2=4')
        #port = args.setdefault('port','22')
        portlist = ['2222','22']
        if ip :
            jump_handler = (self.ip,int(self.port))
            jump_transport = self.current_client.get_transport()
            jump_transport.set_keepalive(15)
            for port in portlist:
                try:
                    remote_handler = (ip,int(port))
                    self.print_log("Trying to login LT from NT with ip + port: %s" % str(remote_handler))
                    jump2remote = jump_transport.open_channel("direct-tcpip",remote_handler,jump_handler)
                    jump_client = paramiko.SSHClient()  
                    jump_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    jump_client.connect('',username=user,password=pazwd,sock=jump2remote)
                    self.current_client = jump_client
                    ret = True
                    break
                except Exception as inst:
                    self.print_log("login LT with ip + port: %s fail due to %s" % (str(remote_handler), inst))

        else :
            if int(self.port) == 22:
                port = '2222'
            else:
                port = '22'

            portlist = [self.port, port]
            for port in portlist:
                try:
                    remote_handler = (self.ip,int(port))
                    self.print_log("try to ssh login dut with ip + port: %s" % str(remote_handler))
                    self.current_client.connect(self.ip,port=int(port),username=self.user,password=self.pazwd,timeout=self.timeout)
                    self.current_client.get_transport().set_keepalive(15)
                    ret = True
                    break
                except Exception as inst:
                    self.print_log("ssh login dut with ip + port: %s fail due to %s" % (str(remote_handler), inst))

        if not ret:
            raise AssertionError ("fail to ssh to dut !!!" )

    def send_cmd(self,cmd):
        self.print_log("input: %s" % str(cmd))
        ret_str = 'output: '
        stdin, stdout, stderr = self.current_client.exec_command(cmd)
        star_time = time.time()
        last_time = 0
        out_section = stdout.read(8192)
        while out_section and last_time < self.cmd_timeout:
            ret_str = ret_str + out_section
            self.print_log(out_section)
            last_time = time.time() - star_time
            out_section = stdout.read(8192)
        return ret_str


    def _init_sftp_client(self):
        if not self.sftp_file_client:
            self.sftp_file_client = paramiko.SFTPClient.from_transport(self.current_client.get_transport())
            
    
    def sftp_get(self,remote_file,local_file):
        self._init_sftp_client()
        self.sftp_file_client.get(remote_file,local_file)


    def sftp_put(self,local_file,remote_file):
        self._init_sftp_client()
        self.sftp_file_client.put(local_file,remote_file)

    
    def interactive_command(self,command,**args):
        if not self.terminal:
            self.terminal = self.current_client.invoke_shell()
        self.terminal.send(command)
        time.sleep(3)
        part_recv = self.terminal.recv(self.INVOKE_BUFF)
        self.print_log(part_recv)
        return part_recv

    def disconnect(self):
        if self.sftp_file_client:
            self.sftp_file_client.close()
        self.current_client.close()        


################################update process instance#########################################
#base class
class Update_Instance(object):
    def __init__(self, args):
        self.args = args
        self.build_server = {}
        self.update_server = {}
        self.local_server = {}
        self.dut_info = {}
        self.build_info = {}
        self.tool_box_dict = {}
        #dut info
        self.dut_info['ip'] = self.args.setdefault('dut_ip',None)
        self.dut_info['port'] = self.args.setdefault('dut_port','830')
        self.dut_info['user'] = self.args.setdefault('dut_user','admin')
        self.dut_info['password'] = self.args.setdefault('dut_password_orgin','admin')
        self.dut_info['second_password'] = self.args.setdefault('dut_password','Netconf#150')
        self.dut_info['clean_db'] = self.args.setdefault('clrDB',True)
        self.dut_info['index_desc'] = self.args.setdefault('nt_type','AF')
        self.dut_info['trans_mode'] = self.args.setdefault('trans_mode','tftp')
        self.dut_info['reborn_port'] = self.args.setdefault('db_port','2222')
        self.dut_info['reborn_pazwd'] = self.args.setdefault('reborn_pazwd','2x2=4')
        self.dut_info['reborn_user'] = self.args.setdefault('reborn_user','root')
        self.dut_info['product'] = self.args.setdefault('product','lightspan')
        #build info
        self.build_info['build'] = self.args.setdefault('build_name', None)
        self.build_info['build_type'] = self.args.setdefault('build_type','MS')#proposal,wild,iwf,trans
        #build server info
        self.build_server['ip'] = self.args.setdefault('build_ip','135.251.206.97')
        self.build_server['port'] = self.args.setdefault('build_port',None)
        self.build_server['user'] = self.args.setdefault('build_user','asblab')
        self.build_server['password'] = self.args.setdefault('build_pazwd','asblab')
        self.build_server['build_dir'] = self.args.setdefault('build_dir','~')
        self.build_server['ftp_dir'] = self.args.setdefault('build_ftp_dir','/loads')
        self.build_server['protocol'] = self.args.setdefault('protocol','ftp')
        #update server info
        self.update_server['ip'] = self.args.setdefault('update_ip',http_ip_sh_site)
        self.update_server['port'] = self.args.setdefault('update_port','')
        self.update_server['user'] = self.args.setdefault('update_user','atxuser')
        self.update_server['password'] = self.args.setdefault('update_pazwd','alcatel01')
        self.update_server['abs_dir'] = self.args.setdefault('update_abs_dir','/tftpboot/official_moswa_build')
        self.update_server['alias_dir'] = self.args.setdefault('alias_dir','official_moswa_build')
        self.update_server['server_port'] = self.args.setdefault('server_port',http_port_sh_site)
        #local shell info
        self.local_server['ip'] = self.args.setdefault('ip','')
        self.local_server['port'] = self.args.setdefault('port','')
        self.local_server['user'] = self.args.setdefault('user','atxuser')
        self.local_server['password'] = self.args.setdefault('pazwd','alcatel01')
        self.local_server['dir'] = self.args.setdefault('dir','.')
        self.local_server['file'] = self.args.setdefault('file','')
        #netconf session instance info
        self.netconf_active = False
        self.netconf_instance = None
        #hardcode command
        self.cleanDB_tup   = ( '/bin/sync',
                               'ls /mnt/nand-dbase/confd-cdb/',
                               'ls /isam/slot_default/fast_db/', 
                               'rm -rf /mnt/nand-dbase/confd-cdb/*.cdb', #the common db dir share by fiber and copper dir like /mnt/persistent/confd-cdb/*
                               'rm -rf /mnt/nand-dbase/confd-cdb/*.xml',
                               'rm -rf /isam/slot_default/fast_db/*',#ALU02505439 introduce fsdb, inconsistent between fsdb and confdDB before AUDIT function(ALU02574954) drop, need clear fsdb manually
                               'rm -rf /mnt/nand-dbase/backup/*', #ALU02706715, to clean up backup db
                               'touch /tmp/dmsu/flag_stop', #ALU02706715, add one command requested by Gu weiwei
                               '/bin/sync',
                               'ls /mnt/nand-dbase/confd-cdb/',
                               'ls /isam/slot_default/fast_db/')                       
        self.rebootFlag_tup = ('/bin/sync',
                               'cat /isam/config/reboot',
                               'echo \"1\" > /isam/config/reboot',
                               '/bin/sync',
                               'cat /isam/config/reboot')
        self.removeRebootLog_tup = ('rm /tmp/reboot_log.tar',
                                    r'rm -rf /mnt/reboot_info/reboot_log_*')
        self.gzipRebootLog_tup = (r"tail -n 1 /mnt/reboot_info/reboot_info | awk -F: '{ print $2 }' | xargs -I {} tar cvf /tmp/reboot_log.tar /mnt/reboot_info/{} && gzip /tmp/reboot_log.tar",)
        self.abort_xml = '' 
        self.download_xml = ''
        self.active_xml = ''
        self.commit_xml = ''
        self.open_remote_xml = ''
        self.clear_db_xml = ''
        #SDFX info
        self.slot_id = self.args.setdefault('slot_id','not_nat')
        if re.match('\d+',self.slot_id):
            self.lt_netconf, self.lt_ip, self.lt_port = self._fx_lt_info(self.slot_id)
            self.dut_info['port'] = self.lt_netconf
            self.dut_info['slot_id'] = self.slot_id
        else:
            self.lt_netconf, self.lt_ip, self.lt_port = ('','','')
        #log info
        self.log_dir = self.args['log_dir'] if ('log_dir' in self.args.keys() and self.args['log_dir']) else ''
        log_ins = urlNetconf.Logger(self.log_dir) if self.log_dir else None
        self.log = self.args.setdefault('log_ins',log_ins)
        self.log_directory,self.log_name = os.path.split(self.log_dir)
        global print_time
        self.print_log = self.args.setdefault('print_log',print_time)
        self.pboard_id = ''
        #private variable for object
        self._step = 0
        self._build_id = ''
        self._build_id_short = ''
        self._build_untar = ''
        self._nt_type_list = []
        self.asb_path = ''
        if ',' in self.dut_info['index_desc']:
            temp_list = self.dut_info['index_desc'].split(',')       
            self._nt_type = temp_list[0]
            self._nt_type_list = temp_list
        else :
            self._nt_type = self.dut_info['index_desc']
            self._nt_type_list = [self.dut_info['index_desc']]
        self.index_file = ''
        self.url = ''
        self.START_TIME = time.time()
        self.UPDATE_PORT = ':' + self.update_server['server_port'] if (self.update_server['server_port'] and self.dut_info['trans_mode'] == 'http') else ''
        self.packagme = False
        self.packagme_sub_dir = ''
        self.preparation_list = ['build_id_guess','build_to_update','gen_index_url']
        self.dashboard = None


    #interface for smoke
    def log_init(self):
        global log_ins
        log_ins = self.log
        

    def _fx_lt_info(self,slot_id=1,board_type='fglt-b'):
        slot_id = int(slot_id)
        netconf_port = 832 + slot_id
        ip_end = 2 + slot_id
        nat_ip = '169.254.1.' + str(ip_end)
        nat_port = '22'
        return str(netconf_port),nat_ip,nat_port


    def local_shell(self,cmd,timeout=3):
        p_ins = subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        stat_time = time.time()
        recv = ''
        err_recv = ''
        while p_ins.poll() is None:
            time.sleep(1)
            recv_n = p_ins.stdout.read()
            err_recv_n = p_ins.stderr.read()
            recv = recv + recv_n
            err_recv = err_recv + err_recv_n
            if time.time() - stat_time > timeout:
                self.print_log('system response time too long')
                p_ins.terminate()
                p_ins.kill()
                break
        if p_ins.poll() is None:
            self.print_log('%s still on going after %s ses, it has been killed now' % (str(cmd), str(timeout)))
        elif p_ins.poll() != 0:
            self.print_log('cmd %s return fail %s' % (str(cmd),str(err_recv)))
        return recv


    def config_data_file(self,**fargs):
        print_log = fargs.setdefault('print_log',self.print_log)
        file_location = fargs.setdefault('file_location','/tmp')
        file_name = fargs.setdefault('file_name','sw_update_config.conf')
        mode = fargs.setdefault('mode','read')
        config_dict = fargs.setdefault('config_dict',{})
        input_str = ''
        config_file = os.path.join(file_location,file_name)
        if mode == 'write':
            with open(config_file,'w') as fc:
                for k,v in config_dict.items():
                    if v:
                        input_str = str(k) + ' = ' + str(v) + '\n'
                    else:
                        input_str = str(k) + ' = ' + 'none' + '\n'
                    fc.writelines(input_str)
        else:
            with open(config_file,'r') as fc:
                expr_line = 'begin'
                while expr_line:
                    expr_line = fc.readline()
                    m = re.match('(\S+) = (\S+)',expr_line)
                    if m:
                        config_dict[m.group(1)] = m.group(2)
        return config_dict

    def _step_by_step(self):
        self._step = self._step + 1
        return str(self._step)

    def _draw_attention(self,**args):
        try:
            if 'dashboard' in args and self.dashboard:
                self.dashboard[self.board_type].update({args['dashboard'].keys()[0]:int(args['dashboard'].values()[0])})
                args.pop('dashboard')
        except Exception as inst:
            pass

        statement = args.pop('statement','')
        self.print_log("*"*100)
        self.print_log("*"+" "*98+"*")
        if statement :
            self.print_log("*  %-95s *" % str(statement))
        for key,val in args.items():
            self.print_log("*   %-15s : %74s   *" % (str(key),str(val)))
        self.print_log("*"+" "*98+"*")
        self.print_log("*"*100)

    def _ssh_list(self,**args):
        ssh_ip = args.setdefault('ssh_ip',self.update_server['ip'])
        ssh_port = args.setdefault('ssh_port','22')
        ssh_user = args.setdefault('ssh_user','atxuser')
        ssh_pazwd = args.setdefault('ssh_pazwd','alcatel01')
        cmd_list = args.setdefault('cmd_list',[])
        timeout = args.setdefault('timeout',20)
        prompt = args.setdefault('prompt','(\[[^\]]+\][\s\S]+(#|\$|%|\s)?)|(reborn#\s*)|($\s)')
        ret_list = []
        ins_client = Ssh_Client(ip=ssh_ip,port=ssh_port,user=ssh_user,password=ssh_pazwd,timeout=timeout,print_log=self.print_log)
        ins_client.connect() 
        for cmd in cmd_list: 
            ret_str = ins_client.send_cmd(cmd)
            ret_list.append(ret_str)
        return ret_list


    def _check_netconf_reset(self,**args):
        _s_time = time.time()
        self.get_download_state(self.netconf_instance,timeout=20)
        _last = time.time() - _s_time
        if _last > 60:
            self.print_log("reboot dut lasts %s" % str(_last))
            return True
        else:
            return False


    def _check_netconf_reset_block(self,**args):
        _s_time = time.time()
        _last = 0
        _max_times = 15
        i = 0
        while not self._check_netconf_reset():
            time.sleep(1)
            i = i + 1
            if i > _max_times:
                return False
        _last = time.time() - _s_time
        self._draw_attention(statement="system has been reset",last_time=str(_last)+' sec')
        return True


    def _check_netconf_state(self,**args):
        timeout = args.setdefault('timeout',20)
        if self.netconf_instance :
            try :
                self.get_download_state(self.netconf_instance,timeout=timeout)
            except :
                try :
                    ret_hello = self.netconf_instance.netconf_connect()
                    self.get_download_state(self.netconf_instance,timeout=timeout)
                except :
                    self.netconf_active = False
                    return False
        else :
            try :
                self.netconf_instance = urlNetconf.ssh_netconf(ip=self.dut_info['ip'], port=self.dut_info['port'], username=self.dut_info['user'], password=self.dut_info['password'],change_password=False,log_ins=self.log,print_log=self.print_log)
                ret_hello = self.netconf_instance.netconf_connect()
                self.get_download_state(self.netconf_instance,timeout=timeout)
            except Exception as inst:
                self.print_log("fail to connect dut %s:%s for %s!" % (self.dut_info['ip'],self.dut_info['port'],str(inst)))
                self.netconf_active = False
                return False
        self.netconf_active = True
        return True

    def _check_netconf_connectivity(self,**args):
        #return false if the rpc channel is closed
        timeout = args.setdefault('timeout',10)
        ret = self.get_download_state(self.netconf_instance,timeout=timeout)
        if 'download' in ret.keys() and ret['download'] == {}:
            return False
        else:
            return True

    def _check_netconf_state_transpose(self,**args):
        return not self._check_netconf_state(**args)

    def _get_active_name(self,**args):
        slist = args.setdefault('getlist',[[],[]])
        out_item = args.setdefault('out_item','name')
        in_item = args.setdefault('in_item','is-active')
        in_val = args.setdefault('in_val','true')
        ret = ''
        try :
            for item_dict in slist :
                if item_dict[in_item] == in_val:
                    ret = item_dict[out_item]
        except :
            self.print_log("fail to get %s from %s" % (str(out_item),str(slist)))
        return ret


    def _check_commit_state(self,**args) :
        index_file = args.setdefault('index_file',self.index_file)
        if self._get_active_name(getlist=self.get_download_state(self.netconf_instance,timeout=20)['revisions'],in_item='name',in_val=index_file,out_item='is-committed') == 'true' :
            return True
        else :
            return False


    def _gen_hardcode_xml(self,**args):
        url = args.setdefault('url',self.url)
        index_file = args.setdefault('index_file',self.index_file)
        remote_open = args.setdefault('remote_open','open')
        board_name = args.setdefault('board_name','Board-Nta')
        self.abort_xml = "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"1\"><action xmlns=\"urn:ietf:params:xml:ns:yang:1\"><hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>Chassis</name><software xmlns=\"urn:bbf:yang:bbf-software-image-management-one-dot-one\"><software><name>application_software</name><download><abort-download><name>%s</name></abort-download></download></software></software></component></hardware-state></action></rpc>" %(index_file)
        self.download_xml = "<rpc message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><action xmlns=\"urn:ietf:params:xml:ns:yang:1\"><hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>Chassis</name><software xmlns=\"urn:bbf:yang:bbf-software-image-management-one-dot-one\"><software><name>application_software</name><download><download-software><url>%s</url><name>%s</name></download-software></download></software></software></component></hardware-state></action></rpc>" %(url, index_file)
        self.active_xml = "<rpc message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><action xmlns=\"urn:ietf:params:xml:ns:yang:1\"><hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>Chassis</name><software xmlns=\"urn:bbf:yang:bbf-software-image-management-one-dot-one\"><software><name>application_software</name><revisions><revision><name>%s</name><activate-revision><activate/></activate-revision></revision></revisions></software></software></component></hardware-state></action></rpc>" %(index_file)   
        self.commit_xml = "<rpc message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><action xmlns=\"urn:ietf:params:xml:ns:yang:1\"><hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>Chassis</name><software xmlns=\"urn:bbf:yang:bbf-software-image-management-one-dot-one\"><software><name>application_software</name><revisions><revision><name>%s</name><commit-revision><commit/></commit-revision></revision></revisions></software></software></component></hardware-state></action></rpc>" %(index_file)
        self.open_remote_xml = "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"1\"><edit-config><target><running/></target><config><system xmlns=\"urn:ietf:params:xml:ns:yang:ietf-system\"><security xmlns=\"urn:ietf:params:xml:ns:yang:nokia-ip-aug\"><tech-support xmlns:ns0=\"urn:ietf:params:xml:ns:netconf:base:1.0\" ns0:operation=\"merge\"><remote-access>%s</remote-access></tech-support></security></system></config></edit-config></rpc>" % remote_open
        self.open_debug_xml = "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"1\"><edit-config><target><running/></target><config><system xmlns=\"urn:ietf:params:xml:ns:yang:ietf-system\"><management xmlns=\"http://www.nokia.com/Fixed-Networks/BBA/yang/nokia-ietf-system-aug\"><debug><ip_itf xmlns:ns0=\"urn:ietf:params:xml:ns:netconf:base:1.0\" ns0:operation=\"merge\"><enable>true</enable></ip_itf></debug></management></system></config></edit-config></rpc>"
        self.open_cli_xml1 = r'<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><edit-config><target><running/></target><config><confdConfig xmlns="http://tail-f.com/ns/confd_dyncfg/1.0"><cli xmlns:ns0="urn:ietf:params:xml:ns:netconf:base:1.0" ns0:operation="merge"><enabled>true</enabled><ssh><enabled>true</enabled><ip>0.0.0.0</ip><port>2024</port></ssh></cli></confdConfig></config></edit-config></rpc>'
        self.open_cli_xml2 = r'<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><edit-config><target><running/></target><config><system xmlns="urn:ietf:params:xml:ns:yang:ietf-system"><management xmlns="http://www.nokia.com/Fixed-Networks/BBA/yang/nokia-ietf-system-aug"><cli><transport><ssh><ip_itf xmlns:ns0="urn:ietf:params:xml:ns:netconf:base:1.0" ns0:operation="merge"><enable>true</enable></ip_itf></ssh></transport></cli></management></system></config></edit-config></rpc>'
        self.clear_db_xml = "<rpc message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><action xmlns=\"urn:ietf:params:xml:ns:yang:1\"><hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>Chassis</name><reset xmlns=\"urn:bbf:yang:bbf-hardware-reset-action\"><reset-type xmlns:rt=\"urn:bbf:yang:nokia-hardware-reset-action-extension\">rt:hardware-reset-to-default-configuration</reset-type></reset></component></hardware-state></action></rpc>"
        self.clear_db_board_xml = "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"1\"><action xmlns=\"urn:ietf:params:xml:ns:yang:1\"><hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>%s</name><reset xmlns=\"urn:bbf:yang:bbf-hardware-reset-action\"><reset-type>hardware-reset</reset-type></reset></component></hardware-state></action></rpc>" % board_name


    def _send_yang_xml(self,send_xml,netconf_instance):
        show_xml = etree.tostring(etree.fromstring(send_xml),pretty_print=True)
        self.print_log("\nsend xml:\n%s\n" % str(show_xml))
        netconf_instance.send_xml(send_xml)
        data = netconf_instance.get_output(60)
        result, error_info = netconf_instance.check_result(data)
        return result


    def _send_trace_cmd(self,cmd_tup,timeout=20):
        if self.slot_id == 'not_nat':
            #ret_list = self._ssh_list(ssh_ip=self.dut_info['ip'],ssh_port=self.dut_info['reborn_port'],ssh_user='root',ssh_pazwd='2x2=4',cmd_list=cmd_tup,prompt='\s#\s',timeout=timeout)
            trace_client = Ssh_Client(ip=self.dut_info['ip'],port=self.dut_info['reborn_port'],user='root',password='2x2=4',timeout=timeout,print_log=self.print_log)
            trace_client.connect()
            ret_list = []
            for cmd in cmd_tup:
                ret_str = trace_client.send_cmd(cmd)
                self.print_log(ret_str)
                ret_list.append(ret_str)
            trace_client.disconnect()
        else:
            lt_peer = Ssh_Client(ip=self.dut_info['ip'],port=self.dut_info['reborn_port'],user='root',password='2x2=4',timeout=timeout,print_log=self.print_log)
            lt_peer.connect()
            self.print_log("NT gateway:\n")
            lt_peer.send_cmd('ifconfig')
            lt_peer.connect(ip=self.lt_ip,timeout=timeout,print_log=self.print_log)
            self.print_log("LT gateway:\n")
            lt_peer.send_cmd('ifconfig')
            ret_list = []
            for cmd in cmd_tup:
                ret_str = lt_peer.send_cmd(cmd)
                ret_list.append(ret_str)
            lt_peer.disconnect()
        return ret_list


    def _backup_nt_trace_cmd(self,cmd_tup,timeout=20,**args):
        backup_nt_ip, backup_nt_port = '10.10.0.2', '2222'
        nt_peer = Ssh_Client(ip=self.dut_info['ip'],port=self.dut_info['reborn_port'],user='root',password='2x2=4',timeout=timeout,print_log=self.print_log)
        nt_peer.connect()
        self.print_log("NT gateway:\n")
        nt_peer.send_cmd('ifconfig')
        nt_peer.connect(ip=backup_nt_ip,port=backup_nt_port,timeout=timeout,print_log=self.print_log)
        self.print_log("2nd NT gateway:\n")
        nt_peer.send_cmd('ifconfig')
        ret_list = []
        for cmd in cmd_tup:
            ret_str = nt_peer.send_cmd(cmd)
            ret_list.append(ret_str)
        nt_peer.disconnect()
        return ret_list


    def _wait_reset(self,**args):
        _s_time = time.time()
        start_wait = args.setdefault('start_wait', 2)
        abort_time = args.setdefault('abort_time', 65535)
        start_time = args.setdefault('start_time', 20)
        long_time = args.setdefault('long_time', 10)
        long_gap = args.setdefault('long_gag', 10)
        short_gap = args.setdefault('short_gag', 1)
        self_des = args.setdefault('self_des', '')
        statement = args.setdefault('statement', '')
        check_func = args.setdefault('check_func', self._check_ssh_alive)
        _e_time = 0
        _flag = False
        _step = 0
        _gap = short_gap
        _last = 0
        time.sleep(start_wait)
        self.print_log("wait for system %s restore after reset..." % str(self_des))
        while not _flag :
            try :
                _flag = check_func()
            except Exception as inst:
                self.print_log ("check %s fail because of %s" % (self_des,str(inst)))
            _last = time.time() - _s_time
            self.print_log("wait %s sec for system %s restore after reboot" % (str(_last),str(self_des)))
            if _last > abort_time :
                return False
            _step = _step + 1
            if _step < start_time :
                _gap = short_gap
            elif _step > start_time and _step < (long_time + start_time) :
                _gap = long_gap
            else :
                _gap = short_gap
            time.sleep(_gap)
        if statement :
            statement = statement
            self._draw_attention(statement=statement,last_time=str(_last)+' sec')
        elif self_des :
            statement = "%s system has been reset" % str(self_des)
            self._draw_attention(statement=statement,last_time=str(_last)+' sec')
        return True


    def _check_ssh_alive(self,**args):
        ip = args.setdefault('ip',self.dut_info['ip'])
        port = args.setdefault('port',self.dut_info['reborn_port'])
        user = args.setdefault('user','root')
        pazwd = args.setdefault('pazwd','2x2=4')
        ret_list = self._ssh_list(ssh_ip=ip,ssh_port=port,ssh_user=user,ssh_pazwd=pazwd,cmd_list=('whoami',),timeout=1)
        if user in ret_list[0] :
            return True
        else :
            return False

    def clean_db(self,**args):
        reset = args.setdefault('reset','')
        double_nt = args.setdefault('double_nt','')
        cmd_tup = args.setdefault('cmd_list',self.cleanDB_tup)
        self._send_trace_cmd(cmd_tup)
        if double_nt:
            self._backup_nt_trace_cmd(cmd_tup)
        self.print_log("clean db operation finished")
        if reset:
            self.reboot_board()
            self.print_log("clean db operation finished")
        return True

    def _set_typec_upgrade_flag(self):
        if not self.dashboard or nt_ncy_port in self.dut_info['port']:
            return

        flag = 'Zynq upgrade succeeded'
        chk_cmd = ("grep 'Zynq upgrade' /isam/logs/info_initlog",)
        res = ''
        try:
            res = self._send_trace_cmd (chk_cmd)
        except Exception as inst:
            self.print_log("fail to get TypeC upgrade flag,%s!"%str(inst))

        self.dashboard[self.board_type].update({"TypeC upgrade": flag in str(res)})

    def clean_db_double_nt(self,**args):
        return self.clean_db(double_nt=True)

    def clean_db_with_reset_build(self,**args):
        return self.clean_db(reset=True)

    def clean_db_rpc(self,**args):
        self._send_yang_xml(self.clear_db_xml,self.netconf_instance)
        if self._check_netconf_reset_block():
            self.print_log("clean db operation finished")
            return True
        else :
            self.print_log("clean db operation fail")
            return False

    def operate_reboot_log(self,**args):
        action = args.setdefault('action', 'NA')
        if action == 'remove':
            cmd_tup = self.removeRebootLog_tup
        elif action == 'gzip':
            cmd_tup = self.gzipRebootLog_tup
        elif action == 'upload':
            password = self.local_server['password']
            timeout= 20
            UploadFlag = False
            if self.slot_id == 'not_nat':
                trace_client = Ssh_Client(ip=self.dut_info['ip'],port=self.dut_info['reborn_port'],user='root',password='2x2=4',timeout=timeout,print_log=self.print_log)
                trace_client.connect()
            else:
                trace_client = Ssh_Client(ip=self.dut_info['ip'],port=self.dut_info['reborn_port'],user='root',password='2x2=4',timeout=timeout,print_log=self.print_log)
                trace_client.connect()
                self.print_log("NT gateway:\r\n")
                trace_client.send_cmd('ifconfig')
                trace_client.connect(ip=self.lt_ip,timeout=timeout,print_log=self.print_log)
                self.print_log("LT gateway:\r\n")
                trace_client.send_cmd('ifconfig')
            #interactive command
            current_time = time.strftime("%Y%m%d_%H%M")
            if re.match('\d+',self.slot_id):
               scp_cmd = (r'scp /tmp/reboot_log.tar.gz %s@%s:/tftpboot/reboot_log_slot%s_%s.tar.gz' %(self.local_server['user'],self.local_server['ip'],str(self.slot_id),current_time))
            else:
               scp_cmd = (r'scp /tmp/reboot_log.tar.gz %s@%s:/tftpboot/reboot_log_nt_%s.tar.gz' %(self.local_server['user'],self.local_server['ip'],current_time))
            self.print_log("input an carriage")
            out = trace_client.interactive_command('\r\n')
            self.print_log("carriage reply is %s" %str(out))
            self.print_log("input scp cmd")
            out = trace_client.interactive_command(scp_cmd+'\r\n')
            self.print_log("scp cmd reply is %s" %str(out))
            if 'fingerprint' in out:
                self.print_log("encounter fingerprint")
                out = trace_client.interactive_command('yes\r\n')
                self.print_log("cmd reply after input yes:%s" % str(out))
            if 'password' in out:
                self.print_log("input password")
                out = trace_client.interactive_command(password+'\r\n')
                self.print_log("cmd reply after input password:%s" % str(out))
                UploadFlag = True
            #wait 5s to upload reboot log file
            time.sleep(5)
            if UploadFlag:
               self.print_log("upload reboot log operation finished")
            else:
               self.print_log("upload reboot log operation fail")
            return True
        else:
            self.print_log("Not a valid action, skip...")
            return True
        self._send_trace_cmd(cmd_tup)
        self.print_log("%s reboot log operation finished" % action)
        return True
    
    def reboot_board(self):
        self._send_trace_cmd(('/sbin/reboot',),timeout=1)
        _start_time = time.time()
        _check_time = 180
        _abort_time = _start_time + _check_time
        while self._check_netconf_connectivity() and time.time() <= _abort_time:
            time.sleep(3)
            self.print_log("system still online for %d sec after reboot cmd send" %  int(time.time() - _start_time))
        #ALU02706715, raise expection when board not reboot actually
        if time.time() > _abort_time:
            raise AssertionError("Board fail to reboot after %s seconds" % str(_abort_time))
        else:
            self.print_log("system successfully reboot within %d seconds" %  int(time.time() - _start_time))
        if self._wait_reset(self_des='reborn os',start_wait=1,long_time=20,check_func=self._check_netconf_connectivity,abort_time=300):
            self.print_log("reset board finished")
        return True

    def get_download_state(self,netconf_instance,**args):
        timeout = args.setdefault('timeout',60)
        module_name = 'urn:bbf:yang:bbf-software-image-management-one-dot-one'
        cmd_string = "get(filter=('subtree','<hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>Chassis</name><software xmlns=\"urn:bbf:yang:bbf-software-image-management-one-dot-one\"><software><name>application_software</name></software></software></component></hardware-state>'))"
        oswp_list = []
        oswp_item_dict = {}
        down_dict = {}
        ret_dict = {}
        ret_dict['download'] = down_dict
        ret_dict['revisions'] = oswp_list
        try:
            ret = ''
            ret = netconf_instance.netconf_operation(cmd_string,timeout=timeout)
            root_xml = etree.fromstring(ret)
        except Exception as inst:
            self.print_log("fail to get message from dut")
            return ret_dict 
        try:
            for child in root_xml.findall('.//{' + module_name + '}revisions')[0].getchildren():
                oswp_item_dict['name'] = child.find('{' + module_name + '}name').text
                oswp_item_dict['name'] = oswp_item_dict['name'].strip("'")
                oswp_item_dict['is-valid'] = child.find('{' + module_name + '}is-valid').text
                oswp_item_dict['is-committed'] = child.find('{' + module_name + '}is-committed').text
                oswp_item_dict['is-active'] = child.find('{' + module_name + '}is-active').text
                oswp_item_dict['version'] = child.find('{' + module_name + '}version').text
                oswp_list.append(dict(oswp_item_dict))
            if '<current-state>' in ret:
                down_dict['download_state'] = root_xml.findall('.//{urn:bbf:yang:bbf-software-image-management-one-dot-one}current-state')[0].find('{urn:bbf:yang:bbf-software-image-management-one-dot-one}state').text
            if '<last-download-state>' in ret:
                down_dict['last_download_state'] = root_xml.findall('.//{urn:bbf:yang:bbf-software-image-management-one-dot-one}last-download-state')[0].find('{urn:bbf:yang:bbf-software-image-management-one-dot-one}state').text 
                down_dict['last_download_version'] = root_xml.findall('.//{urn:bbf:yang:bbf-software-image-management-one-dot-one}last-download-state')[0].find('{urn:bbf:yang:bbf-software-image-management-one-dot-one}software-name').text
        except Exception as inst:
            self.print_log("[get_download_state]" + str(inst)) 
        ret_dict['download'] = down_dict
        ret_dict['revisions'] = oswp_list
        self.print_log("oswp state") 
        self.print_log(str(ret_dict['download'])) 
        self.print_log("revisions state") 
        for revisions_state in ret_dict['revisions']:
            self.print_log(str(revisions_state))
        self.print_log("--*"*40 + "--")
        return ret_dict 


    def build_to_update_local(self):
        _temp_ip = re.sub('\.','_',str(self.dut_info['ip']))
        _temp_ip = re.sub('^\d+_\d+_','',_temp_ip)
        _temp_prefix = _temp_ip + '_' + str(self.dut_info['port']) + '_'
        self._stamp_str = _temp_prefix + str(time.strftime("%m%d%H%M"))
        self.update_server['abs_dir'] = self.update_server['abs_dir'] + '/' + self._stamp_str 
        PORT = self.update_server['port'] if self.update_server['port'] else '22'
        remotescript = '/tmp/.jenkins/packagemeUtility.py'
        cmd = '%s --action prepareOSWP --build %s --serverip %s --destDir %s --Host %s:%s:%s:%s:%s --build_type private' %(remotescript,self.build_info['build'],self.update_server['ip'],self.update_server['abs_dir'],self.build_server['protocol'],self.build_server['ip'],self.build_server['build_dir'],self.build_server['user'],self.build_server['password'])
        self.print_log("cmd %s\n" % str(cmd))
        ret_list = self._ssh_list(ssh_ip=self.update_server['ip'],ssh_port=PORT,ssh_user=self.update_server['user'],ssh_pazwd=self.update_server['password'],cmd_list=(cmd,),timeout=12000)#20 min to wait download
        out_put = ret_list[0]
        if 'legacy build download' in out_put and ('skip download file exists' in out_put or 'download successfully' in out_put) :
            self.packagme = False
            self.print_log("legacy download file %s successfully" % str(self._build_id))
            return "PASS"
        elif 'packageme build download' in out_put :
            self.packagme = True
            self.print_log("packageme download file %s successfully" % str(self._build_id))
            return "PASS"
        else :
            raise AssertionError("fail to download file %s!" % str(self._build_id))


    def gen_index_local(self):
        ssh_port = self.update_server['port'] if self.update_server['port'] else '22'
        untar = re.sub('\.tar$','',self.build_info['build'])
        self.update_server['abs_dir'] = self.update_server['abs_dir'] + '/' + untar 
        cmd1 = 'cd %s;ls' % self.update_server['abs_dir']
        res_list = self._ssh_list(ssh_ip=self.update_server['ip'],ssh_port=ssh_port,ssh_user=self.update_server['user'],ssh_pazwd=self.update_server['password'],cmd_list=(cmd1,),timeout=100)
        ls_output_list = re.findall('L6GQA[ABCDEFGH][\d\w\-\.]+',re.sub('\n',' ',str(res_list[-1])))
        self.print_log("index files are %s " % str(ls_output_list))
        if len(ls_output_list) == 1:
            self.print_log("found only one 'L6GQ*' file in dir %s, get index file %s from file folder without guess" % (str(self.update_server['abs_dir']),str(ls_output_list[0])))
            self.index_file = str(ls_output_list[0])
            self.update_server['alias_dir'] = self.update_server['alias_dir'] + '/' + self._stamp_str + '/' + untar
        elif len(ls_output_list) > 1 :
            for nt_ty_item in self._nt_type_list :
                m = None
                for candidata_item in ls_output_list :
                    m = re.match('L6GQ' + nt_ty_item.upper(),candidata_item)
                    if m :
                        self.index_file = candidata_item
                        self.print_log("get index file %s from -t--index_desc %s--->%s" % (str(self.index_file),str(self._nt_type_list),str(nt_ty_item))) 
                        break 
            self.update_server['alias_dir'] = self.update_server['alias_dir'] + '/' + self._stamp_str + '/' + untar
        elif len(ls_output_list) == 0:
            sub_file = 'L6GQ' + self._nt_type.upper()
            self.update_server['abs_dir'] = self.update_server['abs_dir'] + '/' + sub_file
            cmd1 = 'cd %s;ls' % self.update_server['abs_dir']
            res_list = self._ssh_list(ssh_ip=self.update_server['ip'],ssh_port=ssh_port,ssh_user=self.update_server['user'],ssh_pazwd=self.update_server['password'],cmd_list=(cmd1,),timeout=100)
            ls_output_list = re.findall('(?<=[\n\s])L6GQ[\w\.\-]+(?=[\n\s])|^L6GQ[\w\.\-]+(?=[\n\s])',re.sub('\n',' ',str(res_list[-1])))
            if len(ls_output_list):
                self.print_log("found 'L6GQ*' file in dir %s, get index file %s from file folder without guess" % (str(self.update_server['abs_dir']),str(ls_output_list[0])))
                self.index_file = str(ls_output_list[0])
            self.update_server['alias_dir'] = self.update_server['alias_dir'] + '/' + self._stamp_str + '/' + untar + '/' + sub_file
        else :
            self.index_file = 'L6GQ' + self._nt_type.upper() + self._build_id_short 
            self.update_server['alias_dir'] = self.update_server['alias_dir'] + '/' + self._stamp_str + '/' + untar + '/' + sub_file
        self.url =  self.dut_info['trans_mode'] + '://' + self.update_server['ip'] + self.UPDATE_PORT + '/' + self.update_server['alias_dir'] + '/' + self.index_file
        self.print_log("index file :\n\t%s\n" % self.index_file)
        self.print_log("url :\n\t%s\n" % self.url)
        return {'index_file':self.index_file,'url':self.url}

    #[seq main step]
    @seq('none')
    def build_id_guess(self):
        build_id = str(self.build_info['build'])
        self.print_log('input build id is: %s' % build_id)
        m = re.match('(\d{2,4})\.(\d{3,6})', build_id)
        if m:
            #standard build id format like: 62.001, 6201.123 and 2009.123456
            self._build_id = build_id
            if len(m.group(1)) == 2 or (len(m.group(1)) == 4 and int(m.group(1)) < 6000):
                self._build_id_short = build_id
            else:
                self._build_id_short = m.group(1)[0:2] + '.' + m.group(2)
            self._build_untar = self.dut_info['product'] + '_' + self._build_id
            self.print_log('build id: %s' % self._build_id)
            self.print_log('build id for short: %s' % self._build_id_short)
            self.print_log('build untar: %s' % self._build_untar)
        else:
            #other build id format like: lightspan_6203.123.tar, lightspan_2009.456.tar
            self._build_untar = re.sub('\.tar$', '', build_id)
            self._build_id = re.sub('\w+_', '', self._build_untar)
            m = re.match('(\d{2,4})\.(\d{3,6})', self._build_id)
            if m:
                if len(m.group(1)) == 2 or (len(m.group(1)) == 4 and int(m.group(1)) < 6000):
                    self._build_id_short = self._build_id
                else:
                    self._build_id_short = m.group(1)[0:2] + '.' + m.group(2)
            self.print_log('build id: %s' % self._build_id)
            self.print_log('build id for short: %s' % self._build_id_short)
            self.print_log('build untar: %s ' % self._build_untar)

    @seq('none')
    def show_get_info(self):
        self.print_log('dut info:\n%s\n' % str(self.dut_info)) 
        self.print_log('build info:\n%s\n' % str(self.build_info)) 
        self.print_log('build server:\n%s\n' % str(self.build_server)) 
        self.print_log('update server:\n%s\n' % str(self.update_server)) 

    @seq('none')
    def build_to_update(self):
        if self.build_info['build_type'] == 'MS' :
            ssh_port = self.update_server['port'] if self.update_server['port'] else '22'
            remotescript = '/tmp/.jenkins/packagemeUtility.py'
            cmd = '%s --action prepareOSWP --build %s --serverip %s --destDir %s --Host %s:%s:%s:%s:%s' %(remotescript,self._build_id,self.update_server['ip'],self.update_server['abs_dir'],self.build_server['protocol'],self.build_server['ip'],self.build_server['ftp_dir'],self.build_server['user'],self.build_server['password'])
            #cmd = 'ls' 
            ret_list = self._ssh_list(ssh_ip=self.update_server['ip'],ssh_port=ssh_port,ssh_user=self.update_server['user'],ssh_pazwd=self.update_server['password'],cmd_list=(cmd,),timeout=12000)#20 min to wait download
            out_put = ret_list[0]
            if 'legacy build download' in out_put and ('skip download file exists' in out_put or 'download successfully' in out_put) :
                self.packagme = False
                self._build_untar = 'SD_' + self._build_id #legacy moswa in SD tar 
                if self.update_server['ip'] == http_ip_sh_site :
                    self.update_server['alias_dir'] = ''
                self.print_log("legacy download file %s successfully" % str(self._build_id))
                return "PASS"
            elif 'packageme build download' in out_put :
                self.packagme = True
                self.print_log("packageme download file %s successfully" % str(self._build_id))
                return "PASS"
            else :
                raise AssertionError("fail to download file %s!" % str(self._build_id))

    @seq('none')
    def gen_index_url(self):
        if self.build_info['build_type'] == 'MS' and (not self.packagme) :
            self.index_file = 'L6GQ' + self._nt_type.upper() + self._build_id_short 
            UPDATE_DIR = self.update_server['alias_dir'] + '/' if self.update_server['alias_dir'] else ''
            self.url =  self.dut_info['trans_mode'] + '://' + self.update_server['ip'] + self.UPDATE_PORT + '/' + UPDATE_DIR + self._build_untar + '/' + self.index_file
        elif self.packagme:
            self.index_file = 'L6GQ' + self._nt_type.upper() + self._build_id_short 
            self.packagme_sub_dir = 'L6GQ' + self._nt_type.upper()
            UPDATE_DIR = self.update_server['alias_dir'] if self.update_server['alias_dir'] else '' 
            self.url =  self.dut_info['trans_mode'] + '://' + self.update_server['ip'] + self.UPDATE_PORT + '/' + UPDATE_DIR + '/' + self._build_untar + '/' + self.packagme_sub_dir + '/' + self.index_file
        self.print_log("index file :\n\t%s\n" % self.index_file)
        self.print_log("url :\n\t%s\n" % self.url)
        return {'index_file':self.index_file,'url':self.url}

    @seq('netconf')
    def check_state(self):
        get_list=self.get_download_state(self.netconf_instance,timeout=20)['revisions']
        if self.index_file == self._get_active_name(getlist=get_list) and ((not self._build_id_short) or self._build_id_short == self._get_active_name(getlist=get_list,out_item='version')) :
            self.print_log ("do not need to update sw %s, active build have the same index file %s" % (str(self.build_info['build']),str(self.index_file))) 
        return get_list

    @seq('netconf')
    def download_build(self):
        state_list = self.get_download_state(self.netconf_instance,timeout=20)['revisions']
        #commit
        if len(state_list) == 2 :
            for i in state_list :
                if i['is-active'] == 'true' and i['is-committed'] == 'false':
                    temp_name = i['name']
                    self.commit_build(index_file=temp_name)   
                    self._gen_hardcode_xml()
        #trigger download
        retry_time = 3
        wait_time =0.5 
        start_time = 0
        end_time = 0
        self._send_yang_xml(self.download_xml,self.netconf_instance)
        for ii in range(retry_time) :
            if not start_time :
                start_time = time.time()
            time.sleep(wait_time)
            state_list = self.get_download_state(self.netconf_instance,timeout=20)['download']
            pro_flag = ('download_state' in state_list) and (state_list['download_state'] == 'in-progress')
            if pro_flag:
                break
            wait_time = wait_time * 1.5
        if not state_list['download_state'] == 'in-progress' :
            raise AssertionError("fail to trigger download file %s!" % str(self._build_id))
        #wait download
        if self.build_info['build_type'] == 'MS' :
            star_wait_time = 30 
        else :
            star_wait_time = 5
        wait_time = 1 
        abort_time = 65535
        check_time = 0
        while pro_flag:  
            end_time = time.time()
            last_time = end_time-start_time
            if last_time > abort_time :
                raise AssertionError("download file %s takes too long time %s s!" % (str(self._build_id),str(last_time)))
            self.print_log ("download time lasts for %s s" % str(last_time))
            time.sleep(wait_time)
            check_time = check_time + 1
            if check_time > 10  and check_time < 20 :
                wait_time = star_wait_time
            else :
                wait_time = 1
            state_list = self.get_download_state(self.netconf_instance,timeout=20)['download']
            pro_flag = ('download_state' in state_list) and (state_list['download_state'] == 'in-progress')
        time.sleep(10)
        state_list = self.get_download_state(self.netconf_instance,timeout=20)['download']
        if 'download_state' in state_list :
            if state_list['download_state'] == 'idle' and state_list['last_download_state'] == 'successful' and state_list['last_download_version'] == str(self.index_file) :
                self.print_log("download %s success" % str(self.index_file))
            else :
                self.get_download_state(self.netconf_instance,timeout=20)
                raise AssertionError("download file %s fail" % (str(self._build_id)))
        elif self.index_file == self._get_active_name(getlist=self.get_download_state(self.netconf_instance,timeout=20)['revisions']) :
            self.print_log("download %s success" % str(self.index_file))
        else :
            self.get_download_state(self.netconf_instance,timeout=20)
            raise AssertionError("download file %s fail" % (str(self._build_id)))
        self._draw_attention(statement="download finished!",last_time=str(last_time)+' sec',index_file=self.index_file,dashboard={'Download':last_time})


    def open_remote_access(self,**args):
        remote_open = args.setdefault('remote_open','open')
        result = self._send_yang_xml(self.open_remote_xml,self.netconf_instance)
        if result == 'PASS':
            self.print_log("Open remote access successfully")
        else:
            self.print_log("Open remote access xml is not accepted")
        return True

    def open_remote_debug(self,**args):
        result = self._send_yang_xml(self.open_debug_xml,self.netconf_instance)
        self.print_log("Open remote debug successfully")
        self.print_log(result)
        return True

    def open_remote_cli(self,**args):
        self._send_yang_xml(self.open_cli_xml1,self.netconf_instance)
        self._send_yang_xml(self.open_cli_xml2,self.netconf_instance)
        self.print_log("Open remote cli successfully")
        return True

    @seq('netconf')
    def active_build(self,**args):
        self.print_log("remove the old reboot log before activate...")
        self.open_debug_and_cli_access() and self.operate_reboot_log(action='remove')
        if self.dut_info['clean_db'] and self.clean_db(): 
            self.print_log("clean db finished, begin to active operation...")
        #trigger active
        active_s_time = time.time()
        self._send_yang_xml(self.active_xml,self.netconf_instance)
        retry_time = 50
        start_wait = 5
        for i in range(retry_time) :
            self.print_log("%d time to retrieve activation status" % i)
            if self._wait_reset(check_func=self._check_netconf_state,start_wait=start_wait) and \
                self.index_file == self._get_active_name(getlist=self.get_download_state(self.netconf_instance,timeout=20)['revisions']) :
                self.print_log("active operation finished!")
                break
            start_wait = start_wait + 5
            wait_time = time.time() - active_s_time
            self.print_log("wait for active reboot lasts %s sec!" % str(wait_time))
            if int(wait_time) > 1800:
                self.print_log("gzip reboot log after activate...")
                self.operate_reboot_log(action='gzip')
                if self.local_server['ip']:
                    self.print_log("upload reboot log because this is a failure case...")
                    self.operate_reboot_log(action='upload')
                raise AssertionError("active operation fail, wait too long time...")
            #self._send_yang_xml(self.active_xml,self.netconf_instance)
        if self._get_active_name(getlist=self.get_download_state(self.netconf_instance,timeout=20)['revisions'],in_item='name',in_val=self.index_file,out_item='is-active') == 'true' :
            ac_last = time.time() - active_s_time
            self._draw_attention(statement="active operation success!",last_time=str(ac_last)+' sec',dashboard={'Activate':ac_last})
            self.open_debug_and_cli_access()
            self._set_typec_upgrade_flag()
        else :
            self.print_log("gzip reboot log after activate...")
            self.operate_reboot_log(action='gzip')
            if self.local_server['ip']:
                self.print_log("upload reboot log because this is a failure case...")
                self.operate_reboot_log(action='upload')
            raise AssertionError("active operation fail!")

    @seq('netconf')
    def commit_build(self,**args):
       index_file = args.setdefault('index_file',self.index_file)
       commit_timeout = int(args.setdefault('commit_timeout',180))
       self._gen_hardcode_xml(index_file=index_file)
       commit_s_time = time.time()
       self._send_yang_xml(self.commit_xml,self.netconf_instance)
       retry_time = commit_timeout
       for i in range(retry_time) :
            time.sleep(1)
            if self._check_commit_state(index_file=index_file) :
                cm_last = time.time() - commit_s_time
                self._draw_attention(statement="commit operation success!", last_time=str(cm_last) + ' sec',dashboard={'Commit': cm_last})
                break
       else:
           raise AssertionError("commit operation fail!")

    @seq('none')
    def clean_env(self):
       getlist=self.get_download_state(self.netconf_instance,timeout=20)['revisions']
       if self.index_file == self._get_active_name(getlist=getlist) and \
              self.index_file == self._get_active_name(getlist=getlist,in_item='is-committed'):
          self.print_log("sw update success %s" % str(self.index_file))
          self._draw_attention(statement="sw update success!",build_tar=self._build_untar,index_file=self.index_file,last_time=str(time.time()-self.START_TIME)+' sec') 
       else :
          self.print_log("sw update fail %s, is-active and is-committed is not true" % str(self.index_file))
          raise AssertionError("sw update success fail!")
       if self.netconf_active :
          self.netconf_instance.netconf_disconnect()

    def open_debug_and_cli_access(self,**args):
        self.open_remote_access()
        self.open_remote_debug()
        self.open_remote_cli()

    #devops pipeline interface
    def __call__(self,build_step):
        if build_step == "preparation":
            for step_func in self.preparation_list:
                getattr(self,step_func)()
            input_dict = {}
            input_dict['url'] = self.url
            input_dict['index_file'] = self.index_file
            input_dict['dut_ip'] = self.dut_info['ip']
            input_dict['dut_port'] = self.dut_info['port']
            input_dict['db_port'] = self.dut_info['reborn_port']
            input_dict['slot_id'] = self.slot_id
            input_dict['asb_path'] = self.asb_path
            input_dict['START_TIME'] = self.START_TIME
            path, filename = os.path.split(self.log_dir)
            input_dict['path'] = path if path else 'none'
            input_dict['filename'] = filename if filename else 'none'
            file_location = self.log_directory if self.log_directory else '/tmp/'
            self.config_data_file(file_location=file_location,mode='write',config_dict=input_dict)
        elif build_step in self.tool_box_dict.keys():
            self.tool_box_dict[build_step]()
        else:
            file_location = self.log_directory if self.log_directory else '/tmp/'
            output_dict = self.config_data_file(file_location=file_location)
            self.url = output_dict['url']
            self.index_file = output_dict['index_file']
            self.dut_info['ip'] = output_dict['dut_ip']
            self.dut_info['port'] = output_dict['dut_port']
            self.dut_info['reborn_port'] = output_dict['db_port']
            self.slot_id = output_dict['slot_id']
            self.asb_path = output_dict['asb_path']
            self.START_TIME = float(output_dict['START_TIME'])
            path = output_dict['path']
            filename = output_dict['filename']
            if filename != 'none':
                filename = build_step + '_' + filename
                if path != 'none':
                    path_filename = os.path.join(path, filename)
                else:
                    path_filename = filename
                global log_ins
                log_ins = urlNetconf.Logger(path_filename)
                self.log = log_ins
            if re.match('\d+',self.slot_id):
                self.lt_netconf, self.lt_ip, self.lt_port = self._fx_lt_info(self.slot_id)
                self.dut_info['port'] = self.lt_netconf
                self.dut_info['slot_id'] = self.slot_id
            self.check_state()
            if build_step in ['clean_env']:
                getattr(self,build_step)()
            else:
                getattr(self,build_step + '_build')()


    #[seq property interface]
    @property
    def URL(self):
        return self.url

    @URL.setter
    def URL(self,value):
        self.url = str(value)

    @property
    def NAME(self):
        return self.index_file

    @NAME.setter
    def NAME(self,value):
        self.index_file = str(value)

    @property
    def NETCONF(self):
        return self.netconf_instance

    @NETCONF.setter
    def NETCONF(self,value):
        self.netconf_instance

#derive class
class Tool_Box(Update_Instance):
    def __init__(self, args):
        super(Tool_Box,self).__init__(args)
        self.tool_box_dict['reboot_flag'] = self.set_reboot_flag
        self.tool_box_dict['upload_reboot_info'] = self.upload_reboot_info

    def upload_reboot_info(self,**args):
        '''
        upload reboot debug info in '/mnt/reboot_info/*' to local server
        '''
        #data init
        file_location = args.setdefault('file_location',self.local_server['dir'])
        user = args.setdefault('user',self.local_server['user'])
        ip = args.setdefault('ip',self.local_server['ip'])
        port = args.setdefault('port',self.local_server['port'])
        password = args.setdefault('password',self.local_server['password'])
        timeout = args.setdefault('timeout','10')
        #pcta file location
        if file_location == '.':
            file_location = os.getcwd()
        elif os.path.isfile(file_location):
            file_location,_ = os.path.split(file_location)
            if not file_location:
                file_location = os.getcwd()
        file_location = os.path.join(file_location,'reboot_info_' + str(time.strftime("%Y%m%d%H%M%S",time.localtime())))
        if not os.path.exists(file_location):
            os.makedirs(file_location)
        #scp cmd
        scp_cmd = 'scp -P %s -r /mnt/reboot_info/ %s@%s:%s/.' % (port,user,ip,file_location)
        password = '%s' % password
        #init ssh client
        if self.slot_id == 'not_nat':
            trace_client = Ssh_Client(ip=self.dut_info['ip'],port=self.dut_info['reborn_port'],user='root',password='2x2=4',timeout=timeout,print_log=self.print_log)
            trace_client.connect()
            trace_client.send_cmd('ifconfig')
        else:
            trace_client = Ssh_Client(ip=self.dut_info['ip'],port=self.dut_info['reborn_port'],user='root',password='2x2=4',timeout=timeout,print_log=self.print_log)
            trace_client.connect()
            self.print_log("NT gateway:\n")
            trace_client.send_cmd('ifconfig')
            trace_client.connect(ip=self.lt_ip,timeout=timeout,print_log=self.print_log)
            self.print_log("LT gateway:\n")
            trace_client.send_cmd('ifconfig')
        #interactive command
        trace_client.interactive_command('\r')
        out = trace_client.interactive_command('ls /mnt/reboot_info\r')
        self.print_log(str(out))
        out = trace_client.interactive_command(scp_cmd+'\r')
        self.print_log(str(out))
        if 'fingerprint' in out:
            '''
            Host '135.51.2.2' is not in the trusted hosts file.
            (ecdsa-sha2-nistp256 fingerprint sha1!! f6:a0:43:97:52:33:57:dc:a3:ac:c4:3a:5c:1a:a9:8c:b3:f1:c9:63)
            Do you want to continue connecting? (y/n)
            '''
            out = trace_client.interactive_command('yes\r')
            self.print_log(str(out))
        if 'password' in out:
            '''
            ~ # scp -P 22 -r reboot_info/ atxuser@135.251.247.233:/home/hongya_lib/atxuser/robot/ULKS/MOSWA/NCY_USER_KW/reboot_info_20191219125018/.
            atxuser@135.251.247.233's password: 
            '''
            out = trace_client.interactive_command(password+'\r')
            self.print_log(str(out))
        trace_client.send_cmd('ls /mnt/reboot_info/')


    def set_reboot_flag(self,**args):
        self._send_trace_cmd(self.rebootFlag_tup,timeout=1)


#derived class
class Atx_Instance(Update_Instance):
    #derived class special for atx server,build server would mount on the tftp server
    def __init__(self, args):
        super(Atx_Instance,self).__init__(args)
        self.pcta_ip = self.args.setdefault('pcta_ip',None)
        self.mount_dir = self.args.setdefault('mount_dir','/ftpserver/RLAB')
        self.server_dir = self.args.setdefault('server_dir','/tftpboot')
        self.timestamp = time.strftime("%Y%m%d%H%M%S",time.localtime())
        self.build_path = ''
        self.asb_path = ''
        self.server_path = ''
        self.tar_file = ''
        self.untar_file = ''
        self.sub_dir = ''
        self.build_type = 'lightspan'#leagecy
        self.preparation_list = ['init_data','build_to_update']


    def atx_print(self,strpr):
        strr = str('atx::' + current_time() + '>>>' + str(strpr))
        strpr1 = re.sub('#','_NUMBER_',str(strr))
        strpr1 = re.sub('\$','_DOLLAR_',strpr1)
        strpr1 = re.sub('%','_PERCENT_',strpr1)
        print(strpr1)
        if self.log :
            self.log.writelines(strr + '\n')
  
 
    def _os(self,cmd):
        self.atx_print('input<--\n%s' % str(cmd))
        ret = subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
        self.atx_print('output-->\n%s' % str(ret))
        return ret 
        

    def _config_ip_get(self):
        cmd = '/sbin/ifconfig -a | grep inet | grep -v 127.0.0.1 | grep -v inet6 '
        ip_str = self._os(cmd)
        cmd = '/sbin/route -n'
        gw_str = self._os(cmd)
        result = ''
        ip_list = re.findall('inet addr\:(\d+\.\d+\.\d+\.\d+)',ip_str)#centos 6
        m = re.search('\n0\.0\.0\.0\s+((\d+\.\d+)\.\d+\.\d+)',gw_str) 
        start_head = m.group(2) if m else '135'
        if ip_list :
            for item in ip_list:
                if item.startswith(start_head):
                    result = item
                    break
            if not result :            
                result = ip_list[0]
        else :
            ip_list = re.findall('inet\s+(\d+\.\d+\.\d+\.\d+)',ip_str)#centos 7
            m = re.search('\n0\.0\.0\.0\s+((\d+\.\d+)\.\d+\.\d+)',gw_str) 
            start_head = m.group(2) if m else '135'
            if ip_list :
                for item in ip_list:
                    if item.startswith(start_head):
                        result = item
                        break
                if not result :            
                    result = ip_list[0]
        return result


    def _list_index_file(self,file_list=[]):
        m_str = self.sub_dir if self.sub_dir else 'L6GQ'
        temp_list = filter(lambda x:re.match(m_str,x),file_list)
        if temp_list:
            self.index_file = temp_list[0] 
        elif self._build_id_short:
            self.index_file = self.sub_dir + self._build_id_short
        else:
            self.atx_print("fail to guess the index_file")    
        return self.index_file


    @seq('none')
    def init_data(self):
        self.build_path = self.timestamp + '-OSWP_UPDATE_DPU'
        self.tar_file = self.build_info['build']
        self.untar_file = re.sub('\.tar$','',self.tar_file)
        self.sub_dir = 'L6GQ' + self.dut_info['index_desc']
        self.pcta_ip = self.pcta_ip if self.pcta_ip else self._config_ip_get()
        m = re.search('((\d\d)\d?\d?\.(\d\d\d))',self.tar_file)
        if m :
            self._build_id = m.group(1)
            self._build_id_short = m.group(2) + '.' + m.group(3)
        if self.tar_file.startswith('lightspan_'):
            self.build_type = 'lightspan'
        elif self.tar_file.startswith('SD_'):
            self.build_type = 'leagecy'
        elif self.tar_file.startswith('ZACEAA'):
            self.build_type = 'lightspan'
        if self.dut_info['trans_mode'] == 'http':
            self.server_dir = '/http'
        self.asb_path = self.server_dir + '/' + self.build_path
        self.atx_print("build path %s\nasb_path %s\ntar_file %s\nuntar_file %s\nbuild id %s\nip %s\n" % (self.build_path,self.asb_path,self.tar_file,self.untar_file,self._build_id,self.pcta_ip) )
        self.atx_print("netconf ip: %s" % self.dut_info['ip'])
        self.atx_print("netconf: port %s" % self.dut_info['port'])
        self.atx_print("user: %s" % self.dut_info['user'])
        self.atx_print("password: %s" % self.dut_info['password'])
        self.atx_print("second password: %s" % self.dut_info['second_password'])
        self.atx_print("index file: %s" % self.dut_info['index_desc'])
        self.atx_print("trans mode: %s" % self.dut_info['trans_mode'])
        self.atx_print("reborn port: %s" % self.dut_info['reborn_port'])
    

    @seq('none')
    def build_to_update(self): 
        if not os.path.exists(self.asb_path):
            os.makedirs(self.asb_path)
        self.atx_print('start cp file %s' % self.tar_file)
        shutil.copyfile(os.path.join(self.mount_dir,self.tar_file),os.path.join(self.asb_path,self.tar_file))
        self.atx_print('file %s is copy to %s' % (self.tar_file,self.asb_path))
        self.server_path = os.path.join(self.asb_path,self.untar_file)
        if not os.path.exists(self.server_path):
            os.makedirs(self.server_path)
        temp_tar_dir = os.path.join(self.asb_path,self.tar_file)
        self.atx_print('start untar file %s' % self.tar_file)
        tarFF = tarfile.open(temp_tar_dir,'r')
        tarFF.extractall(path=self.asb_path)
        tarFF.close() 
        self.atx_print('untar file %s finished' % self.tar_file)
        os.remove(temp_tar_dir)
        _temp_sub_dir = os.path.join(self.asb_path,self.sub_dir)
        if os.path.exists(_temp_sub_dir):
            file_list = os.listdir(_temp_sub_dir)
            self.url = self.dut_info['trans_mode'] + '://' + self.pcta_ip + '/' + re.sub(self.server_dir + '/','',_temp_sub_dir) 
        else:
            file_list = os.listdir(self.asb_path)
            self.url = self.dut_info['trans_mode'] + '://' + self.pcta_ip + '/' + re.sub(self.server_dir + '/','',self.asb_path) 
        self._list_index_file(file_list=file_list)
        self.url = self.url + '/' + self.index_file
        self.atx_print('URL %s' % self.url)
        self.atx_print('NAME %s' % self.index_file)


    @seq('none')
    def clean_env(self):
        if self.index_file == self._get_active_name(getlist=self.get_download_state(self.netconf_instance,timeout=20)['revisions']) :
            self.atx_print("sw update success %s" % str(self.index_file))
            self._draw_attention(statement="sw update success!",build_tar=self._build_untar,index_file=self.index_file,last_time=str(time.time()-self.START_TIME)+' sec')
            try:
                shutil.rmtree(self.asb_path)
            except Exception as inst:
                self.print_log("clean env fail: " + str(inst))
        else :
            raise AssertionError("sw update success fail!")
        if self.netconf_active :
            self.netconf_instance.netconf_disconnect()

    
#derived class
class Robot_Instance(Update_Instance):
    #derived class special for robot api in mgmt.py
    def __init__(self, args):
        super(Robot_Instance,self).__init__(args)
        from robot.api import logger #depend on robot api
        self.logger = logger
        self.UPLOAD_BUILD = self.args.setdefault('UPLOAD_BUILD','None')
        args['MS'] = turn_str_to_bool(args['MS'])
        self.MS = self.args.setdefault('MS',True)
        self.build_server['build_dir'],self.build_info['build'] = os.path.split(self.UPLOAD_BUILD)
        self._build_id = ''
        self._stamp_str = ''
        self.packagme = True
        if 'SD_' in self.build_info['build']:
            self.packagme = False
        elif 'lightspan_' in self.build_info['build']:
            self.packagme = True


    def robot_print(self,strpr,level='info'):
        strr = str('robot::' + current_time() + '>>>' + str(strpr))
        if level == 'info':
            self.logger.info(strr)
        elif level == 'debug':
            self.logger.debug(strr)
        else :
            self.logger.warn(strr)
        if self.log :
            self.log.writelines(strr + '\n')


    def parse_build_id(self):
        m = re.search('(\d{2,4}\.\d+)',self.build_info['build'])
        if m:
            self._build_id = m.group(1)
            self.robot_print("OSWP build id %s" % (self._build_id))
        else :
            self.robot_print("faild to get build id %s from path %s" % (self.build_info['build'],self.UPLOAD_BUILD))
        self.robot_print('\nbuild tar %s\ndut_info %s\nbuild_server %s\nupdate_server %s' % (str(self.build_info['build']),str(self.dut_info),str(self.build_server),str(self.update_server)),level='debug')

    
    @seq('none')
    def build_to_update_ci_local(self):
        return super(Robot_Instance,self).build_to_update_local()


    @seq('none')
    def gen_index_ci_local(self):
        return super(Robot_Instance,self).gen_index_local()


    def build_to_update(self):
        global print_time
        print_time = self.robot_print
        if self.MS:
            super(Robot_Instance,self).build_to_update()
        elif self.update_server['ip'] == http_ip_sh_site:
            self.build_server['protocol'] = 'sftp'
            self.update_server['abs_dir'] = '/tftpboot/private_moswa_build'
            self.update_server['alias_dir'] = 'private_moswa_build'
            self.build_to_update_ci_local()
             

    def gen_index_url(self):
        if self.MS:
            temp_list = str(self._build_id).split('.')
            self._build_id_short = temp_list[0][0:2] + '.' + temp_list[1]
            if self.dut_info['product'] == 'lightspan' :
                self._build_untar = self.dut_info['product'] + '_' + self._build_id 
            super(Robot_Instance,self).gen_index_url()
        elif self.update_server['ip'] == http_ip_sh_site:
            self.gen_index_ci_local()


    def get_index_file(self):
        self.robot_print(self.NAME,level='debug')
        self.robot_print(self.URL,level='debug')
        return(self.NAME,self.URL)


#derived class
class Developer_Instance(Update_Instance):
    #derived class special for developer
    def __init__(self, args):
        super(Developer_Instance,self).__init__(args)
        self._stamp_str = ''
        self.packagme = True
        self.build_type = self.args.setdefault('build_type','LIS')
        if 'SD_' in self.build_info['build']:
            self.packagme = False
        elif 'lightspan_' in self.build_info['build']:
            self.packagme = True
        self.preparation_list = ['build_to_update', 'gen_index_url']


    def build_to_update(self):
        global print_time
        if self.build_type == 'official':
            super(Developer_Instance,self).build_to_update()
        elif self.update_server['ip'] == http_ip_sh_site:
            self.build_server['protocol'] = 'sftp'
            self.update_server['abs_dir'] = '/tftpboot/private_moswa_build'
            self.update_server['alias_dir'] = 'private_moswa_build'
            self.build_to_update_developer()
        else :
            self.build_server['protocol'] = 'sftp'
            self.build_to_update_developer()
    

    def gen_index_url(self):
        if self.build_type == 'official':
            temp_list = str(self._build_id).split('.')
            self._build_id_short = temp_list[0][0:2] + '.' + temp_list[1]
            if self.dut_info['product'] == 'lightspan' :
                self._build_untar = self.dut_info['product'] + '_' + self._build_id 
            super(Developer_Instance,self).gen_index_url()
        elif self.update_server['ip'] == http_ip_sh_site:
            self.gen_index_developer()
        else :
            self.build_server['protocol'] = 'sftp'
            self.gen_index_developer()

        
    @seq('none')
    def build_to_update_developer(self):
        return super(Developer_Instance,self).build_to_update_local()


    @seq('none')
    def gen_index_developer(self):
        return super(Developer_Instance,self).gen_index_local()


    def clean_env(self):
        getlist = self.get_download_state(self.netconf_instance,timeout=20)['revisions']
        if self.index_file == self._get_active_name(getlist=getlist) and \
               'true' == self._get_active_name(getlist=getlist,out_item='is-committed') :
            self.print_log("sw update success %s" % str(self.index_file))
            self._draw_attention(statement="sw update success!",build_tar=self._build_untar,index_file=self.index_file,last_time=str(time.time()-self.START_TIME)+' sec')
            ssh_port = self.update_server['port'] if self.update_server['port'] else '22'
            upd_cli = Ssh_Client(ip=self.update_server['ip'],port=ssh_port,user=self.update_server['user'],password=self.update_server['password'],timeout=12,print_log=self.print_log)
            upd_cli.connect()
            out_put = upd_cli.send_cmd('rm -rf %s' % self.update_server['abs_dir'])
            upd_cli.disconnect()
        else :
            raise AssertionError("sw update success fail!")
        if self.netconf_active :
            self.netconf_instance.netconf_disconnect()


#derived class
class Parallel_Instance(Update_Instance):
    #provide function with coroutine
    def __init__(self, args):
        super(Parallel_Instance,self).__init__(args)
        self.board_type = self.args.setdefault('board_type','BOARD')
        self.suppress, self.board_type = self._check_suppress_board(self.board_type)
        self.pboard_id = self.args.setdefault('pboard_id','%s@%s:%s' % (self.board_type,self.dut_info['ip'],self.dut_info['port']))
        self.print_log = self.print_time_with_board_id
        self.log_ins = self.log
        self.log_ins_board = urlNetconf.Logger(args['log_dir_board']) if ('log_dir_board' in args) and args['log_dir_board'] else None
        self.plan_rpc = {'sub_board_id':'Slot-' + self.slot_id + '_' + self.board_type, 'sub_board_parent':'Slot-Lt-' + self.slot_id, 'sub_board_type':self.board_type}
        self.board_error_report = 'OK'
        self.clean_db_parallel = self.clean_db

    def _check_suppress_board(self,dirty_board_type):
        m = re.match('^0([\w\-\_]*)',dirty_board_type)
        if m :
            return (True,m.group(1))
        else :
            return (False,dirty_board_type)


    def print_time_with_board_id(self,sster):
        sster = '[' + self.pboard_id + ']' + ' ' + sster
        sster = str(current_time() + '>>>' + str(sster))
        print(sster)
        if self.log_ins :
            self.log_ins.writelines(sster + '\n')
        if self.log_ins_board :
            self.log_ins_board.writelines(sster + '\n')


    def _gen_planboard_hardcode_xml(self,args):
        sub_board_id = args.setdefault('sub_board_id',self.plan_rpc['sub_board_id'])
        sub_board_parent = args.setdefault('sub_board_parent',self.plan_rpc['sub_board_parent'])
        sub_board_type = args.setdefault('sub_board_type',self.plan_rpc['sub_board_type'])
        self.plan_rpc_xml = "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"1\"><edit-config><target><running/></target><config><hardware xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>%s</name><parent>%s</parent><parent-rel-pos>1</parent-rel-pos><mfg-name>ALCL</mfg-name><model-name xmlns=\"urn:bbf:yang:bbf-hardware-extension\">%s</model-name><class xmlns:nokia-hwi=\"http://www.nokia.com/Fixed-Networks/BBA/yang/nokia-hardware-identities\">nokia-hwi:lt</class></component></hardware></config></edit-config></rpc>" % (sub_board_id,sub_board_parent,sub_board_type)
        self.get_sub_board_state = "<hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>%s</name></component></hardware-state>" % (sub_board_id)


    def _gen_hardcode_check_nt_xml(self):
        self.check_nt_xml = "<hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><class xmlns:nokia-hwi=\"http://www.nokia.com/Fixed-Networks/BBA/yang/nokia-hardware-identities\">nokia-hwi:nt</class></component></hardware-state>"


    def _check_planned_state(self,**args):
        timeout = args.setdefault('timeout',60)
        module_name = 'urn:ietf:params:xml:ns:yang:ietf-hardware'
        cmd_string = "get(filter=('subtree','%s'))" % self.get_sub_board_state
        ret = self.netconf_instance.netconf_operation(cmd_string,timeout=timeout)
        board_state = ''
        try:
            board_state = etree.fromstring(ret).find('.//{' + module_name + '}oper-state').text
        except Exception as inst:
            self.print_log(str(inst))
        return board_state


    @seq('netconf')
    def download_build_parallel(self,**args):
        state_list = self.get_download_state(self.netconf_instance,timeout=20)['revisions']
        #commit
        if len(state_list) == 2 :
            for i in state_list :
                if i['is-active'] == 'true' and i['is-committed'] == 'false':
                    temp_name = i['name']
                    self.commit_build(index_file=temp_name)   
                    self._gen_hardcode_xml()
        #trigger download
        retry_time = 5
        wait_time =0.5 
        start_time = 0
        end_time = 0
        for ii in range(retry_time) :
            if ii == 0 :
                self._send_yang_xml(self.download_xml,self.netconf_instance)
            if not start_time :
                start_time = time.time()
            yield False
            time.sleep(wait_time)
            state_list = self.get_download_state(self.netconf_instance,timeout=20)['download']
            pro_flag = ('download_state' in state_list) and (state_list['download_state'] == 'in-progress')
            if pro_flag:
                break
            wait_time = wait_time + 0.5
        if not state_list['download_state'] == 'in-progress' :
            raise AssertionError("fail to trigger download file %s!" % str(self._build_id))
        #wait download
        if self.build_info['build_type'] == 'MS' :
            star_wait_time = 20 
        else :
            star_wait_time = 5
        wait_time = 1 
        abort_time = 65535
        check_time = 0
        while pro_flag:  
            end_time = time.time()
            last_time = end_time-start_time
            if last_time > abort_time :
                raise AssertionError("download file %s takes too long time %s s!" % (str(self._build_id),str(last_time)))
            self.print_time_with_board_id ("download time lasts for %s s" % str(last_time))
            time.sleep(wait_time)
            check_time = check_time + 1
            if check_time > 15  and check_time < 30 :
                wait_time = star_wait_time
            else :
                wait_time = 1
            yield False
            state_list = self.get_download_state(self.netconf_instance,timeout=20)['download']
            pro_flag = ('download_state' in state_list) and (state_list['download_state'] == 'in-progress')
        time.sleep(10)
        yield False
        state_list = self.get_download_state(self.netconf_instance,timeout=20)['download']
        if 'download_state' in state_list :
            if state_list['download_state'] == 'idle' and state_list['last_download_state'] == 'successful' and state_list['last_download_version'] == str(self.index_file) :
                self.print_time_with_board_id("download %s success" % str(self.index_file))
            else :
                self.get_download_state(self.netconf_instance,timeout=20)
                raise AssertionError("download file %s fail" % (str(self._build_id)))
        elif self.index_file == self._get_active_name(getlist=self.get_download_state(self.netconf_instance,timeout=20)['revisions']) :
            self.print_time_with_board_id("download %s success" % str(self.index_file))
        else :
            self.get_download_state(self.netconf_instance,timeout=20)
            raise AssertionError("download file %s fail" % (str(self._build_id)))
        self._draw_attention(statement="download finished!",last_time=str(last_time)+' sec',index_file=self.index_file,dashboard={'Download': last_time})

        state = yield True
        while not state:
            state = yield True
     

    @seq('netconf')
    def active_build_parallel(self,**args):
        self.print_time_with_board_id("remove the old reboot log before activate...")
        self.open_debug_and_cli_access() and self.operate_reboot_log(action='remove')
        if self.dut_info['clean_db'] and self.clean_db(): 
            self.print_time_with_board_id("clean db finished, begin to active operation...")
        #trigger active
        active_s_time = time.time()
        self._send_yang_xml(self.active_xml,self.netconf_instance)
        yield False
        retry_time = 50
        start_wait = 5
        for i in range(retry_time) :
            self.print_log("%d time to retrieve activation status" % i)
            if self._wait_reset(check_func=self._check_netconf_state,start_wait=start_wait) and \
                self.index_file == self._get_active_name(getlist=self.get_download_state(self.netconf_instance,timeout=20)['revisions']) :
                self.print_time_with_board_id("active operation finished!")
                break
            start_wait = start_wait + 5
            wait_time = time.time() - active_s_time
            self.print_time_with_board_id("wait for active reboot lasts %s sec!" % str(wait_time))
            #self._send_yang_xml(self.active_xml,self.netconf_instance)
            if int(wait_time) > 1800:
                self.print_time_with_board_id("gzip reboot log after activate...")
                self.operate_reboot_log(action='gzip')
                if self.local_server['ip']:
                    self.print_time_with_board_id("upload reboot log because this is a failure case...")
                    self.operate_reboot_log(action='upload')
                raise AssertionError("active operation fail, wait too long time...")
        if self._get_active_name(getlist=self.get_download_state(self.netconf_instance,timeout=20)['revisions'],in_item='name',in_val=self.index_file,out_item='is-active') == 'true' :
            ac_last = time.time() - active_s_time
            self._draw_attention(statement="active operation success!",last_time=str(ac_last)+' sec',dashboard={'Activate': ac_last})
            self.open_debug_and_cli_access()
            self._set_typec_upgrade_flag()
        else :
            self.print_time_with_board_id("gzip reboot log after activate...")
            self.operate_reboot_log(action='gzip')
            if self.local_server['ip']:
                self.print_time_with_board_id("upload reboot log because this is a failure case...")
                self.operate_reboot_log(action='upload')
            raise AssertionError("active operation fail!")
        state = yield True
        while not state:
            state = yield True


    @seq('netconf')
    def commit_build_parallel(self,**args):
        index_file = args.setdefault('index_file',self.index_file)
        commit_timeout = int(args.setdefault('commit_timeout',30))
        self._gen_hardcode_xml(index_file=index_file)
        commit_s_time = time.time()
        self._send_yang_xml(self.commit_xml,self.netconf_instance)
        yield False
        retry_time = commit_timeout
        for i in range(retry_time) :
            yield False
            time.sleep(1)
            if self._check_commit_state(index_file=index_file) :
                cm_last = time.time() - commit_s_time
                self._draw_attention(statement="commit operation success!", last_time=str(cm_last) + ' sec',dashboard={'Commit': cm_last})
                break
        else:
            raise AssertionError("commit operation fail!")
        state = yield True
        while not state:
            state = yield True


    @seq('netconf')
    def check_if_double_nt(self):
        self._gen_hardcode_check_nt_xml()
        module_name = 'urn:ietf:params:xml:ns:yang:ietf-hardware'
        cmd_string = "get(filter=('subtree','%s'))" % self.check_nt_xml
        ls_nt_xml = self.netconf_instance.netconf_operation(cmd_string,timeout=5)
        nt_component = './/{' + module_name + '}component' 
        nt_component_list = etree.fromstring(ls_nt_xml).findall(nt_component)
        if len(nt_component_list) == 2 :
            return True
        else :
            return False


    def reboot_board_parallel(self):
        self._send_trace_cmd(('/sbin/reboot',),timeout=1)
        yield False
        _last_time = 0
        _abort_time = 60
        START_T = time.time()
        while self._check_netconf_state() and _last_time < _abort_time:
            yield False
            time.sleep(3)
            self.print_log("system still online for %s sec after reboot cmd send" % str(_last_time))
            _last_time = time.time() - START_T
        if self._wait_reset(self_des='reborn os',start_wait=1,long_time=20,check_func=self._check_netconf_state):
            self.print_log("reset board finished")
        state = yield True
        while not state:
            state = yield True


    def clean_db_with_reset_parallel(self,**args):
        reset = args.setdefault('reset','reset')
        cmd_tup = args.setdefault('cmd_list',self.cleanDB_tup)
        self._send_trace_cmd(cmd_tup)
        self.print_log("clean db operation finished")
        if reset:
            #for py2
            #yield from self.reboot_board_parallel()
            self._send_trace_cmd(('/sbin/reboot',),timeout=1)
            yield False
            _last_time = 0
            _abort_time = 180
            while self._check_netconf_state() and _last_time < _abort_time:
                yield False
                time.sleep(3)
                self.print_log("system still online for %s sec after reboot cmd send" % str(_last_time))
                _last_time = _last_time + 3
            if self._wait_reset(self_des='reborn os',start_wait=1,long_time=20,check_func=self._check_netconf_state):
                self.print_log("reset board finished")
        self.print_log("clean db operation finished")
        state = yield True
        while not state:
            state = yield True


    @seq('netconf')
    def plan_sub_board(self,args,check_time=5):
        no_check = args.pop('no_check','')
        self._gen_planboard_hardcode_xml(args)
        if no_check or self._check_planned_state() == 'enabled':
            return True
        self._send_yang_xml(self.plan_rpc_xml,self.netconf_instance)
        s_time = time.time()
        time.sleep(5)

        while self._check_planned_state() != 'enabled':
            self.print_log("checking LT state after planning...")
            if time.time() - s_time > check_time:
                break
            time.sleep(10)

        if self._check_planned_state() == 'enabled':
            self.print_log("plan LT %s OK" % str(args['sub_board_id']))
            return True
        else:
            self.print_log("plan LT %s fail" % str(args['sub_board_id']))
            return False


    @classmethod
    def pop_fail_board(cls,upd_list):
        ret_list = []
        for b_item in upd_list:
            if b_item.board_error_report == 'OK':
                ret_list.append(b_item)
        return ret_list

    @classmethod
    def board_event_loop(cls,func,instance_list,**params):
        loop_mode = params.setdefault('loop_mode','abort')
        commit_timeout = int(params.setdefault('commit_timeout',30))
        gen_list = []
        for board_item in instance_list:
            board_gen = getattr(board_item,func)(commit_timeout=commit_timeout)
            #py2 not support yield from
            try:
                board_gen.send(None)
            except Exception as inst:
                error_record = current_time() + ':[' + board_item.pboard_id + ']@' + func + '  ' + str(inst)
                board_item.print_log(error_record)
                board_item.board_error_report = error_record if board_item.board_error_report == 'OK' \
                                          else board_item.board_error_report + '\n' + error_record
                instance_list.remove(board_item)
                if loop_mode == 'abort':
                    board_item.print_log(str(inst))
                    raise inst
            gen_list.append((board_item,board_gen))
        jury = False
        while not jury:
            #jury = all([ i.send(jury) for i in gen_list ])
            twe_angry_men = []
            for board_obj,gen in gen_list:
                #py2 not support yield from
                try:
                    judge = False
                    judge = gen.send(jury)
                except Exception as inst:
                    error_record = current_time() + ':[' + board_obj.pboard_id + ']@' + func + '  ' + str(inst)
                    board_obj.print_log(error_record)
                    board_obj.board_error_report = error_record if board_obj.board_error_report == 'OK' \
                                          else board_obj.board_error_report + '\n' + error_record
                    instance_list.remove(board_obj)
                    judge = error_record if judge is False else judge
                    if loop_mode == 'abort':
                        board_obj.print_log(str(inst))
                        raise inst
                twe_angry_men.append(judge) 
            jury = all(twe_angry_men)


#derived derived class
class Multi_Instance(Developer_Instance,Parallel_Instance):
    #derived class for trigger private build sw upgrade on multi board 
    def __init__(self, args):
        super(Multi_Instance,self).__init__(args)


#derived derived class
class Atx_Parallel_Instance(Atx_Instance,Parallel_Instance):
    #derived class for trigger atx sw upgrade on multi board 
    def __init__(self, args):
        super(Atx_Parallel_Instance,self).__init__(args)
        self.print_log = self.atx_parallel_print

    def atx_parallel_print(self,strpr):
        strr = str('atx::' + current_time() + '>>>' + str(strpr))
        strr = '[' + self.pboard_id + ']' + ' ' + strr
        strpr1 = re.sub('#','_NUMBER_',str(strr))
        strpr1 = re.sub('\$','_DOLLAR_',strpr1)
        strpr1 = re.sub('%','_PERCENT_',strpr1)
        print(strpr1)
        if self.log_ins :
            self.log_ins.writelines(strr + '\n')
        if self.log_ins_board :
            self.log_ins_board.writelines(strr + '\n')


#derived derived class
class Smartlab_Instance(Parallel_Instance,Tool_Box):
    #derived class for trigger smartlab sw upgrade on multi board 
    def __init__(self, args):
        super(Smartlab_Instance,self).__init__(args)
        self.no_fallback = self.args.setdefault('no_fallback',False)
        self.preparation_list = ['build_id_guess','build_to_update','gen_index_url']

    def set_board_name(self):
        board_suffix=''
        if self.board_type=='BOARD' and lt_ncy_port in self.dut_info['port']:
            try:
                check_board_xml = "get(filter=('subtree','<hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>Board</name><model-name/></component></hardware-state>'))"
                ret = self.netconf_instance.netconf_operation(check_board_xml, timeout=10)
                self.board_type = re.findall(r"<model-name>(.+?)</model-name>",ret)[0]
            except Exception as inst:
                self.print_log("fail to get board model-name: %s" % str(inst))

        if nt_ncy_port in self.dut_info['port']:
            if self.check_if_double_nt():
                board_suffix ='_duplex'
            else:
                board_suffix = '_simplex'

        self.board_type = self.board_type.upper() + board_suffix

        self.dashboard ={
            self.board_type:
                {'Build':self.build_info['build'],
                 "Configuration load": 0,
                 "CFG_DB": "Default",
                 "ONUMGNT": "Embeded",
                 "WITH_AV": False,
                 "TypeC upgrade": False
                 }
        }
    @seq('none')
    def build_to_update(self): 
        if self.update_server['port']:
            PORT = self.update_server['port']
        else:
            PORT = '22'  
        remotescript = '/tmp/.jenkins/packagemeUtility.py'
        cmd = '%s --action prepareOSWP --build %s --serverip %s --destDir %s --Host %s:%s:%s:%s:%s' %(remotescript,self._build_id,self.update_server['ip'],self.update_server['abs_dir'],self.build_server['protocol'],self.build_server['ip'],self.build_server['ftp_dir'],self.build_server['user'],self.build_server['password'])
        if self.no_fallback:
            cmd = cmd + ' --noFallback'
        upd_cli = Ssh_Client(ip=self.update_server['ip'],port=PORT,user=self.update_server['user'],password=self.update_server['password'],timeout=1200,print_log=self.print_log)
        upd_cli.connect()
        out_put = upd_cli.send_cmd(cmd)
        upd_cli.disconnect()
        if 'legacy build download' in out_put and ('skip download file exists' in out_put or 'download successfully' in out_put) :
            self.packagme = False
            self._build_untar = 'SD_' + self._build_id #legacy moswa in SD tar 
            if self.update_server['ip'] == http_ip_sh_site and self.build_info['build_type'] == 'MS':
                self.update_server['alias_dir'] = ''
            self.print_log("legacy download file %s successfully" % str(self._build_id))
            return "PASS"
        elif 'packageme build download' in out_put :
            self.packagme = True
            res = re.search('url->(.+)@',out_put)
            try:
                if res:
                    dir_untar = res.group(1)
                    self._build_untar = dir_untar.split('/')[-1]
            except Exception as inst:
                self._build_untar = 'lightspan_' + self._build_id 
            self.print_log("packageme download file %s successfully" % str(self._build_id))
            return "PASS"
        else :
            raise AssertionError("fail to download file %s!" % str(self._build_id))

    @seq('none')
    def gen_index_url(self):
        ssh_port = self.update_server['port'] if self.update_server['port'] else '22'
        if re.search('.tar',self.build_info['build']):
            untar = re.sub('\.tar$','',self.build_info['build'])
        else:
            untar = self._build_untar
        self.update_server['abs_dir'] = self.update_server['abs_dir'] + '/' + untar 
        cmd1 = 'cd %s;ls' % self.update_server['abs_dir']
        res_list = self._ssh_list(ssh_ip=self.update_server['ip'],ssh_port=ssh_port,ssh_user=self.update_server['user'],ssh_pazwd=self.update_server['password'],cmd_list=(cmd1,),timeout=100)
        ls_output_list = re.findall('L6GQA[ABCDEFGH][\d\w\-\.]+',re.sub('\n',' ',str(res_list[-1])))
        self.print_log("index files are %s " % str(ls_output_list))
        if len(ls_output_list) == 1:
            self.print_log("found only one 'L6GQ*' file in dir %s, get index file %s from file folder without guess" % (str(self.update_server['abs_dir']),str(ls_output_list[0])))
            self.index_file = str(ls_output_list[0])
            self.update_server['alias_dir'] = self.update_server['alias_dir'] + '/' + untar
        elif len(ls_output_list) > 1 :
            for nt_ty_item in self._nt_type_list :
                m = None
                for candidata_item in ls_output_list :
                    m = re.match('L6GQ' + nt_ty_item.upper(),candidata_item)
                    if m :
                        self.index_file = candidata_item
                        self.print_log("get index file %s from -t--index_desc %s--->%s" % (str(self.index_file),str(self._nt_type_list),str(nt_ty_item))) 
                        break 
            self.update_server['alias_dir'] = self.update_server['alias_dir'] + '/' + untar
        elif len(ls_output_list) == 0:
            sub_file = 'L6GQ' + self._nt_type.upper()
            self.update_server['abs_dir'] = self.update_server['abs_dir'] + '/' + sub_file
            cmd1 = 'cd %s;ls' % self.update_server['abs_dir']
            res_list = self._ssh_list(ssh_ip=self.update_server['ip'],ssh_port=ssh_port,ssh_user=self.update_server['user'],ssh_pazwd=self.update_server['password'],cmd_list=(cmd1,),timeout=100)
            ls_output_list = re.findall('(?<=[\n\s])L6GQ[\w\.\-]+(?=[\n\s])|^L6GQ[\w\.\-]+(?=[\n\s])',re.sub('\n',' ',str(res_list[-1])))
            if len(ls_output_list):
                self.print_log("found 'L6GQ*' file in dir %s, get index file %s from file folder without guess" % (str(self.update_server['abs_dir']),str(ls_output_list[0])))
                self.index_file = str(ls_output_list[0])
            self.update_server['alias_dir'] = self.update_server['alias_dir'] + '/' +  untar + '/' + sub_file
        else :
            self.index_file = 'L6GQ' + self._nt_type.upper() + self._build_id_short 
            self.update_server['alias_dir'] = self.update_server['alias_dir'] + '/' +  untar + '/' + sub_file
        self.url =  self.dut_info['trans_mode'] + '://' + self.update_server['ip'] + self.UPDATE_PORT + '/' + self.update_server['alias_dir'] + '/' + self.index_file
        self.print_log("index file :\n\t%s\n" % self.index_file)
        self.print_log("url :\n\t%s\n" % self.url)
        return {'index_file':self.index_file,'url':self.url}


##########################################SEQ#######################################################
def simple_seq():
    one_produce = Update_Instance(args)
    one_produce.build_id_guess() 
    one_produce.show_get_info()
    one_produce.build_to_update()
    one_produce.gen_index_url()
    #moswa step
    one_produce.check_state()
    one_produce.download_build()
    one_produce.active_build()
    one_produce.commit_build()
    one_produce.clean_env()

def atx_seq(build_T='official'):
    global print_time
    if args['csv_file']:
        lib_path = os.environ['ROBOTREPO'] +'/LIBS/DATA_TRANSLATION'
        if lib_path not in sys.path:
            sys.path.append(lib_path)
        setupfile = args['csv_file']
        if args['csv_file'].lower().endswith('.yaml') or args['csv_file'].lower().endswith('.yml'):
            try :
                from yaml_parser import get_node
                kwargs = { 'index': 0, 'file': setupfile, 'caseless': True}
                args['dut_port'] = str(get_node('OAM/NCY/Port',**kwargs))
                args['db_port'] = str(get_node('OAM/TnD/Port',**kwargs))
            except Exception as inst:
                print_time ("import yaml_parser failed! %s,parse yaml file need robot LIBS." % (inst))
        else:
            try :
                import data_translation 
                data_translation.create_global_tables(setupfile)       
                SDOLT_DICT = data_translation.get_table_line('LTData')
                args['dut_port'] = SDOLT_DICT['port']
                args['db_port'] = SDOLT_DICT['trace_port']
                print_time ("dut port and reborn port has been updated by csv file")
            except Exception as inst:
                print_time ("import data_translation failed! %s,parse csv file need robot LIBS." % (inst))
    atx_pro = Atx_Instance(args)
    print_time = atx_pro.atx_print # atx remote call would abort while there are #%$ in print out put
    if build_T == 'official':
        atx_pro.init_data()
        atx_pro.build_to_update()
        #moswa step
        atx_pro.check_state()
        atx_pro.download_build()
        atx_pro.active_build()
        atx_pro.commit_build()
    atx_pro.clean_env()

def developer_seq():
    de_pro = Developer_Instance(args)
    de_pro.build_to_update()
    de_pro.gen_index_url()
    #moswa step
    de_pro.check_state()
    de_pro.download_build()
    de_pro.active_build()
    de_pro.commit_build()
    de_pro.clean_env()

def devops_pipeline_seq(**seq_args):
    ci_mode = seq_args.setdefault('ci_mode','')
    build_step = seq_args.setdefault('build_step','')
    if ci_mode == 'atx':
        ins = Atx_Instance(args)
    elif ci_mode == 'developer':
        ins = Developer_Instance(args)
    else:
        ins = Update_Instance(args)
    ins(build_step)

def devops_pipeline_seq_parallel(**seq_args):
    pass

def tool_box_seq(**seq_args):
    build_step = seq_args.setdefault('build_step','')
    ins = Tool_Box(args)
    ins(build_step)

def SDFX_parallel_seq(branch_env='',loop_mode='abort'):
    #nt data
    nt_board_slot, nt_board_type = map(str,args['board_info']['NT'][0].items()[0])
    nt_args = copy.deepcopy(args)
    nt_args['board_type'] = nt_board_type#key param
    path, filename = ('','')
    if args['log_dir']:
        path, filename = os.path.split(args['log_dir'])
        nt_args['log_dir_board'] = os.path.join(path,'NT' + '_' + filename)
    #lt data
    lt_args_list = []
    for lt_item in args['board_info']['LT']:
        lt_args_part1 = {}
        lt_slot, lt_type = map(str,lt_item.items()[0])
        if lt_slot == "0":
            break
        lt_args_part1['slot_id'] = lt_slot#key param
        lt_args_part1['board_type'] = lt_type#key param
        #init lt args
        lt_args = copy.deepcopy(args)
        lt_args.update(lt_args_part1)
        if filename:
            lt_args['log_dir_board'] = os.path.join(path,'LT' + str(lt_slot) + '_' + filename)
        lt_args.pop('board_info')
        lt_args_list.append(lt_args)
    #init ins
    if branch_env == 'atx':
        setupfile_flag = False
        if nt_args['csv_file'] :
            try :
                lib_path = os.environ['ROBOTREPO'] +'/LIBS/DATA_TRANSLATION'
                if lib_path not in sys.path:
                    sys.path.append(lib_path)
                import data_translation 
                data_translation.create_global_tables(nt_args['csv_file'])       
                SDOLT_DICT = data_translation.get_table_line('NTData')
                nt_args['dut_port'] = SDOLT_DICT['nt_port']
                nt_args['db_port'] = SDOLT_DICT['nt_trace_port']
                setupfile_flag = True
            except Exception as inst:
                print ("import data_translation failed! %s,parse csv file need robot LIBS." % (inst))
        nt_upd = Atx_Parallel_Instance (nt_args)
        if setupfile_flag:
            nt_upd.print_log ("dut port and reborn port has been updated by csv file")
        nt_upd.init_data()
        nt_upd.build_to_update()
        nt_active_name = nt_upd._get_active_name(getlist=nt_upd.check_state())
        nt_upd_flag = 'nt need update'
        nt_upd.print_log("nt active lead file %s" % str(nt_active_name))
        if nt_upd.suppress \
                and nt_upd.NAME == nt_active_name \
                :
            nt_upd_flag = None
        lt_upd_list = []
        lt_keep_list = []
        lt_suppress_list = []
        for lt_args in lt_args_list:
            lt_args['db_port'] = nt_upd.dut_info['reborn_port']
            lt_upd = Atx_Parallel_Instance(lt_args)
            if lt_upd.suppress :
                lt_suppress_list.append(lt_upd)
            else :
                lt_upd.NAME = nt_upd.NAME
                lt_upd.URL = nt_upd.URL
                lt_active_name = lt_upd._get_active_name(getlist=lt_upd.check_state())
                lt_upd.print_log("lt active lead file %s" % str(lt_active_name))
                if lt_upd.NAME == lt_active_name :
                    lt_keep_list.append(lt_upd)
                else:
                    lt_upd_list.append(lt_upd)
    elif branch_env == 'developer':
        nt_upd = Multi_Instance(nt_args)
        nt_upd.build_to_update() 
        nt_upd.gen_index_url()
        nt_active_name = nt_upd._get_active_name(getlist=nt_upd.check_state())
        nt_upd_flag = 'nt need update'
        nt_upd.print_log("nt active lead file %s" % str(nt_active_name))
        if nt_upd.suppress \
                and nt_upd.NAME == nt_active_name \
                :
            nt_upd_flag = None
        lt_upd_list = []
        lt_keep_list = []
        lt_suppress_list = []
        for lt_args in lt_args_list:
            lt_upd = Multi_Instance(lt_args)
            if lt_upd.suppress :
                lt_suppress_list.append(lt_upd)
            else :
                lt_upd.NAME = nt_upd.NAME
                lt_upd.URL = nt_upd.URL
                lt_active_name = lt_upd._get_active_name(getlist=lt_upd.check_state())
                lt_upd.print_log("lt active lead file %s" % str(lt_active_name))
                if lt_upd.NAME == lt_active_name :
                    lt_keep_list.append(lt_upd)
                else:
                    lt_upd_list.append(lt_upd)
    else:
        nt_upd = Parallel_Instance(nt_args)
        nt_upd.build_id_guess() 
        nt_upd.show_get_info()
        nt_upd.build_to_update()
        nt_upd.gen_index_url()
        nt_active_name = nt_upd._get_active_name(getlist=nt_upd.check_state())
        nt_upd_flag = 'nt need update'
        nt_upd.print_log("nt active lead file %s" % str(nt_active_name))
        if nt_upd.suppress \
                and nt_upd.NAME == nt_active_name \
                :
            nt_upd_flag = None
        lt_upd_list = []
        lt_keep_list = []
        lt_suppress_list = []
        for lt_args in lt_args_list:
            lt_upd = Parallel_Instance(lt_args)
            if lt_upd.suppress :
                lt_suppress_list.append(lt_upd)
            else :
                lt_upd.NAME = nt_upd.NAME
                lt_upd.URL = nt_upd.URL
                lt_active_name = lt_upd._get_active_name(getlist=lt_upd.check_state())
                lt_upd.print_log("lt active lead file %s" % str(lt_active_name))
                if lt_upd.NAME == lt_active_name :
                    lt_keep_list.append(lt_upd)
                else:
                    lt_upd_list.append(lt_upd)
    #nt_upd,lt_keep_list,lt_upd_list
    update_list = []
    if nt_upd_flag:
        update_list = lt_upd_list + [nt_upd]
    else:
        update_list = lt_upd_list
    plan_update_list = update_list
    #moswa download step
    Parallel_Instance.board_event_loop('download_build_parallel',update_list,loop_mode=loop_mode)
    lt_upd_list = Parallel_Instance.pop_fail_board(lt_upd_list)
    #moswa active step
    Parallel_Instance.board_event_loop('active_build_parallel',lt_upd_list,loop_mode=loop_mode)
    update_list = Parallel_Instance.pop_fail_board(update_list)
    if nt_upd_flag and nt_upd.board_error_report == 'OK':
        # if nt_upd.check_if_double_nt():
        #     nt_upd.clean_db_parallel = nt_upd.clean_db_double_nt
        try:
            Parallel_Instance.board_event_loop('active_build_parallel',[nt_upd],loop_mode=loop_mode)
            update_list = Parallel_Instance.pop_fail_board(update_list)
        except Exception as inst:
            raise inst
        finally:
            #plan sub board
            for lt_plan in lt_keep_list + lt_upd_list:
                nt_upd.plan_sub_board(lt_plan.plan_rpc)
            for lt_suppress_plan in lt_suppress_list:
                lt_suppress_plan.plan_rpc['no_check'] = True
                nt_upd.plan_sub_board(lt_suppress_plan.plan_rpc)
    #moswa commit step
    Parallel_Instance.board_event_loop('commit_build_parallel',update_list,loop_mode=loop_mode)
    update_list = Parallel_Instance.pop_fail_board(update_list)
    #clean env 
    fail_board = []
    pass_board = []
    fail_str = ''
    for update_inst in plan_update_list:
        try:
            update_inst.clean_env()
            pass_board.append(update_inst)
        except Exception as inst:
            error_record = current_time() + ':[' + update_inst.pboard_id + ']' + '  ' + str(inst)
            update_inst.board_error_report = error_record if update_inst.board_error_report == 'OK' \
                                  else update_inst.board_error_report + '\n' + error_record
            fail_board.append(update_inst)
            if loop_mode == 'abort':
                update_inst.print_log(str(inst))
                raise inst
        board_info = update_inst.board_type if update_inst.slot_id == 'not_nat' else update_inst.board_type + ':' + update_inst.slot_id
        if update_inst.board_error_report != 'OK':
            fail_str = board_info if fail_str else fail_str + ',' + board_info

    #summary
    for update_inst in plan_update_list:#another loop for pretty print 
        board_info = update_inst.board_type if update_inst.slot_id == 'not_nat' else update_inst.board_type + ':' + update_inst.slot_id
        if update_inst.board_error_report != 'OK':
            update_inst._draw_attention(statement=board_info,result='FAIL')
        else:
            update_inst._draw_attention(statement=board_info,result='SUCCESS')
    for fail_inst in fail_board:
        fail_inst.print_log(fail_inst.board_error_report)
    if fail_board:
        raise AssertionError("update %s fail" % fail_str)

def debug_seq(branch_env='atx'):
    pass

#demo seq
def area_1():
    #strongly recommend private area ci imitate this seq, URL and NAME would get from ci script
    one_produce = Update_Instance(args)
    one_produce.URL = 'http://' + http_ip_sh_site + '/SD_61.126/L6GQAG61.126'
    one_produce.NAME = 'L6GQAG61.126'
    #moswa step
    one_produce.check_state()
    one_produce.download_build()
    one_produce.active_build()
    one_produce.commit_build()

#demo seq
def ntlt_seq():
    global print_time
    common_dict = {'dut_ip':'135.251.202.17','build_name':'62.051','nt_type':'AG','trans_mode':'http','build_type':'MS'}
    nt_dict = {'log_dir':'/home/atxuser/1.txt','db_port':'3022','dut_port':'3830','pboard_id':'LT3'}
    lt_dict = {'log_dir':'/home/atxuser/2.txt','db_port':'5022','dut_port':'5830','pboard_id':'LT5'}
    nt_dict.update(common_dict)
    lt_dict.update(common_dict)
    nt = Multi_Instance(nt_dict)
    lt = Multi_Instance(lt_dict)
    print_time = nt.print_log
    if 'build_type' in common_dict.keys() and common_dict['build_type'] == 'MS':
        nt.build_id_guess()#share step
    nt.build_to_update()
    nt.gen_index_url()
    lt.NAME = nt.NAME#message share
    lt.URL = nt.URL
    nt.check_state()#sequential step
    lt.check_state()
    Multi_Instance.board_event_loop('download_build_parallel',[nt,lt])#parallel step
    Multi_Instance.board_event_loop('active_build_parallel',[nt,lt])#parallel step
    Multi_Instance.board_event_loop('commit_build_parallel',[nt,lt])#parallel step
    nt.clean_env()
    lt.clean_env()


def get_event_time(ins_list):
    upgrade_time = {}

    for i,update_inst in enumerate(ins_list):
        if isinstance(update_inst, Update_Instance):
            upgrade_time.update(update_inst.dashboard)

    return upgrade_time


#####################################main update issue################################################
if __name__ == '__main__':
    parser = ArgumentParser(
             formatter_class=RawDescriptionHelpFormatter,
             description='''

update sw example:  
    @shanghai site main stream NC_DPU:
        python sw_update_netconf.py -i 135.251.247.125 -b 62.077 -t AF

    @shanghai site main stream SDFX moswa NT
        python sw_update_netconf.py -i 135.251.247.125 -b 62.077 -t AG -m http -o 923 -n 832
  
    @shanghai site main stream SDFX moswa LT on leagcy NT:
        python sw_update_netconf.py -i 135.251.202.117 -b 62.077 -t AG -m http -o 6022 -n 6830
  
    @shanghai site main stream SDFX moswa LT on moswa NT:
        python sw_update_netconf.py -i 135.251.202.117 -b 62.080 -t AG -m http -o 923 -n 832 -j 6
                                                                                             -j '{"LT":[{"6":""}]}'
                                                                                             -j single_board_json.json
  
    @shanghai site main stream parallel download
        python sw_update_netconf.py -i 135.251.202.117 -b 62.080 -t AG -m http -o 923 -n 832 -j board_json.json
                                                                                           -j '{"LT":[{"7":"FWLT-B"},{"15":"FGLT-B"}],"NT":[{"1":"fant-f"}]}' 
  
    @shanghai site private build
        python sw_update_netconf.py -i 135.251.199.27 -f developer -t AG -m http -o 3022 -n 3830 -p hongya@135.251.206.172:/home/buildmgr/images/SD_62.841p28.tar,PASSWORD
                                                      -f developer                                                                                                           -j 6
                                                      -f developer                                                                                                           -j '{"LT":[{"7":"FWLT-B"},{"15":"FGLT-B"}],"NT":[{"1":"fant-f"}]}' 
                                                      -f developer                                                                                                           -j board_json.json
  
    @RLAB standard PCTA, mount /ftpserver/RLAB, /http for http server, //tftpboot for tftp server 
        python sw_update_netconf.py -i 135.251.247.21 -b lightspan_62.077.tar -f atx -v XXXXXXX.csv -t AF -l XXX/XXXX/sw_update.log
                                                                              -f atx                                                   -j 6
                                                                              -f atx                                                   -j '{"LT":[{"7":"FWLT-B"},{"15":"FGLT-B"}],"NT":[{"1":"fant-f"}]}' 
                                                                              -f atx                                                   -j board_json.json
  
  
    **********************************************************************************************************************************************************************************
    * If "-s" or "--updateserver" option is not given, the default update server would be script globle variable "http_ip_sh_site" and "http_port_sh_site"                           *
    *     "http_ip_sh_site" is http ip                                                                                                                                               *
    *     "http_port_sh_site" is http server ip                                                                                                                                      *
    *     "/tftpboot/" is http server abs dir                                                                                                                                        *
    *     "/tftpboot/official_moswa_build" is the build dir to put build tar                                                                                                         *
    *                                                                                                                                                                                *
    * It is available to set a dynamic private update server by add "-s" or "--updateserver" option. Meanwhile, private update server should provide http server or tftp server      *
    *     1. set http server and tftp server on your private update dir, like "/tftpboot"                                                                                            *
    *     2. cp all the .py scripts in robot repo "robot/ULKS/MOSWA/NCY_USER_KW/http_server_utility/" to update server dir "/tmp/.jenkins"                                           *
    *            scp USER@PCTA_IP:$ROBOTREPO/ULKS/MOSWA/NCY_USER_KW/http_server_utility/* USER@UPDATE_SERVER_IP:/tmp/.jenkins/.                                                      *
    *        ls /tmp/.jenkins/                                                                                                                                                       *
    *            oswpUtility.py  packagemeUtility.py  paxel.py  urlDaily.py                                                                                                          *
    *     3. add "-s" or "--updateserver" to update sw command                                                                                                                       *
    *            python sw_update_netconf.py  -i 135.251.27.45 -t AG -m http -s 135.251.27.8::root:PASSWORD:/tftproot/20190101:20190101: -o 6022 -n 6830                             *
    *        "135.251.27.8" is update server ip, "root" and "PASSWORD" is update server user and password, "/tftproot" is http server root dir                                       *
    *        "/tftproot/20190101" is build tar placed dir                                                                                                                            *
    ********************************************************************************************************************************************************************************** 
    @private updateserver, need oswpUtility.py,packagemeUtility.py,paxel.py,urlDaily.py in updateserver's /tmp/.jenkins, need self httpserver or tftpserver
        python sw_update_netconf.py  -i 135.251.27.45 -t AG -m http -s 135.251.27.8::root:PASSWORD:/tftproot/20190101:20190101: -o 6022 -n 6830
        python sw_update_netconf.py  -i 135.251.27.45 -t AG -m tftp -f developer -p root@135.251.27.147:/home/Downloads/6201/lightspan_6201.228.tar,PASSWORD -s 135.251.27.8::root:PASSWORD:/tftproot/20190101:20190101: -o 22 -n 830


set reboot flag command:
    ***************************************************************************************************************
    *   this script need some reborn system file content keeps 1, or active RPC would not trigger reboot          *
    *   ~ # cat /isam/config/reboot                                                                               *
    *   1                                                                                                         *
    *   ~ # cat /mnt/persistent/rootfs-overlay/isam/config/reboot       <---------- this file could be not exist  *
    *   1                                                                                                         *
    ***************************************************************************************************************
    @set the reboot flag:
        python sw_update_netconf.py -i 135.251.247.125 -b 6201.077 -t AF -d reboot_flag
        python sw_update_netconf.py -i 135.251.202.117 -b 6201.267 -t AG -m http -o 3022 -n 3830 -d reboot_flag


upload reboot info:
    ***************************************************************************************************************
    *   this script could upload all the reboot info under reborn dir '/mnt/reboot_info' before update,           *
    *   ~ # scp -P 22 -r /mnt/reboot_info/ atxuser@135.251.47.3:/home/hongya/reboot_info_20191223103813/.         *
    *   atxuser@135.251.47.3's password:                                                                          *
    ***************************************************************************************************************
    @upload reboot info:
        python sw_update_netconf.py -i 135.251.247.215 -t AF -d upload_reboot_info -z 135.251.247.233:22:atxuser:alcatel01:/home/atxuser/atxuser-Nov25140408:
        python sw_update_netconf.py -i 135.251.247.215 -t AG -d upload_reboot_info -z 135.251.247.233:22:atxuser:alcatel01:.: -o 3022 -n 3830
        python sw_update_netconf.py -i 135.251.247.215 -t AG -d upload_reboot_info -z 135.251.247.233:22:atxuser:alcatel01:.: -o 923 -n 832 -j 2


topology:
    |---------------------|  -b--build   |-----------------------|      -b--build    |------------|
    |     build server    | -----------> |   tftp/http server    | ----------------> |    dut     |
    |                     |              |                       |  -m--trans_mode   |            |
    |   lightspan_*.tar   |              |  packagemeUtility.py  |                   | linux_port |
    |          or         |              |          or           |                   |            |
    |  mounted remote dir |              |    linux 'cp' cmd     |                   |            |
    |---------------------|              |-----------------------|                   |------------|
        -p--buildserver                       -s--updateserver                         -i--dut_ip
                                                                                       -u--dut_user
                                                                                       -n--dut_port
                                                                                       -o--linux_port
                                                                                       -t--index_desc 
                                                                                       -c--clean_db
                      
devops pipeline:
              |<-----------Preparation-------------->|
                                                     |<---------------Download------------>|
                                                                                     |<--Active-->|
                                                                                     |<--Commit-->|
                                         |<------------------------Clean_env--------------------->|
    
                                        
-p--buildserver   
    135.251.206.172::atxuser:alcatel01:/home/buildmgr/images/SDNFDT/FXtrtrm:~
    ip::username:password:dir contains tar file:ftp server dir
-s--updateserver
    10.85.185.28::sdan:5dan:/home/sdan/artifacts/vasilis:vasilis
    ip::username:password:http/tftp server abs dir:dir of http/tftp server
-z--localserver
    135.251.27.33:22:atxuser:acatel233:/home/atxuser/atxuser-Nov25140408:filename.log
    ip:port:user:password:dir:filename


-j--json 
json config file context
{
   "LT":[
           {"7":"FWLT-B"},
           {"15":"FGLT-B"}
        ],
   "NT":[
           {"1":"fant-f"}
        ]
}

known issues:
    1.)dut password can only be admin or Netconf#150.
    2.)once netconf port connect, two change password error report would be shown.
    3.)if netconf port no response, there would be a long block time. It should be improved to dynamic value.
    4.)netconf connect is a blocking API, it should be turn into asynchronous API.
    5.)ALU02632494 is in Reject state, WA step of ALU02632494 should be removed

''')
    parser.add_argument("-i","--dut_ip", required=True, dest="dut_ip", help="dut oam ip (eg. 135.252.245.137)")
    parser.add_argument("-b","--build", dest="build_name", help="build name (eg. 62.080)")
    parser.add_argument("-t","--index_desc", required=True, dest="nt_type", help="nt_type (eg. AF)")
    parser.add_argument("-c","--clean_db",dest="clrDB",default=True, help="if clean db is needed (e. False)")
    parser.add_argument("-u","--dut_user",dest="dut_user",default="admin", help="dut oam username (e. admin)")
    parser.add_argument("-a","--dut_password",dest="dut_password",default="Netconf#150", help="dut oam password (e. admin Netconf#150).It is unvaildable in the latest version")
    parser.add_argument("-m","--trans_mode",dest="trans_mode",default="tftp",help="trans mode tftp or http (e. tftp http)")
    parser.add_argument("-p","--buildserver", dest="buildserver_str", default=None, help="buildserver info (eg. 135.251.206.172::atxuser:alcatel01:/home/buildmgr/images/SDNFDT/FXtrtrm:~)")
    parser.add_argument("-s","--updateserver", dest="updateserver_str", default=None, help="updateserver info (eg. 10.85.185.28::sdan:5dan:/home/sdan/artifacts/vasilis:vasilis:80)")
    parser.add_argument("-z","--localserver", dest="localserver", default=None, help="localserver info (eg. 135.251.247.211::atxuser:alcatel01:/tmp:: or  135.251.247.211:8080:atxuser:alcatel01:.::)")
    parser.add_argument("-l","--log", dest="log_dir", default=None, help="log file (eg. /tftpboot/atx/atxuser/SB_Log_08032016-113020/sw.log)")
    parser.add_argument("-f","--ci_type", dest="ci_type", default='', help="run env of this script (eg. atx developer)")
    parser.add_argument("-o","--linux_port", dest="db_port", type=int, default=2222, help="port of reborn linux (eg. 2222)")
    parser.add_argument("-n","--dut_port", dest="dut_port", type=int, default=830, help="port of netconf xml(eg. 830)")
    parser.add_argument("-v","--csv_file", dest="csv_file", default=None, help="csv file of dut(eg. /repo/atxuser/robot/SETUPS/SMOKE/NC_OLT_NFXSE_FANTF_FGLTB_SMOKE_SETUPFILE_39_220.csv)")
    parser.add_argument("-j","--json", dest="json_config", default=None, help="lt slot id and type \d or json text(eg. /home/atxuser/update_board.json or \"{\"LT\":[{\"1\":\"fgltb\"}]}\" or 5)")
    parser.add_argument("-d","--build_step", dest="build_step", default='', help="pipeline step of sw upgrade (eg. Preparation Download Active Commit Clean_env Clean_db reboot_flag upload_reboot_info)")
    parser.add_argument("-e","--loop_mode", dest="loop_mode", default='abort', help="parallel download, one board fail, abort other board (eg. abort continue)")
    options = parser.parse_args()
    #print_time ('input argument:\n' + str(vars(options)) + '\n') ----------> atx remote call would abort while there are #%$ in print out put

    args = {}
    args['clrDB'] = turn_str_to_bool(options.clrDB)
    args['ci_type'] = options.ci_type
    args['dut_ip'] = options.dut_ip 
    args['build_name'] = options.build_name
    args['nt_type'] = options.nt_type
    args['dut_user'] = options.dut_user
    args['dut_password'] = options.dut_password
    args['trans_mode'] = options.trans_mode
    args['log_dir'] = options.log_dir
    args['db_port'] = options.db_port
    args['dut_port'] = options.dut_port
    args['csv_file'] = options.csv_file
    args['json_config'] = options.json_config
    args['build_step'] = options.build_step
    args['loop_mode'] = options.loop_mode
    
    #server info parse
    if options.updateserver_str:
        upda_dict = parse_updateserver_str(options.updateserver_str)
        args.update(upda_dict)
    if options.buildserver_str:
        buid_dict = parse_buildserver_str(options.buildserver_str)
        args.update(buid_dict)
    if options.localserver:
        localshell_dict = parse_std_format(options.localserver)
        args.update(localshell_dict)
    if options.log_dir:
        log_ins = urlNetconf.Logger(options.log_dir)

    #json config info
    json_config = args['json_config']
    parallel_suffix = ''
    if json_config:
        slot_id = ''
        json_d = {}
        if re.match('\d+',json_config):
            slot_id = json_config
        elif os.path.isfile(json_config):
            with open(json_config,'r') as ftr:
                json_d = json.load(ftr)
        else:
            json_d = json.loads(str(json_config))
        json_d = to_str_dict(json_d) if json_d else {}
        print_time(str(json_d))
        if "LT" in json_d.keys() and len(json_d["LT"]) == 1 and "NT" not in json_d.keys():#single LT board
            args['slot_id'] = json_d["LT"][0].keys()[0]
        elif "LT" in json_d.keys() and "NT" in json_d.keys():
            parallel_suffix = 'sdfx_parallel'
        elif slot_id:
            args['slot_id'] = slot_id
        args['board_info'] = json_d 

    #special requirement
    build_step = args['build_step'].lower()

    #sw update branch entrance
    if build_step in ['preparation','download','active','commit','clean_env','clean_db_with_reset']:
        if parallel_suffix == 'sdfx_parallel':
            devops_pipeline_seq_parallel(ci_mode=args['ci_type'],build_step=build_step)
        else:
            devops_pipeline_seq(ci_mode=args['ci_type'],build_step=build_step)
    elif build_step in ['reboot_flag','upload_reboot_info'] :
        tool_box_seq(build_step=build_step)
    elif parallel_suffix == 'sdfx_parallel':
        if args['ci_type'] == 'atx':
            SDFX_parallel_seq(branch_env='atx',loop_mode=args['loop_mode'])
        elif args['ci_type'] == 'developer':
            SDFX_parallel_seq(branch_env='developer',loop_mode=args['loop_mode'])
        else:
            SDFX_parallel_seq(branch_env='',loop_mode=args['loop_mode'])
    else:
        if args['ci_type'] == 'atx':
            atx_seq()
        elif args['ci_type'] == 'developer':
            developer_seq()
        else :
            simple_seq()


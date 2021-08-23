from argparse import ArgumentParser
import sys,re,os,time,socket
import urlNetconf
from lxml import etree
import subprocess
from sshClient import ssh2

###############global dynamic variable come from func args or main#################################
oam_ip = ''
build_name = ''
nt_type = ''
YANG_VERSION = ''
XMLNS_MAP = ''
step_count = 0
ftpserver = ''
oam_port = 830
oam_username = 'admin'
oam_pazwd2 = 'Netconf#150'
oam_pazwd = 'admin'
trans_mode = 'tftp'
build_ver = ''
build_ver_short = ''
download_xml = ''
active_xml = ''
commit_xml = ''
abort_xml = ''
index_file = ''
clrDB = True
db_port = 2222
db_username = 'root'
db_pazwd = '2x2=4'
step_name = ''

def str2func(func_name_str):
    functionable = compile(func_name_str+'()', '','eval')
    eval(functionable)

######################global static variable#######################################################

HOST_IP = socket.gethostbyname(socket.gethostname()) 
SERVER_IP = '135.252.245.44' if not ftpserver else ftpserver
show_string = "get(filter=('subtree','<hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>Chassis</name><software xmlns=\"urn:bbf:yang:bbf-software-image-management-one-dot-one\"><software><name>application_software</name></software></software></component></hardware-state>'))" 


#################common tools#####################################################################
def build_name_check():
    global build_name
    global build_ver
    global build_ver_short
    if build_name.startswith('SD_') and build_name.endswith('.tar'):
        print_time("build_name check pass")
    elif re.match('^\d+\.\d{3}$',build_name):
        build_name = 'SD_' + build_name + '.tar'
    else:
        print_time("build name SyntaxError")
    build_ver = build_name.strip('SD_').strip('.tar')
    build_ver_list = build_ver.split('.')
    build_ver_short = build_ver_list[0][0:2] + '.' + build_ver_list[1]

        
def ip_pingable():
    ret = os.system('/bin/ping -c 4 %s 2>&1 >/dev/null' % oam_ip)
    if not ret:
        print_time('%s is reachable' % oam_ip)
        return True
    else:
        print_time('%s is not reachable' % oam_ip)
        return False

 
def current_time():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def print_time(strpr):
    print('['  + step_name + ' ' + current_time() + ']:' + str(strpr))    

def step_by_step():
    global step_count
    step_count = step_count + 1
    return "Step." + str(step_count) + " "

def _merge_two_list(list1, list2):
    list3 = list2
    for a in list1:
        isFound = False
        for b in list2:
            if a == b :
                isFound = True
                break0
        if not isFound :
            list3.append(a)
    return list3

def get_download_state(session_name):
    module_name = 'urn:bbf:yang:bbf-software-image-management-one-dot-one'
    cmd_string = "get(filter=('subtree','<hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>Chassis</name><software xmlns=\"urn:bbf:yang:bbf-software-image-management-one-dot-one\"><software><name>application_software</name></software></software></component></hardware-state>'))"
    ret = session_name.netconf_operation(cmd_string)
    root_xml = etree.fromstring(ret.encode('utf-8'))
    oswp_list = []
    oswp_item_dict = {}
    try:
        for child in root_xml.findall('.//{' + module_name + '}revisions')[0].getchildren():
            oswp_item_dict['name'] = child.find('{' + module_name + '}name').text
            oswp_item_dict['name'] = oswp_item_dict['name'].strip("'")
            oswp_item_dict['is-valid'] = child.find('{' + module_name + '}is-valid').text
            oswp_item_dict['is-committed'] = child.find('{' + module_name + '}is-committed').text
            oswp_item_dict['is-active'] = child.find('{' + module_name + '}is-active').text
            oswp_list.append(dict(oswp_item_dict))
    except:
        pass 
    return oswp_list

def show_download_progress(session_name):
    module_name = 'urn:bbf:yang:bbf-software-image-management-one-dot-one'
    cmd_string = "get(filter=('subtree','<hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>Chassis</name><software xmlns=\"urn:bbf:yang:bbf-software-image-management-one-dot-one\"><software><name>application_software</name></software></software></component></hardware-state>'))"
    ret = session_name.netconf_operation(cmd_string)
    root_xml = etree.fromstring(ret.encode('utf-8'))
    if '<last-download-state>' in ret:
        download_state = root_xml.findall('.//{urn:bbf:yang:bbf-software-image-management-one-dot-one}current-state')[0].find('{urn:bbf:yang:bbf-software-image-management-one-dot-one}state').text
        last_download_state = root_xml.findall('.//{urn:bbf:yang:bbf-software-image-management-one-dot-one}last-download-state')[0].find('{urn:bbf:yang:bbf-software-image-management-one-dot-one}state').text 
        last_download_version = root_xml.findall('.//{urn:bbf:yang:bbf-software-image-management-one-dot-one}last-download-state')[0].find('{urn:bbf:yang:bbf-software-image-management-one-dot-one}software-name').text
        return (download_state,last_download_state,last_download_version)
    else:
        tem_list = get_download_state(session_name)
        return ('Normal',tem_list[0],tem_list[-1])

def send_yang_xml(send_xml,session_name):
    print_time(str(session_name))
    session_name.send_xml(send_xml)
    data = session_name.get_output(60)
    result, error_info = session_name.check_result(data)
    return result

def send_trace_cmd(trace_cmd):
    cmd = "sshpass -p '%s' ssh -p %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s '%s'" %(db_pazwd,db_port,db_username,oam_ip,trace_cmd)
    result=subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE, shell=True).communicate()[0]
    print_time(result)

def clear_db():
    global oam_pazwd
    if clrDB:
        send_trace_cmd('cd /mnt/nand-dbase/confd-cdb/;ls -l')
        send_trace_cmd('rm -rf /mnt/reboot_info/*')
        send_trace_cmd('s6-rc -a listall')
        send_trace_cmd('ls -la /mnt/nand-dbase/confd-cdb/*.cdb')
        send_trace_cmd('rm -rf /mnt/nand-dbase/confd-cdb/*.cdb')
        send_trace_cmd('rm -rf /mnt/nand-dbase/confd-cdb/*.xml')
        send_trace_cmd("echo \"1\" > /isam/config/reboot")
        send_trace_cmd('/bin/sync')
        #send_trace_cmd('/sbin/reboot')
        #time.sleep(30)
        #while True:
        #    if ip_pingable():
        #        break
        #    time.sleep(10) 
        #time.sleep(60)
        oam_pazwd = 'admin'

def reboot_isam():
    send_trace_cmd('/sbin/reboot')
    time.sleep(180)
    while True:
        if ip_pingable():
            break
        time.sleep(10)  
 
def set_reboot():
    send_trace_cmd("echo \"1\" > /isam/config/reboot")
    send_trace_cmd("cat /isam/config/reboot")


def reboot_action(action_xml,action_build_name):
    set_reboot()
    if '<activate-revision><activate/></activate-revision>' in action_xml:
        check_field = 'is-active'
    elif '<commit-revision><commit/></commit-revision>' in action_xml:
        check_field = 'is-committed'        
    else:
        return 0
    session_name = urlNetconf.ssh_netconf(ip=oam_ip, port=oam_port, username=oam_username, password=oam_pazwd)
    ret_hello = session_name.netconf_connect()
    get_download_state(session_name)
    session_name.send_xml(action_xml)
    count_time = 0
    ping_flag = True
    ping_wait_time =30
    if check_field == 'is-active':
        ping_wait_time = 120
    elif check_field == 'is-committed':
        ping_wait_time = 40
    while count_time < ping_wait_time:
        time.sleep(1)
        if not ip_pingable():
            ping_flag = False
            break
        try:
            session_name = urlNetconf.ssh_netconf(ip=oam_ip, port=oam_port, username=oam_username, password=oam_pazwd)
            ret_hello = session_name.netconf_connect()
            list_result = get_download_state(session_name)
            print_time(str(list_result))
            down_dict = filter(lambda xd:xd['name'] == action_build_name, list_result)[0]
            if down_dict[check_field] == 'true':
                print_time("action success")
                return
            session_name.send_xml(action_xml)
        except:
            pass
        print_time("action send still pingable")
        count_time = count_time + 1
    if ping_flag:
        count_time = 0
        time.sleep(5)
        while count_time < 100:
            try:
                list_result = get_download_state(session_name)
                print_time(str(list_result))
                down_dict = filter(lambda xd:xd['name'] == action_build_name, list_result)[0]
                if down_dict[check_field] == 'true':
                    print_time("action success")
                    return
                session_name.send_xml(action_xml)
                print_time("action send retry")
            except:
                pass
            time.sleep(20)
            if not ip_pingable():
                break
            count_time = count_time + 1
        if ip_pingable():
            print_time("action command send fail, no response.")  
    else:
        print_time("reboot start...")  
    count_time = 0
    while not ip_pingable() and count_time <200 :
        print_time("active time waiting...")
        count_time = count_time + 1
        time.sleep(10) 
    if not ip_pingable():
        print_time("DUT no response after a long time.")
    else:
        time.sleep(20)
        session_name = urlNetconf.ssh_netconf(ip=oam_ip, port=oam_port, username=oam_username, password=oam_pazwd)
        ret_hello = session_name.netconf_connect()
        list_result = get_download_state(session_name)
        print_time(list_result)
        down_dict = filter(lambda xd:xd['name'] == action_build_name, list_result)[0]
        if down_dict[check_field] == 'true':
            print_time("action success")
    session_name.netconf_disconnect()


################################step name#######################################################
def build_preparation():
    global build_ver
    global build_ver_short
    global step_name
    step_name = 'build preparation'
    print("%s : Prepare load %s") % (current_time(), build_name)
    print(">"*10 + step_by_step() + "Build Preparetion" + "<"*10)
    build_ver = build_name.strip('SD_').strip('.tar')
    build_ver_list = build_ver.split('.')
    build_ver_short = build_ver_list[0][0:2] + '.' + build_ver_list[1]
    #oswpUtility.prepareOSWP(build_ver,SERVER_IP,'',False)
    remotescript = '/tmp/.jenkins/oswpUtility.py'
    destDir = '/tftpboot'
    cmd = '%s --action prepareOSWP --build %s --serverip %s --destDir %s' %(remotescript,build_ver,SERVER_IP,destDir)
    tmpRes = ssh2(SERVER_IP,'atxuser','alcatel01',cmd,True)
    print_time(tmpRes)

def connect_netconf_server():
    global step_name
    global YANG_VERSION
    global XMLNS_MAP
    step_name = 'connect netconf'
    print(">"*10 + step_by_step() + "Connect Netconf Server" + "<"*10)
    session_name = urlNetconf.ssh_netconf(ip=oam_ip, port=oam_port, username=oam_username, password=oam_pazwd)
    ret_hello = session_name.netconf_connect()
    YANG_INFO,XMLNS_MAP = urlNetconf._collect_yang_info_from_hello(ret_hello)
    cmd_string = "get(filter=('subtree','<modules-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\"><module/></modules-state>'))"
    ret = session_name.netconf_operation(cmd_string,session_name=session_name)
    result, message = session_name.check_result(ret)  
    if result == 'FAIL' :
        print_time("cmd get() message fail")
    #l_yang_info_yang_lib,d_yang_xmlns_map = urlNetconf._collect_yang_info_from_yang_library(ret)
    #YANG_INFO = _merge_two_list(YANG_INFO, l_yang_info_yang_lib)
    #XMLNS_MAP.update(d_yang_xmlns_map)
    #print YANG_INFO
    #print "\n\n\n\n"
    #print XMLNS_MAP
    session_name.netconf_disconnect()

def check_oswp_statue():
    global show_string
    global download_xml
    global active_xml
    global commit_xml
    global build_ver_short
    global index_file
    global step_name
    step_name = 'check oswp'
    print(">"*10 + step_by_step() + "Check Oswp Statue" + "<"*10)
    session_name = urlNetconf.ssh_netconf(ip=oam_ip, port=oam_port, username=oam_username, password=oam_pazwd)
    ret_hello = session_name.netconf_connect()
    index_file = 'L6GP' + nt_type.upper() + build_ver_short
    server_url = trans_mode + '://' + SERVER_IP + '/' + index_file
    abort_xml = "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"1\"><action xmlns=\"urn:ietf:params:xml:ns:yang:1\"><hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>Chassis</name><software xmlns=\"urn:bbf:yang:bbf-software-image-management-one-dot-one\"><software><name>application_software</name><download><abort-download><name>%s</name></abort-download></download></software></software></component></hardware-state></action></rpc>" %(index_file)
    download_xml = "<rpc message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><action xmlns=\"urn:ietf:params:xml:ns:yang:1\"><hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>Chassis</name><software xmlns=\"urn:bbf:yang:bbf-software-image-management-one-dot-one\"><software><name>application_software</name><download><download-software><url>%s</url><name>%s</name></download-software></download></software></software></component></hardware-state></action></rpc>" %(server_url, index_file)
    active_xml = "<rpc message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><action xmlns=\"urn:ietf:params:xml:ns:yang:1\"><hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>Chassis</name><software xmlns=\"urn:bbf:yang:bbf-software-image-management-one-dot-one\"><software><name>application_software</name><revisions><revision><name>%s</name><activate-revision><activate/></activate-revision></revision></revisions></software></software></component></hardware-state></action></rpc>" %(index_file)   
    commit_xml = "<rpc message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><action xmlns=\"urn:ietf:params:xml:ns:yang:1\"><hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>Chassis</name><software xmlns=\"urn:bbf:yang:bbf-software-image-management-one-dot-one\"><software><name>application_software</name><revisions><revision><name>%s</name><commit-revision><commit/></commit-revision></revision></revisions></software></software></component></hardware-state></action></rpc>" %(index_file)
    returnlist = get_download_state(session_name) 
    session_name.netconf_disconnect()
    return returnlist

def download_build():
    global step_name
    step_name = 'download build'
    print(">"*10 + step_by_step() + "Download Build" + "<"*10)
    #clear_db()
    session_name = urlNetconf.ssh_netconf(ip=oam_ip, port=oam_port, username=oam_username, password=oam_pazwd)
    ret_hello = session_name.netconf_connect()
    state_tuple = show_download_progress(session_name)
    two_build_state = get_download_state(session_name)
    if two_build_state[0]['name'] != two_build_state[-1]['name']:
        if two_build_state[0]['is-active'] == 'true':
            active_build = two_build_state[0]
        else:
            active_build = two_build_state[1]
        if active_build['is-committed'] == 'false':
            commint_noac_xml = "<rpc message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><action xmlns=\"urn:ietf:params:xml:ns:yang:1\"><hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>Chassis</name><software xmlns=\"urn:bbf:yang:bbf-software-image-management-one-dot-one\"><software><name>application_software</name><revisions><revision><name>%s</name><commit-revision><commit/></commit-revision></revision></revisions></software></software></component></hardware-state></action></rpc>" %(active_build['name'])
            reboot_action(commint_noac_xml,active_build['name'])
            #clear_db()
            session_name = urlNetconf.ssh_netconf(ip=oam_ip, port=oam_port, username=oam_username, password=oam_pazwd)
            ret_hello = session_name.netconf_connect()
    send_yang_xml(download_xml,session_name)
    time.sleep(2)
    while True:
        state_tuple = show_download_progress(session_name)
        time.sleep(5)
        if state_tuple[0] == 'in-progress':
            continue
        if state_tuple[0] == 'idle':
            if state_tuple[1] == 'successful' and state_tuple[2] == index_file:
                break
            if state_tuple[1] == 'failed' and state_tuple[2] == index_file:
                send_yang_xml(abort_xml,session_name)
                time.sleep(5)
                show_download_progress(session_name)
                send_yang_xml(download_xml,session_name)
    get_download_state(session_name)
    session_name.netconf_disconnect()

def active_build():
    global step_name
    step_name = 'active build'
    print(">"*10 + step_by_step() + "Active Build" + "<"*10)
    clear_db()
    reboot_action(active_xml,index_file)

def commit_build():
    global step_name
    step_name = 'commit build'
    print(">"*10 + step_by_step() + "Commit Build" + "<"*10)
    reboot_action(commit_xml,index_file)

###################################interface SEQ#########################################################
def default_SEQ(de_SEQ,oam_ip_,build_name_,nt_type_,**kw):
    global build_ver
    global build_ver_short
    global oam_ip #required
    global build_name #required
    global nt_type #required
    global clrDB
    global trans_mode
    global db_port
    global oam_port
    oam_ip = oam_ip_
    build_name = build_name_
    nt_type = nt_type_
    if clrDB in kw:
        clrDBstr = kw[clrDB]
        if clrDBstr.lower() == 'false':
            clrDB = False
        elif clrDBstr.lower() == 'true':
            clrDB = True 
    if trans_mode in kw:
        trans_mode = kw[trans_mode]
    if db_port in kw:
        db_port = kw[db_port]
    if oam_port in kw:
        oam_port = kw[oam_port]
    build_name_check()
    #SEQ_normal = ['connect_netconf_server','check_oswp_statue','download_build']
    #SEQ_normal = ['connect_netconf_server','check_oswp_statue']
    map(str2func,de_SEQ)
    downloadresult = check_oswp_statue()
    print(downloadresult)
    if de_SEQ[-1] == 'download_build':
        checkfield = 'is-valid'
    elif de_SEQ[-1] == 'active_build':
        checkfield == 'is-active'
    elif de_SEQ[-1] == 'commit_build':
        checkfield == 'is-committed'
    else:
        checkfield = 'is-valid'
    if len(downloadresult) is not 0:
        for verItem in downloadresult:
            if verItem['name'] == index_file:
                if verItem[checkfield] == 'true':
                    print(downloadresult)
                    return 'PASS'
    return 'download state get fial' 

def download_SEQ(oam_ip_,build_name_,nt_type_,**kw):
    SEQ_download = ['connect_netconf_server','check_oswp_statue','download_build'] 
    default_SEQ(SEQ_download,oam_ip_,build_name_,nt_type_,**kw)

def active_SEQ(oam_ip_,build_name_,nt_type_,**kw):
    SEQ_active = ['connect_netconf_server','check_oswp_statue','active_build','commit_build'] 
    default_SEQ(SEQ_active,oam_ip_,build_name_,nt_type_,**kw)

def clear_SEQ(oam_ip_,db_port_=2222,oam_port_=830):
    global oam_ip #required
    global clrDB
    global db_port
    global oam_port
    oam_ip = oam_ip_
    clrDB = True
    session_name = urlNetconf.ssh_netconf(ip=oam_ip, port=oam_port_, username=oam_username, password=oam_pazwd)
    ret_hello = session_name.netconf_connect()
    returnlist = get_download_state(session_name)
    commitfile = index_file
    commitflag = False
    if len(returnlist) == 2 and returnlist[0]['is-active'] != returnlist[0]['is-committed']:
        commitflag = True
        if returnlist[0]['is-active'] == 'true':
            commitfile = returnlist[0]['name']
        else:
            commitfile = returnlist[1]['name']
    commit_clear_xml = "<rpc message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><action xmlns=\"urn:ietf:params:xml:ns:yang:1\"><hardware-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-hardware\"><component><name>Chassis</name><software xmlns=\"urn:bbf:yang:bbf-software-image-management-one-dot-one\"><software><name>application_software</name><revisions><revision><name>%s</name><commit-revision><commit/></commit-revision></revision></revisions></software></software></component></hardware-state></action></rpc>" %(commitfile)
    if commitflag:
        reboot_action(commit_clear_xml,commitfile)
    clear_db()

def upgrade_build():
    SEQ_normal = ['connect_netconf_server','check_oswp_statue','download_build','active_build','commit_build']
    map(str2func,SEQ_normal)  

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-i","--dut_ip", required=True, dest="oam_ip", help="oam ip (eg. 135.252.245.137)")
    parser.add_argument("-b","--build", required=True, dest="build_name", help="build name (eg. SD_56.350.tar)")
    parser.add_argument("-t","--index_desc", required=True, dest="nt_type", help="nt_type (eg. AF)")
    parser.add_argument("-c","--clean_db",dest="clrDB",default=True,help="if clean db is needed (e. False)")
    parser.add_argument("-u","--dut_user",dest="oam_username",default="admin",help="dut oam username (e. admin)")
    parser.add_argument("-a","--dut_password",dest="oam_pazwd",default="admin",help="dut oam pazwd (e. admin Netconf#150)")
    parser.add_argument("-m","--trans_mode",dest="trans_mode",default="tftp",help="trans mode tftp or http (e. tftp http)")
    parser.add_argument("-p","--ftpserver", dest="ftpserver", default="135.252.245.44", help="ftpserver ip (eg. 135.252.245.44)")
    parser.add_argument("-l","--log", dest="log_dir", default='~', help="log dir (eg. /tftpboot/atx/atxuser/SB_Log_08032016-113020)")

    parser.add_argument("-o","--linux_port", dest="db_port", type=int, default=2222, help="port of linux (eg. 2222)")
    parser.add_argument("-n","--dut_port", dest="oam_port", type=int, default=830, help="port of netconf xml(eg. 830)")
    options = parser.parse_args()
    
    oam_ip = options.oam_ip
    build_name =  'SD_' + options.build_name + r'.tar'
    nt_type = options.nt_type
    clrDB = options.clrDB
    oam_username = options.oam_username
    oam_pazwd = options.oam_pazwd
    trans_mode = options.trans_mode
    if isinstance(clrDB,str) and clrDB.lower() == 'false':
        clrDB = False
    ftpserver = options.ftpserver
    db_port = options.db_port
    oam_port = options.oam_port
    
    build_name_check()
    SEQ_normal = ['build_preparation','connect_netconf_server','check_oswp_statue','download_build','active_build','commit_build']
    #SEQ_normal = ['build_preparation','connect_netconf_server','check_oswp_statue','active_build','commit_build']
    map(str2func,SEQ_normal)

import paramiko,re,time
from lxml import etree


HELLO_XML = '<?xml version="1.0" encoding="UTF-8"?><hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>'
BASE_NS_1_0 = "urn:ietf:params:xml:ns:netconf:base:1.0"
XMLNS_MAP = ''
YANG_INFO = ''
log_ins = None

def _get_module_state (session_name):
    """ 
    private keyword called by update_yang_info
    """
    try :
        # get yang-library message
        ret_yang_lib = netconf_get("modules-state{ietf-yang-library}/module",session_name)
    
    except Exception as inst:
        # for some user, it has no permission to access modules node
        ret_yang_lib = ''

    return ret_yang_lib

def print_log(strpr) :
    print (strpr)
    if log_ins :
        log_ins.writelines(strpr + '\n')

def netconf_get (command_index=None,*command_elements,**params) :
    """           
    get states for specific nodes or system
    
    usage example:
        | netconf_get | output_flatpair=name subtending-itf,vlan-id 4 | output_regexp=type.*user_port | timeout=5 |
        | netconf_get | interfaces{ietf-interfaces}/interface | output_flatpair=name subtending-itf,vlan-id 4 |            
        | netconf_get | interfaces{ietf-interfaces}/interface | name subtending-itf | output_regexp=enabled.*true |
        | netconf_get | interfaces{ietf-interfaces}/interface | type{bbfift:bbf-if-type} bbfift:xdsl |        
    
    - *command_index:* interface for target nodes. If command_index=None, get states for whole system                      
    - *command_elements:* contents for filter
    - *session_name:* string, default value is "first_netconf_session"
    - *output_regexp:* the exact match regexp to command output
    - *output_flatpair:* the xml key value pair match
    - *check_time: * how long time (seconds) before return not found
    - *expect_result:* PASS or FAIL, default value is "PASS" 
    - *with_defaults: with-defaults value, default is None
    - *timeout:* the max-time to get response of this rpc message (second)
    - *parser:* the format of output, default is XML, also support YAML
    """
    keyword = "netconf_get"
    logger.debug ("%s:%s-> get %s %s %s" % (__name__,keyword,command_index,str(command_elements),str(params)))
    check_time = params.setdefault('check_time', 0)
    expect_result = params.setdefault('expect_result','PASS')
    expect_result = expect_result.upper()
    session_name = params.setdefault('session_name',"first_netconf_session")
    output_regexp = params.setdefault('output_regexp',None)
    output_flatpair = params.setdefault('output_flatpair',None)
    with_defaults = params.setdefault('with_defaults',None)
    parser = params.setdefault('parser', 'XML')
    interval_time = 5

    current_time = time.mktime(time.localtime())
    end_time = current_time + int(check_time)

    if not command_index and command_elements != () :
        raise AssertionError ("index shouldn't be null when element is not null." )

    if command_index == None :
        cmd_string = "get()" 
    else:
        filter_xml = _get_filter_xml(command_index,*command_elements,mgmt_param=NETCONF_OBJ[session_name].mgmt_param,session_name=session_name)
        cmd_string = "get(filter=('subtree','%s'))" % filter_xml 

    if with_defaults:
        cmd_string = cmd_string + 'capabilities:{'+WITH_DEFAULTS_NS+'}with-defaults='+with_defaults   
    while current_time <= end_time :
        search_result = "PASS"          
        ret = NETCONF_OBJ[session_name].netconf_operation(cmd_string,**params)
        result,message = NETCONF_OBJ[session_name].check_result(ret)

        if result == 'FAIL' :
            if result == expect_result and not (output_regexp or output_flatpair or get_node):
                logger.info("gotten expected response: '%s' \n%s" % (expect_result,result))
                return
            else:
                time.sleep(interval_time)
                current_time = time.mktime(time.localtime())
                if current_time > end_time:
                    raise AssertionError("NETCONF get failed \nexpect: %s, operation return: %s %s" % (expect_result,result,message))
                else:
                    continue
        info = str(ret)
        return (info)


#hongya
class ssh_netconf (object):
    def __init__ (self, **connect_info):
        self.ip = connect_info.setdefault('ip', '127.0.0.1')
        self.port = connect_info.setdefault('port', 830)
        self.password = connect_info.setdefault('password', 'admin')
        self.second_password = connect_info.setdefault('second_password', 'Netconf#150')
        self.username = connect_info.setdefault('username', 'admin')
        self.hello_xml = connect_info.setdefault('hello_xml', HELLO_XML)
        self.timeout = connect_info.setdefault('timeout', 600)
        self.log_ins = connect_info.setdefault('log_ins', None)
        self._print_log = connect_info.setdefault('print_log', self._print_log_default)
        self.mgmt_param = {}
        self.delimiter = "]]>]]>"
        self.transport = ""
        self.channel = ""
        self.client = ""
        self.command_timeout = 60


    def _print_log_default(self,strpr) :
        print (strpr)
        if self.log_ins :
            self.log_ins.writelines(strpr + '\n')
    

    def set_netconf_command_timeout (self,timeout):
        self.command_timeout = timeout

    def _send_hello (self):
        # send hello message
        self.send_xml(self.hello_xml)
        # get output
        ret = self.get_output (self.command_timeout)
        return ret

    def netconf_connect (self,**args):
        timeout = args.setdefault('timeout', self.timeout)
        paramiko.util.log_to_file("filename.log")
        self.client=paramiko.SSHClient()	
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        inst = ""
        connect_flag = False
        hello_ret = ""
        for i in range(0,int(timeout)/60) :
            try :
                time1 = time.time()
                self.client.connect(self.ip,port=int(self.port),username=self.username,password=self.password,allow_agent=False,look_for_keys=False)
                self.transport=self.client.get_transport()
                self.channel=self.transport.open_session()
                self.channel.invoke_subsystem('netconf')
                hello_ret = self._send_hello()
                connect_flag = True
                break
            except Exception as inst:
                if re.search("Authentication failed",str(inst)) :
                    break
                time2 = time.time()
                if (int(60+time1-time2)>0):
                    time.sleep(int(60+time1-time2))
        if connect_flag and self.username=='admin' and self.password == 'admin':
            try :
                # NEED TO DELETE: when SW remove the interface of changing password via edit-config RPC.
                editconfig=etree.Element('edit-config')
                target=etree.SubElement(editconfig,'target')
                running=etree.SubElement(target,'running')
                config=etree.SubElement(editconfig,'config',nsmap={None:'http://tail-f.com/ns/config/1.0'})
                aaa=etree.SubElement(config,'aaa',nsmap={None:'http://tail-f.com/ns/aaa/1.1'})
                authentication=etree.SubElement(aaa,"authentication")
                users=etree.SubElement(authentication,"users")
                user=etree.SubElement(users,"user")
                name=etree.SubElement(user,"name")
                name.text="admin"
                password=etree.SubElement(user,"password")
                password.text=self.second_password
                config_xml=etree.tostring(editconfig,pretty_print=True)
                self.send_xml(_to_xml(_wrap_rpc(editconfig)))
                result = self.get_output(60)
                res,message = self.check_result(result)
                if res == "PASS" :
                    self._print_log ("Change password Netconf#150 successfully !")
                else :
                    actionXml=etree.Element('action',nsmap={None:'http://tail-f.com/ns/netconf/actions/1.0'})
                    data=etree.SubElement(actionXml,'data')
                    aaa=etree.SubElement(data,'aaa',nsmap={None:'http://tail-f.com/ns/aaa/1.1'})
                    authentication=etree.SubElement(aaa,'authentication')
                    users=etree.SubElement(authentication,'users')
                    user=etree.SubElement(users,'user')
                    name=etree.SubElement(user,'name')
                    name.text="admin"
                    changePassword=etree.SubElement(user,'change-password')
                    oldPassword=etree.SubElement(changePassword,'old-password')
                    oldPassword.text=self.password
                    newPassword=etree.SubElement(changePassword,'new-password')
                    newPassword.text=self.second_password
                    confirmPassword=etree.SubElement(changePassword,'confirm-password')
                    confirmPassword.text=self.second_password
                    config_xml=etree.tostring(actionXml,pretty_print=True)
                    self.send_xml(_to_xml(_wrap_rpc(actionXml)))
                    result = self.get_output(60)
                    res,message = self.check_result(result)
            except Exception as inst:
                self._print_log ("Fail to change password Netconf#150,Exception: %s" % inst)
        elif ('Authentication failed' in str(inst)):
            for i in range(0,5) :
                try :
                    self.client.connect(self.ip,port= \
                    int(self.port),username=self.username,password=self.second_password,allow_agent=False,look_for_keys=False)
                    self.transport=self.client.get_transport()
                    self.channel=self.transport.open_session()
                    self.channel.invoke_subsystem('netconf')
                    ret = self._send_hello()
                    connect_flag = True
                    return ret
                except Exception as inst :
                    time.sleep(int(i*5)) 
            raise AssertionError("fail to ssh netconf server! \
            exception: %s" % (inst))

        return hello_ret

    def send_xml (self,xml,timeout=10):
        # will add message delimiter
        for i in range(0,timeout):
            if self.channel.send_ready():
                try:
                    self.channel.sendall(xml + self.delimiter)
                    break
                except Exception as inst:
                    raise AssertionError("fail to send xml message! Exception: %s" % inst)
            time.sleep(0.1)

        return

    def xml_post_operation (self,operation,xml_str):
        return xml_str

    def get_output (self,timeout=0,delay_time=0):
        """
        ssh output
        """
        time.sleep (delay_time)
        if timeout == 0 :
            timeout = self.command_timeout
        #self._print_log ("get output with timeout="+ str(timeout))   
        data = ""
        current_time = time.time()
        start_time = current_time
        end_time = current_time + int(timeout)
        
        while current_time <= end_time :
            while self.channel.recv_ready():
                data += self.channel.recv(4096)
            if self.delimiter in data:
                break
            current_time = time.time()
            time.sleep (0.01)
            
        time_taken = time.time() -start_time
        if time_taken > 10 :
            self._print_log ( "NETCONF response time: %s seconds" % str(time_taken))
        
        if self.delimiter not in data:
            self._print_log ("no %s in %s" % (self.delimiter,data))

        data = data.replace(self.delimiter,'')
        data = re.sub('>\s+','>',data)
        data = re.sub('\s+<','<',data)
        try:
            print_str = etree.tostring(etree.fromstring(data),pretty_print=True)
            if not (('<capability>' in print_str and '<capabilities>' in print_str) or \
                    ('<conformance-type>' in print_str and '<module>' in print_str) or \
                    ('<state>in-progress</state>' in print_str) \
                   ):
                self._print_log ("NETCONF REPLY << %s" % etree.tostring(etree.fromstring(data),pretty_print=True))
        except:
            self._print_log ("(could not tide up) NETCONF REPLY << %s" % data)
        if data == "":
            raise AssertionError("no output got from socket!")
        return data
   
    def netconf_operation (self,cmd="",**args):
    
        cmd_timeout = args.setdefault('timeout',self.command_timeout)
        
        root = _from_cmd_to_xml(cmd)
        try:
            self.send_xml(_to_xml(_wrap_rpc(root)))
            ret = self.get_output(cmd_timeout)
            return ret
        except Exception as inst:
            try:
                self.netconf_disconnect()
            except:
                self._print_log("Fail to disconnect netconf session for reopen")
            self.netconf_connect(timeout=60)        
        try:
            self.send_xml(_to_xml(_wrap_rpc(root)))
            ret = self.get_output(cmd_timeout)
            return ret
        except Exception as inst:
            return inst

    def check_result (self,ret):
        if '<rpc-error>' in ret:
            return ('FAIL','RPCError')
        elif '<rpc-reply' in ret:
            return ('PASS','RPCReply')
        elif '<notification' in ret:
            return ('PASS','NOTIF')
        else:
            return ('FAIL','Other')
   
    def netconf_disconnect (self):
        root = etree.Element("close-session")
        
        self.channel.send(_to_xml(_wrap_rpc(root)))
        self.transport.close()
        self.channel.close()
        
def _from_cmd_to_xml(cmd,**args):

    session_name = args.setdefault('session_name','first_netconf_session')

    capability_cmd = ''
    if 'capabilities:' in cmd:
        capability_cmd = cmd.split('capabilities:')[1]
    
    cmd = cmd.split('capabilities:')[0]
    cmd = cmd.strip('\\r\\n').strip('\\n').strip('\\r')

    #operation = re.search("(\S+?)\(",cmd).group(1)
    operation = re.search("([^\(]+)",cmd).group(1)
    operation = operation.replace('_','-')

    params = re.search("\(([\s\S]*)\)",cmd).group(1)
    params = params.replace('\',\'','\';\'')

    leaf_group = ['running','candidate','startup']
    key_group = ['target','config','default_operation','error_option','test_option',\
                 'source','filter','confirmed','persist','persist-id','timeout','identifier',\
                 'version','format','session-id','data']
    
    # del with the operation with namespace parameter like 'action http://tail-f.com/ns/aaa/1.1'
    if ' ' in operation :
        operation, nameSpace = operation.split(' ')  
        root = etree.Element(operation,nsmap={None:'%s'%nameSpace})  
    else :
        root = etree.Element(operation)  
    param_list = []
    param_grp = []
  
    if params:
        param_grp =  params.split(',')        
    for single_param in param_grp:
        regexp = re.search("(\S+)=([\s\S]*)",single_param)
        if ( regexp and regexp.group(1) in key_group ) or not param_list:
            param_list.append(single_param)
        else:
            param_list[-1] = ','.join([param_list[-1],single_param])
 
    for single_param in param_list:
        regexp = re.search("(\S+)=([\s\S]*)",single_param)
        if regexp :
            key = regexp.group(1)
            value = regexp.group(2) 
            key = key.replace('_','-')
            value = value.strip('(').strip(')').strip('\'')
            # special for confirm
            key = key.replace('timeout','confirmed-timeout')
            # special for get/get-config
            if key == 'filter':
                value_group = value.split(';')
                filter_type = value_group[0].strip('\'')
                value = value_group[-1].strip('\'')
                child = etree.SubElement(root,key,{'type':filter_type})
            else:
                m = re.search("(\w+){(.*)}",key)
                if m :
                    pure_key,xmlns_dict,attr_dict,prefix = _parse_attr(key,session_name) 
                    child = etree.SubElement(root,pure_key,nsmap=xmlns_dict)
                else :      
                    child = etree.SubElement(root,key)
            # if value is xml format
            if value == 'True' or value == 'False':
                continue
            elif value in leaf_group:
                child.append(etree.Element(value))
            elif '<' in value and '>' in value:
                child.append(etree.fromstring(value))
            else:
                child.text = value

    for capability in capability_cmd.split(','):
        try:
            key,value = capability.split('=')
            child = etree.SubElement(root,key)
            child.text = value
        except:
            continue     
    return root

def _change_format (search_string,style=1) :
    search_list = search_string.split(",")       
    index = 0
    search_list_xml = []
    list_xml = []   
    """         
    for index in range(0,len(search_list)) :
        search_list_xml.append(search_list[index].split(" "))
        if len(search_list_xml[index]) > 2 :
            search_list_xml[index] = [search_list_xml[index][0],search_list_xml[index][-1]]
        list_xml.append('<'+search_list_xml[index][0]+'>'+ \
        search_list_xml[index][1]+'</'+search_list_xml[index][0]+'>')
    """
    for item in search_list:
        try :
            key = item.split(" ",1)[0]   # split item in 2 parts  (meaning of 1), [0] first element
            value = item.split(" ",1)[1]   # split item in 2 parts  (meaning of 1), [1] second element
        except Exception as inst :
            raise AssertionError ("input format error, should be 'key value, key value'")
        else :
            if style == 1:
                list_xml.append('<'+key+'>'+ value+'</'+key+'>')
            elif style == 2:
                list_xml.append('<\w+\:'+key+'>'+ value+'</\w+\:'+key+'>')
    return list_xml

def _check_all_items_return_last (search_list,lines) :
    
    found = True  
    for item in search_list :
        orig_item = item
        item = re.sub(" +"," +",item).strip ()           
        res = re.search(item,lines,re.DOTALL) 
        if not res :
            logger.debug("not found : %s" % orig_item)
            found = False
            break
        else :
            logger.debug("found : %s" % orig_item)            
    if found : 
        matched = res.groups()       
        if len(matched) == 0 :
            matched = (res.group(0),)
    else :
        matched = False  
    return matched 

def _check_error (data) :
    res = "PASS"
    error_info = ""
    error_list = ["<rpc-error>"]
    for error_item in error_list :
        if error_item in data :
            res = "FAIL"
            error_info = data
            break
    return (res, error_info)

def _to_xml (elem,encoding ="UTF-8",pretty_print=False):
    xml = etree.tostring(elem, encoding=encoding, pretty_print=pretty_print)
    return xml if xml.startswith('<?xml') else '<?xml version="1.0" encoding="%s"?>%s' % (encoding, xml)

def _wrap_rpc (elem):
    rpc = etree.Element('rpc',{'xmlns':BASE_NS_1_0,'message-id':'1'})
    rpc.append(elem)

    return rpc

def _partial_lock_rpc (elem):    
    rpc = etree.Element("{%s}rpc" % BASE_NS_1_0 ,{'message-id':'1'},nsmap={None:PARTIAL_NS_1_0})
    rpc.append(elem)
    return rpc


def _transfer_string_to_dict ( input_string ) :
    d = {}
    input_string = input_string.strip(',')
    str_group = input_string.split(',')
    for single_str in str_group:
        key,value = single_str.split('=')
        d[key] = value

    return d

def _parse_attr(node,session_name):

    xmlns_map = XMLNS_MAP[session_name]
    res = re.search("(\S+?){",node)
    try:
        key = res.group(1)
    except:
        key = node
    key = key.strip()
    try:
        prefix,key = key.split(':')
    except:
        prefix = None
        key = key
    attr_group = re.findall("{.*?}",node)
    attr_dict = {}
    xml_dict = {}
    
    for single_attr in attr_group:
        single_attr = single_attr.strip('{}').strip()
        try:
            attr,value = single_attr.split(':')
            attr = attr.strip()
            value = value.strip()
            if _is_attr(attr):
                attr = '{%s}%s' % (_is_attr(attr),attr)
                attr_dict[attr] = str(value) 
                continue
            if xmlns_map.get(value) == None:
                raise AssertionError ("%s not found in XMLNS_MAP!" % value)      
            xml_dict[attr] = xmlns_map[value]
            
        except:
            if xmlns_map.get(single_attr) == None:
                raise AssertionError ("%s not found in XMLNS_MAP!" % single_attr)
            xml_dict[None] = xmlns_map[single_attr]
 
    return (key,xml_dict,attr_dict,prefix)

def _is_attr(key):    
    if ATTR_DICT.has_key(key):
        return ATTR_DICT[key]
    else:
        return False

def _add_ns_appendix(appendix,*nodes):
    nodes_appendix = []
    for node in nodes:
        node_appendix = re.sub("{(.*?)}","{\g<1>"+appendix+"}",node)
        for attr in ATTR_DICT.keys():
            node_appendix = re.sub("{("+attr+":.*?)"+appendix+"}","{\g<1>}",node_appendix)
        nodes_appendix.append(node_appendix)
    return nodes_appendix
    
def _get_filter_xml(command_index,*command_elements,**params):
    """
       to generate XML according to node hirachy
       
       2016-7-5 revision 0 by liminxi
       support space in command_element, Nov 21, chunyagu          
    """
    # preoperation before the logic if1/if2[name s1,mtu 1000]/a/b[name s2,mtu 2000]/c/d/e style
    # command_elements leaf1/leaf2[index 0]/leaf3 1
    # name s1,mtu 1000,a/b/name s2,a/b/mtu 2000
    # if1/if2/a/b/c/d/e
    command_element_append = []
    command_elements_bak = []
    mgmt_param = params.setdefault('mgmt_param',{})
    session_name = params.setdefault('session_name','first_netconf_session')

    try :  
        if mgmt_param != {}:
            try:
                mgmt_prefix = mgmt_param['ns_prefix']
                mgmt_appendix = mgmt_param['ns_appendix']
                command_index = mgmt_prefix + _add_ns_appendix(mgmt_appendix,command_index)[0]
                command_elements = _add_ns_appendix(mgmt_appendix,*command_elements)
            except:
                logger.debug("Can not parse netconf mgmt param, please check the input!")

        index_list = re.findall('\[\w.*?\]',command_index)
        for single_index in index_list:
            str_len = len(single_index)
            str_index = command_index.find(single_index)
            end_index = str_index + str_len
            node2insert = command_index[0:str_index].strip('/')
            for one_index in single_index.split(','):
                one_index = one_index.strip('[').strip(']')
                if node2insert:
                    one_index = '/'.join([node2insert,one_index])
                command_element_append.append(one_index)
            command_index = command_index[:str_index] + command_index[end_index:]
 
        node2insert = command_index.strip('/')
        for element in command_elements:
            if node2insert: 
                element = '/'.join([node2insert,element])
            command_elements_bak.append(element)
        command_elements_bak = command_element_append + command_elements_bak
        if command_elements_bak == []:
            command_elements_bak = [node2insert]

        # start to insert the node
        # ['if1/if2/name s1', 'if1/if2/mtu 1000', 'if1/if2/a/b  s2 abc ', 'if1/if2/a/b/mtu 2000', 'if1/if2/a/b/mtu 2000', 
        # 'if1/if2/a/b/c/d/e/leaf1 1',   'if1/if2/a/b/c/d/e/leaf2 2',   'if1/if2/a/b/c/d/e/leaf3 3']
        parent = {}
        xmlns_whole_dict = {}
        instance_parent = []
        instance_list = []
        key_list = []
        for elements in command_elements_bak:
            list_2_elem = elements.split(" ", 1)
            element =list_2_elem[0]
            try :
                value = list_2_elem[1]
            except Exception as inst :
                value = None
                pass
            element_grp = element.split('/')

            for i,single_key in enumerate(element_grp):  
 
                if not single_key :
                    continue
                is_instance = False
                is_new_node = True
                pure_key,xmlns_dict,attr_dict,prefix = _parse_attr(single_key,session_name)  
                pure_key_xmlns = pure_key
                xmlns_whole_dict.update(xmlns_dict)
                if prefix and xmlns_whole_dict.get(prefix):
                    pure_key_xmlns = '{%s}%s' % (xmlns_whole_dict[prefix],pure_key_xmlns)        
                # first root node
                if i == 0:
                    if not parent:
                        root = etree.Element(pure_key_xmlns,attr_dict,nsmap=xmlns_dict)
                        parent[0] = root
                    continue    

                # not first node    
                absolute_path = '/'.join(element_grp[1:i+1])
                absolute_path = re.sub('{.*?}','',absolute_path)
                if i == len(element_grp) - 1:
                    if (absolute_path in instance_list) or (element.rstrip(single_key) not in instance_parent):
                        is_instance = True
                        instance_list.append(absolute_path)
                        instance_parent.append(element.rstrip(single_key))
                if root.find('./'+absolute_path) is None:
                    parent[i] = etree.SubElement(parent[i-1],pure_key_xmlns,attr_dict,nsmap=xmlns_dict)
                    if is_instance:
                        key_list = []
                        key_list.append(absolute_path)
                    else:
                        key_list.append(absolute_path)
                else:
                    # if a instance
                    if is_instance:                    
                        key_list = []
                        key_list.append(absolute_path)
                        # need insert its parent node again
                        #logger.warn("parent:%s" % parent)
                        #logger.warn("i:%s" % i)
                        #logger.warn("parent i-1 : %s" % parent[i-1])
                        #logger.warn("pure_key:%s" % pure_key)
                        #logger.warn("parent pure_key:%s" % parent[i-1].find(pure_key))
                        if parent[i-1].find(pure_key) is not None:
                            parent_key_xmlns,parent_xmlns_dict,parent_attr_dict,parent_prefix = _parse_attr(element_grp[i-1],session_name)
                            if parent_prefix and xmlns_whole_dict.get(parent_prefix):
                                parent_key_xmlns = '{%s}%s' % (xmlns_whole_dict[parent_prefix],parent_key_xmlns)    
                            parent[i-1] = etree.SubElement(parent[i-2],parent_key_xmlns,parent_attr_dict,nsmap=parent_xmlns_dict)
                        parent[i] = etree.SubElement(parent[i-1],pure_key_xmlns,attr_dict,nsmap=xmlns_dict)
                    else:                  
                        # not instance
                        for key in key_list:
                            if re.match(absolute_path,key): 
                                is_new_node = False    
                        if is_new_node or i == len(element_grp)-1:
                            parent[i] = etree.SubElement(parent[i-1],pure_key_xmlns,attr_dict,nsmap=xmlns_dict)
                            key_list.append(absolute_path)

            # check if this node has value
            if value:
                parent[i].text = value   

        xml_string = etree.tostring(root)
        logger.debug("xml message:\n %s" % etree.tostring(root,pretty_print=True))

        return xml_string
    except Exception as inst:
        s = sys.exc_info()
        logger.error("syntax error, lineno:%s, exception:%s" % (s[2].tb_lineno,inst))

def _merge_two_list(list1,list2) : 
    
    list3 = list2

    for a in list1:
        isFound = False
        for b in list2:
            if a == b :
                isFound = True
                break
        if not isFound :
            list3.append(a)
    return list3
 
def _collect_yang_info_from_yang_library (sRpc) :  

    if not re.search ("ietf-yang-library", sRpc) :
        raise AssertionError ("wrong yang-library RPC: %s", sRpc)

    xmlns_map = {}
    d = {}
    l = []
    sModuleEndLable = '</module>'      
    m = re.search('(</[^<]*module>)',sRpc)   
    if m :
        sModuleEndLable = m.group(1)

    lModules = sRpc.split(sModuleEndLable)

    for eachModule in lModules:
        """
        # skip all submodules
        eachModule = re.sub('<[^<]*submodule>.*</[^<]*submodule>','',eachModule)
        """
        
        # get deviation string
        sDeviation = ''
        m = re.search('<[^<]*deviation>(\S+)</[^<]*deviation>',eachModule)
        if m :
            sDeviation = m.group(1)
            eachModule = re.sub('<[^<]*deviation>.*</[^<]*deviation>','',eachModule)

        # get submodule string
        sSubmodule = ''
        m = re.search('<[^<]*submodule>(\S+)</[^<]*submodule>',eachModule)
        if m :
            sSubmodule = m.group(1)
            eachModule = re.sub('<[^<]*submodule>.*</[^<]*submodule>','',eachModule)

        # set conformance-type string
        sConformanceType = ''
        m = re.search('<[^<]*conformance-type>([^<]+)</[^<]*conformance-type>',eachModule)
        if m :
            d['conformance-type'] = m.group(1)

        # set revision string
        sRevision = ''
        m = re.search('<[^<]*revision>([^<]+)</[^<]*revision>',eachModule)
        if m :
            d['revision'] = m.group(1)

        # get features string
        sFeature = ''
        m = re.search('<[^<]*feature>(\S+)</[^<]*feature>',eachModule)
        if m :
            sFeature = m.group(1)
            eachModule = re.sub('<[^<]*feature>.*</[^<]*feature>','',eachModule)

        # set namespace
        m = re.search('<[^<]*namespace>(\S+)</[^<]*namespace>',eachModule)
        if m :
            d['namespace'] = m.group(1)

        # set module name
        # should search like '<name>(\S+)</name>' or '<yanglib:name>(\S+)</yanglib:name>'
        m = re.search('<[^<]*name>(\S+)</[^<]*name>',eachModule)
        if m :
            module_name = m.group(1)
            d['module'] = module_name
            xmlns_map[module_name] = d['namespace']

        # set deviation
        if sDeviation:

            lDeviation = sDeviation.split('</deviation>')
            for eachDeviation in lDeviation:

                dict_deviation = {}
                m = re.search('<[^<]*name>(\S+)</[^<]*name>',eachDeviation)
                if m :
                    dict_deviation['name'] = m.group(1)
                n = re.search('<[^<]*revision>(\S+)</[^<]*revision>',eachDeviation)
                if n :
                    dict_deviation['revision'] = n.group(1)
                
                if m :
                    deviation_name = 'deviations_' + dict_deviation['name']
                    d [deviation_name] = dict_deviation 

        # set submodule
        if sSubmodule:

            lSubmodule = sSubmodule.split('</submodule>')
            for eachModule in lSubmodule:
                dict_submodule = {}
                m = re.search('<[^<]*name>(\S+)</[^<]*name>',eachModule)
                if m :
                    dict_submodule['name'] = m.group(1)
                n = re.search('<[^<]*revision>(\S+)</[^<]*revision>',eachModule)
                if n :
                    dict_submodule['revision'] = n.group(1)
                
                if m : 
                    submodule_name = 'submodule_' + dict_submodule['name']
                    d [submodule_name] = dict_submodule 

        # set features
        if sFeature:
            sFeature = re.sub('</[^<]*feature><[^<]*feature>',',',sFeature)
            sFeature = re.sub('</[^<]*feature>',',',sFeature)
            sFeature = re.sub('<[^<]*feature>',',',sFeature)
            #sFeature.strip('<feature>').strip('</feature>')
            if sFeature :
                d ['features'] = sFeature
             
        l.append(d)
        d = {}
        
    return (l,xmlns_map)
        
def _collect_yang_info_from_hello (hello) :  

    if not re.search ("<capability>.*</capability>", hello) :
        raise AssertionError ("wrong hello: %s", hello)

    xmlns_map = {}
    d = {}
    l = []         
    for capability in re.findall("<capability>(.*?)</capability>",hello) :
        capab_list = capability.split ("?")      
        d['namespace'] = capab_list[0]
        if len(capab_list) > 1 :
            capab_params = capab_list[1].strip ("'").strip('"')
            m=re.search("module=([^;]+)",capab_params)
            if m :
                module_name = re.sub("&amp","",m.group(1))
                d ['module'] = module_name
                xmlns_map[module_name] = d['namespace']

            m=re.search("conformance-type=([^;]+)",capab_params)
            if m :
                d ['conformance-type'] = m.group(1)
            m=re.search("revision=([^;]+)",capab_params)
            if m :
                d ['revision'] = m.group(1)
            m=re.search("deviations=([^;]+)",capab_params)
            if m :
                d ['deviations'] = m.group(1)               
            m=re.search("features=([^;]+)",capab_params)
            if m :
                d ['features'] = m.group(1)
               
        l.append(d)
        d = {}
        
    return (l,xmlns_map)
      
def _get_extend_element(list1,list2):
    '''
    internal function for netconf merge rpc
    '''
    element = []
    for single_node in list2:
        if re.search('^name',single_node) and single_node in list1:
            continue
        element.append(single_node)
    return element

def _find_common_str(str1,str2):
    '''
    internal function for netconf merge rpc
    '''
    i = 0
    common_str = ''
    for letter in str1:
        try:
            if letter == str2[i]:
                common_str = common_str + letter
            else:
                break
        except:
            break
        i+=1
    if '/' not in common_str:
        common_str = ''
    if common_str == '':
        return ('',str1,str2)
     
    if common_str != str1 and common_str != str2:
        common_str = '/'.join(common_str.split('/')[0:-1])
        common_str = common_str + '/'
    (str_pre,string,str_post1) = str1.partition(common_str)
    (str_pre,string,str_post2) = str2.partition(common_str)

    if re.match("{operation:",str_post1):
        common_str = common_str + str_post1
        str_post1 = ''
    elif re.match("{operation:",str_post2):
        common_str = common_str + str_post2
        str_post2 = ''
    return (common_str,str_post1,str_post2)
               
                                 
def _get_merge_rpc(**params):
    '''
    internal function for netconf merge rpc
    '''
    device_manager = {}
    device_node = {}

    session_name = params.setdefault('session_name','first_netconf_session')
    # get common part from command index to prefix
    index_list = []
    for single_node in RPC_NODE_INFO[session_name]:
        index_list.append(single_node['command_index'])
    i = 0
    for single_node in RPC_NODE_INFO[session_name]:
        index_list_tmp = copy.copy(index_list)
        index_list_tmp.remove(single_node['command_index'])
        common_index,match_index,index_post = _find_common_prefix(single_node['command_index'],*index_list_tmp)
        RPC_NODE_INFO[session_name][i]['prefix'] = common_index
        RPC_NODE_INFO[session_name][i]['command_index'] = index_post
        i+=1    

    i = 0
    prefix_list = []
    for single_node in RPC_NODE_INFO[session_name]:
        config_xml = _get_filter_xml(single_node['command_index'],*single_node['command_elements'],session_name=session_name)
        config_xml = NETCONF_OBJ[session_name].xml_post_operation('edit-config',config_xml) 
        if single_node['prefix'] == '':
            device_manager[i] = etree.fromstring(config_xml)
        else:
            common_prefix,match_prefix,prefix_post = _find_common_prefix(single_node['prefix'],*prefix_list)
            if common_prefix == '':
                device_manager[single_node['prefix']] = _get_prefix_xml(single_node['prefix'],**params)
                node = _find_node(device_manager[single_node['prefix']],single_node['prefix'].split('/')[-1])
                node.append(etree.fromstring(config_xml))
            else:
                if prefix_post != '':
                    root = _get_prefix_xml(prefix_post,**params)
                    prefix_node = _find_node(root,prefix_post.split('/')[-1])
                    prefix_node.append(etree.fromstring(config_xml))
                else:
                    root = etree.fromstring(config_xml)
                try:
                    name = re.search('\[name (\S+)\]',common_prefix.split('/')[-2]).group(1)
                except:
                    name = None
                insert_node = _find_node(device_manager[match_prefix],common_prefix.split('/')[-1],name=name)
                insert_node.append(root)      
                self._print_log (etree.tostring(device_manager[match_prefix],pretty_print=True))
        prefix_list.append(single_node['prefix'])         
        i+=1

    i = 0
    for key in device_manager.keys():
        if i == 0:           
            root,config = _wrap_edit_config(etree.tostring(device_manager[key]),**params)
        else:
            config.append(device_manager[key])   
        i+=1 

    return root

def _find_common_prefix(prefix,*prefix_list):
    common_str = ''
    match_prefix = ''
    i = 0
    for single_prefix in prefix_list:
        tmp_common,str_post1,str_post2 = _find_common_str(prefix,single_prefix)
        if tmp_common != '' and match_prefix == '':
            match_prefix = single_prefix
        if tmp_common > common_str:
            common_str = tmp_common    
            
    if common_str == '':
        return common_str,match_prefix,prefix
    a,b,c = prefix.partition(common_str)
    str_post = c.lstrip('/').rstrip('/')
    common_str = common_str.rstrip('/')

    # check if str_post does not has '/',need place back common_str
    if '/' not in str_post and str_post != '':
        str_post = common_str.split('/')[-1]+'/'+str_post
        common_str = '/'.join(common_str.split('/')[0:-1])

    return common_str,match_prefix,str_post
    
def _find_node(root,tag,**params):
    '''
    internal function for netconf merge rpc
    '''
    name = params.setdefault('name',None)
    tag=re.sub('\{\S+\}','',tag)
    if name:
        for node in root.iter():
            if 'name' in node.tag and node.text == name:
                break
        for s_sibling in node.itersiblings():
            if tag in s_sibling.tag:
                return s_sibling
    
    for node in root.iter():
        if tag in node.tag:
            return node    

def _get_prefix_xml(prefix,**params):
    '''
    internal function for netconf merge rpc
    '''
    prefix = prefix.rstrip('/') 
    command_index = '/'.join(prefix.split('/')[0:-1])
    if command_index == '':
        ns_prefix = _get_filter_xml(prefix,**params)
    else:   
        command_element = prefix.split('/')[-1]
        ns_prefix = _get_filter_xml(command_index,command_element,**params)

    return(etree.fromstring(ns_prefix))
    

def _wrap_edit_config(config_xml,**params):
    '''
    internal function for netconf merge rpc
    '''
    # set default value
    source = params.setdefault('source','running')
    default_operation = params.setdefault('default_operation',None)
    error_option = params.setdefault('error_option',None)
    test_option = params.setdefault('test_option',None)

    root = etree.Element('edit-config')
    target = etree.SubElement(root,'target')
    running = etree.SubElement(target,source)
    config = etree.SubElement(root,'config')
    
    # append default_operation, error_option and test_option
    if default_operation :
        do = etree.SubElement(root,'default_operation')
        do.text = default_operation
    if error_option :
        eo = etree.SubElement(root,'error_option')
        eo.text = error_option
    if test_option:
        to = etree.SubElement(root,'test_option')
        to.text = test_option
      
    # append config_xml as a child of 'config' tag
    config.append(etree.fromstring(config_xml))  
    return (root,config) 
      
def get_yang_info (module=None,namespace=None,session_name='first_netconf_session') :
    """
      return the capabilities 
    """

    global YANG_INFO
    if module :
        search_key = "module"
        search_value = module
    elif namespace :
        search_key = "namespace"
        search_value = namespace
    else :
        search_key = None
        
    if not search_key :
        return YANG_INFO[session_name]   
    for item in YANG_INFO[session_name] :
        if item[search_key] == search_value :
            return item
    else :
        raise AssertionError ("no found yang with '%s:%s'" % (search_key,search_value))

class Logger():
    def __init__(self,dir_path):
        self.dir_path = dir_path
        self.fd = open(self.dir_path,"w+")

    def writelines(self,line):
        self.fd.writelines(str(line))

    def __del__(self):
        self.fd.close()

if __name__ == '__main__' :    
    session_name = ssh_netconf(ip='135.251.247.215', port='830', username='admin', password='Netconf#150')
    ret_hello = session_name.netconf_connect()
    YANG_INFO,XMLNS_MAP = _collect_yang_info_from_hello(ret_hello)
    session_name.netconf_disconnect()
    print YANG_INFO
    print XMLNS_MAP 

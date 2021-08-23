#!/usr/bin/env python
"""
    filter output.xml to get necessary test commands
    version: 0.1
    usage:
        python3 filter_robot_output.py --robot_option  "--test EQMT_CRB_FWD_01" \
            --log http://smartlab-service.int.net.nokia.com:9000/log/Fi-Hardening_and_CFT/6202.432/NFXSE_FANTF_XGSPON_FWLTB_OLD_01/SB_Logs_atxuser-Jan14132927_EQMT/ROBOT/output.xml

"""
import re
import sys
import os
import argparse
import robot
from xml.dom.minidom import parseString


HIERARCHY_SYNTAX_MAP = {
    'SUITE_START': ['SUITE>> ',['id','name'],'<suite [^>]*id="([^"]*)" name="([^"]*)"[^>]*>'],
    'TEST_START' : ['\n\tCASE>> ',['id','name'],'<test id="(.*)" name="(.*)">'],
    'SETUP':       ['SETUP>> ',['name'],'<kw [^>]*type="(setup)"[^>]*>'],
    'TEARDOWN'  :  ['TEARDOWN>> ',['name'],'<kw [^>]*type="(teardown)"[^>]*>'],
    'SUITE_END' :  ['SUITE>> ',['status','info'],'<status status="(\w+)" [^>]*>(.*)</status>(\r|\n)+</suite>'],
    'TEST_END'  :  ['RESULT>> ',['status','info'],'<status status="(\w+)".*">(.*)</status>.*</test>']
}

TYPE_SYNTAX_MAP = {
    'CLI' : ['  ','<msg[^>]*level="INFO"[^>]*>[^>]+CLI CMD &gt;&gt; (.*)&lt;[^>]'],
    'CLI_2' : ['  ','<msg[^>]*level="INFO"[^>]*>[^>]+CLI CMD &gt;&gt; ([^si].*)&lt;[^>]'],
    'TL1' : ['  ','<msg[^>]*level="INFO"[^>]*>TL1 CMD &gt;&gt; (.*);'],
    'PCTA' : ['  ','<msg[^>]*level="INFO"[^>]*>[^>]*PCTA CMD &gt;&gt; (.*?)(?:(?:&lt;[^>])|(?:</msg>))'],
    'SNMP': ['  ','<msg[^>]*level="INFO"[^>]*>[^>]*SNMP REPLY&lt;&lt; (.*)'],
    'SSH' : [' ','<msg[^>]*level="INFO"[^>]*>[^>]+?SSH CMD &gt;&gt; +(.*?)&lt;.*?</msg>'],
    'RPC_XML_SEND' : [' ','<msg[^>]*level="DEBUG"[^>]*>send xml to netconf server:(.*)'],
    'RPC_XML_REPLY' : [' ','<msg[^>]*level="DEBUG"[^>]*>NETCONF REPLY &lt;&lt; (.*)'],
    'RPC_CLI_SEND' : [' ','<msg[^>]+level="INFO">NETCONF CLI SEND:(.*)'],
    'RPC_CLI_REPLY' : [' ','<msg[^>]+level="INFO">NETCONF CLI REPLY:(.*)'],
    'STC' : ['  ','<msg[^>]+level="DEBUG"[^>]+>[^>]+CMD EXEC: (stc::.*?)</msg[^>]*>'],
    'TRACE': ['  ','<msg[^>]+level="INFO"[^>]+>[^>]+TND CMD &gt;&gt; (.*?)&lt;.*?</msg[^>]*>'],
    'TND': ['  ','<msg[^>]+level="INFO"[^>]+>[^>]+TND CMD &gt;&gt; (.*?)&lt;.*?</msg[^>]*>'],
}

PROCESS_STATUS = {
    'SUITE_LAYER': 0,
    'TEST_LAYER': 0,
    'SETUP_LAYER': 0,
    'TEARDOWN_LAYER': 0,
    'KEYWORD_LAYER': 0
}

CHECK_STATUS = False
STATUS_LINE = ""
LAST_COMMAND = ""
CURRENT_LINE = ""
CURRENT_COMMAND_TYPE = ""
ITEM_NEED_PREFIX = ""

def check_kw_layer (line):
    """
    check if current line is in setup or teardown for indent numbers
    """
    syntax_kw_start = '<kw type="(setup|kw|teardown){1}" name=".*">'
    syntax_kw_end = '</kw>'

    if re.search(syntax_kw_start,line) :
        PROCESS_STATUS['KEYWORD_LAYER']+= 1
        if re.search('<kw type="setup" name=".*">',line) :
            PROCESS_STATUS['SETUP_LAYER'] = 1

        if re.search('<kw type="teardown" name=".*">',line) :
            PROCESS_STATUS['TEARDOWN_LAYER'] = 1


    elif re.search(syntax_kw_end,line) :
        PROCESS_STATUS['KEYWORD_LAYER']-= 1
        if PROCESS_STATUS['KEYWORD_LAYER'] == 0 :
            PROCESS_STATUS['SETUP_LAYER'] = 0
            PROCESS_STATUS['TEARDOWN_LAYER'] = 0



def print_hierarchy_start_info (line):
    """
    record SUITE and TEST info
    """
    info = re.search(HIERARCHY_SYNTAX_MAP['SUITE_START'][2] , line)
    if info :
        layer_list = info.group(1).split("-")
        PROCESS_STATUS['SUITE_LAYER'] = len(layer_list)-1
        prefix = "  "*PROCESS_STATUS['SUITE_LAYER']+HIERARCHY_SYNTAX_MAP['SUITE_START'][0]
        print(prefix+info.group(2))
        info = None
        return True

    info = re.search(HIERARCHY_SYNTAX_MAP['TEST_START'][2] , line)
    if info :
        layer_list = info.group(1).split("-")
        PROCESS_STATUS['TEST_LAYER'] = len(layer_list)-1
        prefix = "  "*PROCESS_STATUS['TEST_LAYER']+HIERARCHY_SYNTAX_MAP['TEST_START'][0]
        print(prefix+info.group(2))
        info = None
        return  True
    info = re.search(HIERARCHY_SYNTAX_MAP['SETUP'][2] , line)
    if info :
        if PROCESS_STATUS['TEST_LAYER'] != 0 :
            indent = PROCESS_STATUS['TEST_LAYER'] + 1
        elif  PROCESS_STATUS['SUITE_LAYER'] != 0 :
            indent =  PROCESS_STATUS['SUITE_LAYER'] + 1
        else :
            indent = 0
        prefix = "  "*indent+HIERARCHY_SYNTAX_MAP['SETUP'][0]
        print(prefix+info.group(1))
        info = None
        return  True
    info = re.search(HIERARCHY_SYNTAX_MAP['TEARDOWN'][2] , line)
    if info :
        if PROCESS_STATUS['TEST_LAYER'] != 0 :
            indent = PROCESS_STATUS['TEST_LAYER'] + 1
        elif  PROCESS_STATUS['SUITE_LAYER'] != 0 :
            indent =  PROCESS_STATUS['SUITE_LAYER'] + 1
        else :
            indent = 0
        prefix = "  "*indent+HIERARCHY_SYNTAX_MAP['TEARDOWN'][0]
        print(prefix+info.group(1))
        info = None
        return  True
    return False

def print_hierarchy_end_info (line):
    """
    record SUITE and TEST status
    """
    global CHECK_STATUS, STATUS_LINE
    if re.search ('<status status="\w+" .*>.*',line) :
        STATUS_LINE = STATUS_LINE + line
        CHECK_STATUS = True
        return False
    if CHECK_STATUS and not re.search ('</(kw|test|suite)>',line) :
        STATUS_LINE = STATUS_LINE + line
        return False

    if CHECK_STATUS and re.search ('</(kw)>',line):
        STATUS_LINE = ""
        CHECK_STATUS = False
        return False

    if CHECK_STATUS and re.search ('</suite>',line):
        CHECK_STATUS = False
        STATUS_LINE = STATUS_LINE + line
        info = re.search(HIERARCHY_SYNTAX_MAP['SUITE_END'][2], STATUS_LINE, re.S)
        if info :
            prefix = "  "*PROCESS_STATUS['SUITE_LAYER']+HIERARCHY_SYNTAX_MAP['SUITE_END'][0]
            print(prefix+info.group(1))
            info = None
            PROCESS_STATUS['SUITE_LAYER']-= 1
            return True

    if CHECK_STATUS and re.search ('</test>',line):
        CHECK_STATUS = False
        prefix = "  "*PROCESS_STATUS['TEST_LAYER']+HIERARCHY_SYNTAX_MAP['TEST_END'][0]
        PROCESS_STATUS['TEST_LAYER'] = 0
        STATUS_LINE = STATUS_LINE + line
        info = re.search(HIERARCHY_SYNTAX_MAP['TEST_END'][2], STATUS_LINE, re.S)
        if info :
            print(prefix+info.group(1))
            info = None
            return True
    return False


def print_test_info (line,command_type,filter_test_info=None) :
    """
    record test command executed
    """
    global LAST_COMMAND, CURRENT_LINE, CURRENT_COMMAND_TYPE, ITEM_NEED_PREFIX
    if PROCESS_STATUS['TEST_LAYER'] != 0 :
        indent_num = PROCESS_STATUS['TEST_LAYER'] + 1
        if PROCESS_STATUS['SETUP_LAYER'] or PROCESS_STATUS['TEARDOWN_LAYER'] :
            indent_num+= 1
    elif  PROCESS_STATUS['SUITE_LAYER'] :
        indent_num = PROCESS_STATUS['SUITE_LAYER'] + 1
        if PROCESS_STATUS['SETUP_LAYER'] or PROCESS_STATUS['TEARDOWN_LAYER'] :
            indent_num+= 1
    else :
        indent_num = 0

    is_target_command = False
    is_trace_command = False

    if CURRENT_LINE == "" :
        for item in command_type :
            prefix,syntax = TYPE_SYNTAX_MAP[item.upper()]
            matched = re.search(syntax,line)
            if matched :
                CURRENT_COMMAND_TYPE = item.upper()
                if not re.search("</msg>",line) :
                    CURRENT_LINE = CURRENT_LINE + line
                else :
                    is_target_command = True
                    if item == 'TRACE' or item == 'RPC_CLI_SEND' :
                        ITEM_NEED_PREFIX = item
                break
            else :
                continue
    else :
        if not re.search("</msg>",line) :
            CURRENT_LINE = CURRENT_LINE + line
            return False
        else :
            CURRENT_LINE = CURRENT_LINE + line
            prefix,syntax = TYPE_SYNTAX_MAP[CURRENT_COMMAND_TYPE]
            matched = re.search(syntax+"</msg>",CURRENT_LINE,re.S)
            #CURRENT_COMMAND_TYPE = ""
            if not matched :
                print("target line can not be matched by: ")
                print("'"+syntax+"</msg>'")
                print(CURRENT_LINE)
                print("\n")
                return False
            else :
                is_target_command = True

    if is_target_command :
        current_command = matched.group(1).replace(" \r","").replace(" \n","").replace("</msg>","")
        if ITEM_NEED_PREFIX :
            current_command = ITEM_NEED_PREFIX + '::' + current_command
            ITEM_NEED_PREFIX = ''
        if current_command != LAST_COMMAND :
            lines = current_command.split("\n")
            tidy_command = ""
            for current_line in lines :
                tidy_command = tidy_command + prefix*indent_num + current_line

            # replace '&lt;' and '&gt;'
            tidy_command = tidy_command.replace('&lt;','<')
            tidy_command = tidy_command.replace('&gt;','>')

            if filter_test_info :
                if not filter_test_info[CURRENT_COMMAND_TYPE] :
                    print_cmd(tidy_command, indent_num = indent_num)
                else :
                    for each in filter_test_info[CURRENT_COMMAND_TYPE].split(','):
                        if each in tidy_command:
                            print_cmd(tidy_command, indent_num = indent_num)
                            break

        LAST_COMMAND = current_command
        CURRENT_LINE = ""
        return True
    else :
        return False


def print_cmd(cmd_str, indent_num):
    try:
        rpc = parseString(cmd_str)
        rpc = rpc.toprettyxml()
        rpc2 = re.sub('>\n\t+\s+\n', '>\n', rpc)
        for line in rpc2.split('\n')[1:]:
            line = line.replace('\t', '  ')
            print(' '*indent_num  + line)
    except:
        print(cmd_str)



def filter_log (file_name,info_type) :
    """
    main function to check and record each line from input file
    """

    # if info_type was given, users only care about specific commands in it
    # or filter and write all commands defined in TYPE_SYNTAX_MAP to result file
    filter_dict = {}
    filter_info_dict = {}
    if info_type != None :
        for each in info_type :
            if ':' in each  :
                type_name,filter_info = each.split(':')
            else :
                type_name = each
                filter_info = None
            if type_name in TYPE_SYNTAX_MAP:
                filter_dict[type_name] = TYPE_SYNTAX_MAP[type_name]
                filter_info_dict[type_name] = filter_info

            print("type:%s" % type_name)
            print("filter_info:%s" % filter_info)
    else :
        filter_dict = TYPE_SYNTAX_MAP
        for key_item in filter_dict.keys():
            filter_info_dict[key_item] = None

    with open(file_name,'r') as file_handler:
        data = file_handler.readlines()

    print("filter_dict:%s" % filter_dict.keys() )
    for line in data:
        print_hierarchy_end_info(line)
        if not CHECK_STATUS :
            check_kw_layer (line)
            if print_test_info(line,filter_dict.keys(),filter_info_dict):
                continue
            if print_hierarchy_start_info (line):
                continue




if __name__ == '__main__' :

    import sys, time

    parser = argparse.ArgumentParser()
    parser.add_argument('--robot_option', default=[])
    parser.add_argument('--type', default=['CLI'], nargs='+')
    parser.add_argument('--log', default='output.xml')
    args = parser.parse_args()
    print(args)


    if args.log.startswith('http'):
        if os.path.exists('output.xml'):
            os.remove('output.xml')
        if args.log.endswith('log.html'):
            url_log = args.log.replace('log.html', 'output.xml')
        elif args.log.endswith('ROBOT/'):
            url_log = args.log + 'output.xml'
        else:
            url_log = args.log
        print('start download output.xml: %s' % url_log)
        os.system('curl  %s -o output.xml' % url_log)
        if os.path.exists('output.xml'):
            print('download success!')
            log_path = 'output.xml'
        else:
            print('download failed.')
            exit(-1)
    else:
        log_path = args.log


    if args.robot_option:
        if os.path.exists('output_tmp.xml'):
            os.remove('output_tmp.xml')
        robot_option = args.robot_option.split(' ')
        robot_option = [x.strip() for x in robot_option]
        robot_option = [x for x in robot_option if x]
        robot_option.append('-o')
        robot_option.append('output_tmp.xml')
        robot_option.append(log_path)
        print('rebot args: %s' % robot_option)
        robot.rebot_cli(robot_option, exit=False)
        time.sleep(1)
        if not os.path.exists('output_tmp.xml'):
            raise RuntimeError('run rebot failed')
        log_path = 'output_tmp.xml'


    print(log_path)
    filter_type_list = args.type
    print('='*120)
    filter_log(log_path, filter_type_list)
    print('='*120)






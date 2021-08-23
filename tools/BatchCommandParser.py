#!/usr/bin/env python
"""
    filter output.xml to get necessary test commands
    
    usage:
        python BatchCommandParser.py 6002.503 SHA_NFXSE_FANTG_P2P_A2A_WEEKLY_01 
      
    return:
        a result file named output.xml.indent will be gotten
        a middle file named output.xml.list which is not strict indented will be create also
      
    History:
        Jan 9th 2019: designed by jieminbz,huanhu

"""
import re,getopt

HIERARCHY_SYNTAX_MAP = {
    'SUITE_START': ['SUITE>> ',['id','name'],'<suite source=".*" id="(.*)" name="(.*)">'],
    'TEST_START' : ['CASE>> ',['id','name'],'<test id="(.*)" name="(.*)">'],
    'SUITE_END' :  ['SUITE>> ',['status','info'],'</suite>'],
    'TEST_END'  :  ['RESULT>> ',['status','info'],'</test>']
}

TYPE_SYNTAX_MAP = {
    'CLI' : ['<CLI CMD>','<msg[^>]+level="INFO">[^>]+CLI CMD &gt;&gt; (.*)&lt;[^>]'],
    'TL1' : ['<TL1 CMD>','<msg[^>]+level="INFO">TL1 CMD &gt;&gt; (.*);'],
    'PCTA' : ['<PCTA CMD>','<msg[^>]+level="DEBUG">+PCTA CMD &gt;&gt; (.*)[^<]'],
    'SNMP': ['<SNMP>','<msg[^>]+level="INFO">[^>]+SNMP REPLY&lt;&lt; (.*)'],
    'SSH' : ['<SSH CMD>','<msg[^>]+level="INFO">[^>]+SSH CMD &gt;&gt; (.*)&lt;.*?</msg>'],
    'STC' : ['<STC>','<msg[^>]+level="DEBUG">[^>]+CMD EXEC: (stc::.*?)</msg[^>]*>'],
    'TND' : ['<TND CMD>','<msg[^>]+level="INFO">[^>]+TND CMD &gt;&gt; (.*?)&lt;.*?</msg[^>]*>']
}

PROCESS_STATUS = {
    'SUITE_LAYER': 0,
    'SUITE_NAME': [],
    'TEST_LAYER': 0,
    'TEST_NAME': "",
    'SETUP_LAYER': 0,
    'TEARDOWN_LAYER': 0, 
    'KEYWORD_LAYER': 0,
    'USERKW_LAYER': 0,
    'USERKW_NAME': []
}

LAST_COMMAND = ""
CURRENT_LINE = ""
CURRENT_COMMAND_TYPE = ""
"""
 for indent
"""
PRELINE_LAYER_BE = 0
PRELINE_LAYER_AF = 0
LINE_LAYER_BE = 0
LINE_LAYER_AF = 0
LAST_KW_LAYER = 0
PRE_CMD = 0
LAST_KW_LAYER_BE = 0
LAST_KW_LAYER_AF = 0

def print_hierarchy_start_info (line,file_handler):
    """
    record SUITE and TEST info
    """
    suite_name = ""
    info = re.search(HIERARCHY_SYNTAX_MAP['SUITE_START'][2] , line) 
    if info :
        layer_list = info.group(1).split("-")
        suite_name = info.group(2)
        PROCESS_STATUS['SUITE_LAYER'] = len(layer_list)-1
        PROCESS_STATUS['SUITE_NAME'].append(suite_name)
        prefix = "    "*PROCESS_STATUS['SUITE_LAYER']+HIERARCHY_SYNTAX_MAP['SUITE_START'][0]
        file_handler.writelines(prefix+info.group(2)+' START'+"\n" )
        info = None
        return True
    info = re.search(HIERARCHY_SYNTAX_MAP['SUITE_END'][2] , line) 
    if info :
        prefix = "    "*PROCESS_STATUS['SUITE_LAYER']+HIERARCHY_SYNTAX_MAP['SUITE_END'][0]
        if PROCESS_STATUS['SUITE_NAME'] :
            suite_name = PROCESS_STATUS['SUITE_NAME'][-1]
            PROCESS_STATUS['SUITE_NAME'].pop()
        file_handler.writelines(prefix+suite_name+' END'+"\n" )
        PROCESS_STATUS['SUITE_LAYER'] -= 1
        info = None
        return True       
    info = re.search(HIERARCHY_SYNTAX_MAP['TEST_START'][2] , line)
    if info :
        layer_list = info.group(1).split("-")
        PROCESS_STATUS['TEST_NAME'] = info.group(2)
        PROCESS_STATUS['TEST_LAYER'] = len(layer_list)-1
        prefix = "    "*PROCESS_STATUS['TEST_LAYER']+HIERARCHY_SYNTAX_MAP['TEST_START'][0]
        file_handler.writelines(prefix+info.group(2)+"\n" )
        info = None
        return  True
    info = re.search(HIERARCHY_SYNTAX_MAP['TEST_END'][2] , line) 
    if info :
        PROCESS_STATUS['TEST_LAYER'] = 0
        info = None
        return True
    return False



def print_keyword_name (line,file_handler):
    """
    print user defined keyword
    """
    info_all = re.search(r'<kw (?:type=\".*\")?\s*?name=\"([^\"]*)\".*>', line)
    info = re.search(r'<kw (?:type=\"(setup|kw|teardown)[\w\s]*\")?\s*?name=\"([^\"]*)\"\s*?(library=\"(?!(BuiltIn|gpon_cli|Collections|String|OperatingSystem|cli_command|Telnet))[\w\s]+\")?>',line)

    if info_all :
        kw_name = info_all.group(1)
        if PROCESS_STATUS['TEST_LAYER'] != 0 :
            PROCESS_STATUS['USERKW_NAME'].append(kw_name)
            PROCESS_STATUS['USERKW_LAYER'] = PROCESS_STATUS['TEST_LAYER'] + len(PROCESS_STATUS['USERKW_NAME']) - 1
        elif  PROCESS_STATUS['SUITE_LAYER'] != 0 :
            PROCESS_STATUS['USERKW_NAME'].append(kw_name)
            PROCESS_STATUS['USERKW_LAYER'] = PROCESS_STATUS['SUITE_LAYER'] + len(PROCESS_STATUS['USERKW_NAME']) - 1
        else :
            PROCESS_STATUS['USERKW_NAME'].append(kw_name)
            PROCESS_STATUS['USERKW_LAYER'] = len(PROCESS_STATUS['USERKW_NAME']) - 1
        if info :
            indent = PROCESS_STATUS['USERKW_LAYER']
            if info.group(1) != None :
                prefix = "    "*indent+"  "+info.group(1).upper()+">>"
            else :
                prefix = "    "*indent+"  "
            file_handler.writelines(prefix+kw_name+"\n" )
        info = None
        info_all = None
        return  True

    info = re.search(r'</kw>',line)
    if info and PROCESS_STATUS['USERKW_NAME'] != [] :
        PROCESS_STATUS['USERKW_LAYER'] -= 1
        PROCESS_STATUS['USERKW_NAME'].pop()
        if PROCESS_STATUS['USERKW_NAME'] == [] :
                PROCESS_STATUS['USERKW_LAYER'] = 0
        info = None
        info_all = None
        return  True

def print_command (line,file_handler,command_type):
    """
    print filtered commands
    """
    global LAST_COMMAND, CURRENT_LINE, CURRENT_COMMAND_TYPE
    if PROCESS_STATUS['USERKW_LAYER'] != 0 :
        indent = PROCESS_STATUS['USERKW_LAYER'] + 1
    elif  PROCESS_STATUS['TEST_LAYER'] != 0 :
        indent = PROCESS_STATUS['TEST_LAYER'] + 1
    elif  PROCESS_STATUS['SUITE_LAYER'] != 0 :
        indent = PROCESS_STATUS['SUITE_LAYER'] + 1
    else :
        indent = 0

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
                    if item == 'TND' :
                        is_trace_command = True 
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
            if not matched :
                print "target line can not be matched by: "
                print "'"+syntax+"</msg>'"
                print CURRENT_LINE
                print "\n"
                return False    
            else :
                is_target_command = True
                if item == 'TND' :
                    is_trace_command = True 
          
    if is_target_command :                                         
        current_command = matched.group(1).replace(" \r","").replace(" \n","").replace("</msg>","")
        if is_trace_command :
            current_command = 'trace::' + current_command
        if current_command != LAST_COMMAND :
            lines = current_command.split("\n")
            tidy_command = ""
            for current_line in lines :
                tidy_command = tidy_command + "    "*indent + "  " + prefix + current_line +"\n"

            # replace '&lt;' and '&gt;'
            tidy_command = tidy_command.replace('&lt;','<')
            tidy_command = tidy_command.replace('&gt;','>') 

            #if not filter_test_info[CURRENT_COMMAND_TYPE] :
            file_handler.writelines(tidy_command)
        LAST_COMMAND = current_command
        CURRENT_LINE = ""
        return True
    else :
        return False

def print_hierarchy (line,file_handler):

    global PRELINE_LAYER_BE,PRELINE_LAYER_AF,LINE_LAYER_BE,LINE_LAYER_AF,PRE_CMD,LAST_KW_LAYER_AF,LAST_KW_LAYER_BE
    info = re.search(r'([\w\<].*)',line)
    info_cmd = re.search('<CLI CMD>|<TL1 CMD>|<PCTA CMD>|<SNMP>|<SSH CMD>|<STC>|<TND CMD>',line)
    if info :
        LINE_CONTENT = info.group(1)
        LINE_LAYER_BE = info.span()[0]
        if LINE_LAYER_BE > PRELINE_LAYER_AF and PRE_CMD and info_cmd :
            LINE_LAYER_AF = PRELINE_LAYER_AF
        elif LINE_LAYER_BE - PRELINE_LAYER_BE >= 4:
            LINE_LAYER_AF = PRELINE_LAYER_AF + 4
        elif LINE_LAYER_BE == PRELINE_LAYER_BE :
            LINE_LAYER_AF = PRELINE_LAYER_AF
        elif LINE_LAYER_BE < PRELINE_LAYER_BE and LINE_LAYER_BE > PRELINE_LAYER_AF and not info_cmd:
            if LINE_LAYER_BE == LAST_KW_LAYER_BE :
                LINE_LAYER_AF = LAST_KW_LAYER_AF
            elif LINE_LAYER_BE < LAST_KW_LAYER_BE :
                LINE_LAYER_AF = LAST_KW_LAYER_AF - 4
        else :
            LINE_LAYER_AF = LINE_LAYER_BE
        prefix = " "*LINE_LAYER_AF

        file_handler.writelines(prefix+LINE_CONTENT+"\n" )
        PRELINE_LAYER_AF = LINE_LAYER_AF
        PRELINE_LAYER_BE = LINE_LAYER_BE
        if info_cmd :
            PRE_CMD = 1
            info_cmd = None
        else :
            PRE_CMD = 0
            LAST_KW_LAYER_AF = LINE_LAYER_AF
            LAST_KW_LAYER_BE = LINE_LAYER_BE
        info = None
        return True

def filter_log (file_name,info_type) :
    """
    main function to check and record each line from input file
    """
    
    # if info_type was given, users only care about specific commands in it
    # or filter and write all commands defined in TYPE_SYNTAX_MAP to result file
    filter_dict = {} 
    if info_type == None :
       filter_dict = TYPE_SYNTAX_MAP 
    else :
        for each in info_type :
            type_name = each.upper()
            if type_name == "ALL" :
                filter_dict = TYPE_SYNTAX_MAP
                break
            if TYPE_SYNTAX_MAP.has_key(type_name) :
                filter_dict[type_name] = TYPE_SYNTAX_MAP[type_name]

            #print "type:%s" % type_name

    with open(file_name,'r') as file_handler:
        data = file_handler.readlines() 
    prefix = ''
    for domainname in DOMAINLIST :
        if domainname in file_name :
            prefix = domainname+'_'
            break 
    file_name = logATC+prefix+os.path.basename(file_name)
    file_handler_write = open(file_name+'.list','w') 
    for line in data :
        print_hierarchy_start_info(line,file_handler_write)
        print_keyword_name(line,file_handler_write)
        print_command(line,file_handler_write,filter_dict)

    file_handler_write.close()

def change_to_hierarchy(file_name,filter_type_list) :
    filter_log(file_name,filter_type_list)
    prefix = ''
    for domainname in DOMAINLIST :
        if domainname in file_name :
            prefix = domainname+'_'
            break
    file_name = logATC+prefix+os.path.basename(file_name)
    with open(file_name+'.list','r') as file_handler:
        data = file_handler.readlines() 
    file_handler_write = open(file_name+'.indent','w') 
    for line in data :
        print_hierarchy(line,file_handler_write)
    file_handler_write.close()
    retrievestep(file_name+'.indent')
    os.remove(file_name+'.list') 

def retrievestep(file_name) :
    global cFlag
    prefix='CASE>>'
    clist=[]
    dlist=[]
    cFlag= False
    tmp=''
    i=0
    
    with open(file_name,'r') as f1:
        data = f1.readlines() 
    for line in data :
        res= string.find(line,prefix)
        if res!=-1 :
            casename=line.strip().strip(prefix).strip()
            clist.append(casename)
            dlist.append('')
            cFlag= True
            allSteps=''
            i=i+1
        else :
            res1= string.find(line,'suite')
            res2= string.find(line,'SUITE')
            if res1!=-1 or res2!=-1 :
                cFlag= False
            if cFlag== True :
                res3= string.find(line,'<STC>stc::')
                res4= string.find(line,'<PCTA CMD>')
                if res3==-1 and res4==-1 :
                    line=line.replace("<CLI CMD>","CLI CMD: ").replace("<TL1 CMD>","TL1 CMD: ").replace("<SNMP>","SNMP CMD: ").replace("<SSH CMD>","SSH CMD: ").replace("<TND CMD>","TND CMD: ")     
                    oneStep=line.rstrip()
                    j=i-1
                    if dlist[j]=='' :
                        allSteps=allSteps+oneStep
                    else :
                        allSteps=allSteps+'</br>'+oneStep
                    dlist[j]=allSteps
    if 'SETUP' in file_name :
        SETUP1.extend(clist)
        SETUP2.extend(dlist)
    elif 'EQMT' in file_name :
        EQMT1.extend(clist)
        EQMT2.extend(dlist)
    elif 'MCAST' in file_name :
        MCAST1.extend(clist)
        MCAST2.extend(dlist)
    elif 'SUBMGMT' in file_name :
        SUBMGMT1.extend(clist)
        SUBMGMT2.extend(dlist)
    elif 'TRANSPORT' in file_name :
        TRANSPORT1.extend(clist)
        TRANSPORT2.extend(dlist)
    elif 'MGMT' in file_name :
        MGMT1.extend(clist)
        MGMT2.extend(dlist)
    elif 'L2FWD' in file_name :
        L2FWD1.extend(clist)
        L2FWD2.extend(dlist)
    elif 'QOS' in file_name :
        QOS1.extend(clist)
        QOS2.extend(dlist)
    elif 'L3FWD' in file_name :
        L3FWD1.extend(clist)
        L3FWD2.extend(dlist)
    else :     
        GENERAL1.extend(clist)
        GENERAL2.extend(dlist)
    os.remove(file_name)

def search_file(dir,file='output.xml',build=None) :
    fliename = file
    for subPath in os.listdir(dir) :
        path = os.path.join(dir,subPath)
        try :
            if os.path.isfile(path) :
                if os.path.basename(path) == file :
                    fList.append(path)
            elif os.path.isdir(path) :
                search_file(path)
        except Exception,err:
            pass


if __name__ == '__main__' :
    import sys, time
    import pandas as pd
    import os
    import csv
    import string 
    import pandas as pd

    print "Start at: " + str(time.ctime())  
    print ""
    bld = str(sys.argv[1])
    remotehost =  '135.252.245.46'
    remotedir = '/ftp/ATC/OTL/'
    logroot = '/data/logServer/log/'
    logATC = '/data/logServer/ATC/LOG_CMD/'
    
    if sys.argv[3:] :
        team = str(sys.argv[3])
    else :
        team = 'Fi-Hardening_and_CFT'
    search_dir = logroot + str(team) + '/'+str(sys.argv[1])
    print(search_dir)
    dir2 = logATC + str(sys.argv[1])
    #allstepdir = dir + '/' + str(sys.argv[1])
    allstepdir2 = dir2 
    
    if sys.argv[2:] :
        platform = str(sys.argv[2])
    else :
        platform = ''
    if sys.argv[3:] :
        filter_type_list = sys.argv[4:]
    else :
        filter_type_list = ['CLI','TL1','SNMP','SSH','TND']
    
    #Search the list of output.xml files
    print "Start to search output.xml files..."    
    fList = []
    search_file(search_dir, build=bld)


    DOMAINLIST=['SETUP','EQMT','MCAST','SUBMGMT','TRANSPORT','MGMT','L2FWD','QOS','L3FWD','GENERAL']
    for domain in DOMAINLIST :
        locals()[domain+'1'] = []
        locals()[domain+'2'] = []
    
    #Collect ATC steps for every batch
    print "Start to collect Steps for each batch..."     
    for x in fList :
        if str(sys.argv[2]) in x :
            change_to_hierarchy (x,filter_type_list)

    #Generate ATC step files for each Domain
    print "Start to merge each domain ATC cases and generate html files..."     
    for domain in DOMAINLIST :
        for i in range(len(locals()[domain+'2'])) :
            locals()[domain+'2'][i] = '<pre>' + locals()[domain+'2'][i] + '</pre>'            
        old_width = pd.get_option('display.max_colwidth')
        old_rows = pd.get_option('display.max_rows')   
        pd.set_option('display.max_colwidth',1000000)
        pd.set_option('display.max_rows',1000000)
        pd.set_option('display.width',None)
        pd.set_option('display.expand_frame_repr', True)
        data = pd.DataFrame({'ATC Case Name':locals()[domain+'1'],'Steps Of Procedure':locals()[domain+'2']})
        data = data.drop_duplicates()
        data['Steps Of Procedure']=data['Steps Of Procedure'].fillna('null')
        data1 = data[ ~ data['Steps Of Procedure'].isin(['null'])]
        if platform == '' :
            domaindir = allstepdir2 + '/' + domain
        else :
            domaindir = allstepdir2 + '/' + platform +'/' + domain
        if os.path.exists(domaindir) == False :
            os.makedirs(domaindir)
        domainfile = domaindir + '/' + domain +'.html'
        data1.to_html(domainfile,index=False,border=1,escape=False,justify='left')
        pd.set_option('display.max_colwidth', old_width)
        pd.set_option('display.max_rows', old_rows)
        if (os.path.getsize(domainfile) == 195 ) :
            os.remove(domainfile)     
            os.rmdir(domaindir) 
    #SCP upload to remote http server.
    #print "Start to upload html files to http server..."
    #os.system('scp -r "%s" "ftpupload@%s:%s"' % (allstepdir2, remotehost, remotedir) )
    #os.system('sudo rm -rf %s' % (allstepdir))
    print ""     
    if sys.argv[2:] :
        platform = str(sys.argv[2])
        print 'Check result on http://smartlab-service.int.net.nokia.com:9000/ATC/LOG_CMD/%s/%s' %(str(sys.argv[1]),str(sys.argv[2]))
    else :
        print 'Check result on http://smartlab-service.int.net.nokia.com:9000/ATC/LOG_CMD/%s' %(str(sys.argv[1]))
    
    print "End at  : " + str(time.ctime())

import xml.dom.minidom
import os
import re
import sys
from pyquery import PyQuery as pq
import collections
import warnings
import time
import json
from pymongo import MongoClient
import threading

warnings.filterwarnings("ignore")


class mongoOper:
    def __init__(self, resourcePath):
        dom = xml.dom.minidom.parse(resourcePath)
        root = dom.documentElement
        parentHTMLDir = root.getElementsByTagName('repo_home')

        mongo_ip = root.getElementsByTagName('mongo_ip')
        for node in mongo_ip:
            self.mongoIp = node.firstChild.data

        mongo_port = root.getElementsByTagName('mongo_port')
        for node in mongo_port:
            self.mongoPort = node.firstChild.data

        mongo_db = root.getElementsByTagName('mongo_dbName')
        for node in mongo_db:
            self.dbName = node.firstChild.data

        self.collectionSearch = 'robot'
        self.collectionCases = 'productCases'
        self.collectionLLK = 'LLK'
        self.collectionULK = 'ULKS'
        self.collectionTAG = 'TAG'

        self.searchCollectionKey = 'filename'
        self.searchCollectionValue = 'keywordList'

        self.caseCollectionKey = 'product'
        self.caseCollectionValue = 'caseList'

        self.tagCollectionKey = 'suitePath'
        self.tagCollectionValue = 'suiteTag'
        self.tagCollectionValueDocument = 'suiteDocument'
        self.tagCollectionCaseInfo='suiteCaseInfo'
        self.tagCollectionSuiteInits='suiteInits'
        

    def mongoDBConnection(self, ip, port, dbName, collectionName):
        conn = MongoClient(ip, port)
        db = conn.get_database(dbName)
        self.collection = db.get_collection(collectionName)

    def mongoDBWrite(self, collection, dic):
        self.collection.insert(dic, check_keys=False)

    def mongoDBRemove(self):
        self.collection.remove()

    def mongoDBQuery(self):
        res = self.collection.find()
        for item in res:
            print(item)


class codeToHTML:
    def __init__(self, resourcePath, genrateRobot, generatePython,generateYaml):
        self.resourcePath = resourcePath
        self.genrateRobot = genrateRobot
        self.generatePython = generatePython
        self.generateYaml=generateYaml

        self.keywordRegexp = ['*** Keywords ***', '*** Keyword ***', '*** keywords ***', '*** keyword ***']

        dom = xml.dom.minidom.parse(resourcePath)
        root = dom.documentElement
        parentDir = root.getElementsByTagName('repo_home')
        for node in parentDir:
            self.repo = node.firstChild.data

        parentHTMLDir = root.getElementsByTagName('atc_html')
        for node in parentHTMLDir:
            self.atcHTML = node.firstChild.data

        ip = root.getElementsByTagName('ssh_ip')
        for node in ip:
            self.ipAddr = node.firstChild.data

        port = root.getElementsByTagName('ssh_port')
        for node in port:
            self.portNum = node.firstChild.data

        html = root.getElementsByTagName('tomcat_html')
        for node in html:
            self.htmlDir = node.firstChild.data

        productList=[]
        productNode=root.getElementsByTagName('product')
        for node in productNode:
            productList = node.firstChild.data.split(',')

        self.htmlList = []
        self.initsWithoutCaseKwds=[]
        self.allRelated=[]
        self.suiteTxt = {}
        self.keywordTxt = []
        self.keywordPy = []
        self.LLK = []
        self.ULKS = []
        self.product_ULK = {}
        self.suiteResourceBlankDic = {}
        self.searchResDic = collections.OrderedDict()

        self.commonKeywordsList = []
        self.commonKeywordsDic = {'HLKS': [], 'LIBS': [], 'ULKS': []}
        
        productDic={}
        for item in productList:
            productDic[item]=[]

        self.productCaseFilesDic = productDic
        self.productCaseListDic = productDic

        self.ATSDic={}
        productList=productDic.keys()
        for productItem in productList:
            self.ATSDic[productItem]=self.repo + "/ATS/"+productItem
     
        HLKS = self.repo + "/HLKS"
        LIBS = self.repo + "/LIBS"
        ULKS = self.repo + "/ULKS"
        
        self.DirList=self.ATSDic.values()+[HLKS,LIBS,ULKS]
        self.TopDir =self.DirList

    def getAllTxtPyFiles(self):
        suiteInfoDir = {}
        for dir in self.DirList:
            commonDir = dir.replace(self.repo + '/', '')
            product = dir.replace(self.repo + '/ATS/', '')
            g = os.walk(dir)
            for path, d, filelist in g:
                for filename in filelist:
                    filePath = os.path.join(path, filename)
                    filePath = filePath.replace("\\", "/")
                    if filePath[-4:] == '.txt' or filePath[-6:] == '.robot' or filePath[-3:] == '.py':
                        with open(filePath, 'r') as pf:
                            lines = pf.readlines()
                            for line in lines:
                                mat_tc = re.search('^\*\*\* Test Cases \*\*\*', line)
                                mat_kwd = re.search('^\*\*\* Keywords \*\*\*', line)
                                mat_kwd2 = re.search('^\*\*\* Keyword \*\*\*', line)
                                mat_kwd4 = re.search('^\*\*\* keywords \*\*\*', line)
                                mat_kwd3 = re.search('^\*\*\* keyword \*\*\*', line)
                                mat_def = re.match("(\s*)def(\s+)(\w+)(\s*)\(.*", line)

                                if mat_tc or mat_kwd or mat_kwd2 or mat_kwd3 or mat_kwd4 or mat_def:
                                    self.searchResDic[filePath] = []
                                if mat_kwd or mat_kwd2 or mat_kwd3 or mat_kwd4 or mat_def:
                                    if commonDir == 'LIBS' or commonDir == 'HLKS':
                                        self.LLK.append(filePath)
                                    else:
                                        self.ULKS.append(filePath)
                                        res = re.match('(.*)/ULKS', filePath, re.M | re.I)
                                        if res:
                                            dirname = res.group(1)
                                            if not self.product_ULK.has_key(dirname):
                                                self.product_ULK[dirname] = []
                                                self.product_ULK[dirname].append(filePath)
                                            else:
                                                self.product_ULK[dirname].append(filePath)

                                if mat_tc:
                                    self.productCaseFilesDic[product].append(filePath)
                                    suiteInfoDir[filePath] = {}
                                    self.suiteTxt[filePath] = dir.replace(self.repo + '/ATS/', "").encode('utf-8')
                                    break
                                elif mat_kwd or mat_kwd2 or mat_kwd3 or mat_kwd4:
                                    self.keywordTxt.append(filePath)
                                    if commonDir == 'LIBS' or commonDir == 'HLKS' or commonDir == 'ULKS':
                                        self.commonKeywordsDic[commonDir].append(filePath)
                                    break
                                elif mat_def:
                                    self.keywordPy.append(filePath)
                                    if commonDir == 'LIBS' or commonDir == 'HLKS' or commonDir == 'ULKS':
                                        self.commonKeywordsDic[commonDir].append(filePath)
                                    break
                        
                        if not (mat_tc or mat_kwd or mat_kwd2 or mat_kwd3 or mat_kwd4 or mat_def):
                            self.initsWithoutCaseKwds.append(filePath)
                         
            self.suiteResourceBlankDic[product] = suiteInfoDir

    def getTagAndDirname(self):
        ForceTagsDic={}
        suiteTagsDic={}
        allInits=[]
        for dir in self.DirList:
            g = os.walk(dir)
        
            for path, d, filelist in g:
                for filename in filelist:   
                    filePath = os.path.join(path, filename)
                    filePath = filePath.replace("\\", "/")
                    
                    if filePath[-4:] == '.txt' or filePath[-6:] == '.robot':
                        mat_tc=False
                        caseFind=False
                        mat_ForceTag=False
                        settingsFind=False
                        DocumentFind=False
                        keywordFind=False
                        documentString=""
                 
                        filenameTemp=os.path.basename(filePath)
                        if filenameTemp=='__init__.txt' or filenameTemp=='__init__.robot':
                            allInits.append(filePath)
                        forceTagStart=False
                        settingTagLines=[]
                        with open(filePath, 'r') as pf:                   
                            lines = pf.readlines()
                            for line in lines:
                                if '*** Settings ***' in line or '*** Setting ***' in line:
                                    settingsFind = True
                                mat_ForceTag = re.search('^Force Tags', line)
                                if forceTagStart:
                                    if not line.startswith('...'):
                                        forceTagStart=False
                                    else:
                                        settingTagLines.append(line)
                                if settingsFind and mat_ForceTag:
                                    forceTagStart=True
                                    settingTagLines.append(line)

                                mat_tc = re.search('^\*\*\* Test Cases \*\*\*', line)
                                if mat_tc:
                                    caseFind=True
                                    keywordFind=False
                                    suiteTagsDic[filePath]={'tags':[],'document':documentString,'caseInfo':{},'inits':[]}
                                    settingsFind=False
            
                                mat_kwd = re.search('^\*\*\* Keywords \*\*\*', line)
                                mat_kwd2 = re.search('^\*\*\* Keyword \*\*\*', line)
                                mat_kwd3 = re.search('^\*\*\* keyword \*\*\*', line) 
                                mat_kwd4 = re.search('^\*\*\* keywords \*\*\*', line)  
                                if mat_kwd or mat_kwd2 or mat_kwd3 or mat_kwd4:
                                    keywordFind=True 
                                    caseFind=False      
                
                                if caseFind:
                                    line=line.rstrip("\n")                              
                                    caseMatch=re.match("^\w+(.*)", line)                               
                                    if caseMatch:
                                       casename=caseMatch.group(0)                              
                                       suiteTagsDic[filePath]['caseInfo'][casename]=[]
            
                                mat_tag = re.match("(\s+)\[Tags\](\s+)(\w*)(\s*)", line)
                                if caseFind and mat_tag:                             
                                   line=line.rstrip("\n")
                                   tagList = filter(lambda x: x, line.split(' '))[1:]          
                                   suiteTagsDic[filePath]['caseInfo'][casename]=tagList
            
                                if settingsFind:
                                    mat_Document = re.search('^Documentation ', line) 
                                    
                                    if mat_Document:
                                       DocumentFind=True                                      
                                       documentString+=line
                                       continue
            
                                if DocumentFind:
                                    mat_documentGoing=line.startswith('...')
                                    if mat_documentGoing:
                                        documentString+=line
                                    else:
                                        DocumentFind=False
                        if settingTagLines:
                            ForceTagsDic[filePath]=[]
                            for tagLine in settingTagLines:
                                ll=tagLine.rstrip("\n")
                                forceTagList=filter(lambda x: x, ll.split(' '))
                                for forcetag in forceTagList:
                                    excludeL=['Force Tags','...']
                                    if forcetag not in excludeL and forcetag not in ForceTagsDic[filePath]:
                                        ForceTagsDic[filePath].append(forcetag)
                            if len(ForceTagsDic[filePath])==0:
                                del ForceTagsDic[filePath]

        for suite in suiteTagsDic.keys():  
            for forceTagPath in ForceTagsDic.keys():
                dirname=os.path.dirname(forceTagPath)+'/'
                filename=os.path.basename(forceTagPath)
                      
                if (dirname in suite and filename=='__init__.txt') or (forceTagPath==suite):
                    suiteTagsDic[suite]['tags']+=ForceTagsDic[forceTagPath]
                    suiteCasesList=suiteTagsDic[suite]['caseInfo'].keys()
                             
                    for case in suiteCasesList:
                        suiteTagsDic[suite]['caseInfo'][case]+=ForceTagsDic[forceTagPath]
                   
            for initFile in allInits:
                dirname=os.path.dirname(initFile)+'/'
                if dirname in suite and (initFile not in suiteTagsDic[suite]['inits']):
                    suiteTagsDic[suite]['inits'].append(initFile)
                #print suiteTagsDic[suite]['inits'] 
                     
            
        for suite,suiteInfo in suiteTagsDic.items():
            ll = list(set(suiteInfo['tags']))
            suiteTagsDic[suite]['tags']=ll
        #print suiteTagsDic['/repo/atxuser/robot/ATS/P2P/A2A/01__EQMT/05__DFMEA_SFP_MALFUN_ALARM_P2P.txt']
                 
        return suiteTagsDic           
                                               

    """
     get the resource list
    """

    def getResources(self, pathList, resourceListRes):
        
        res = {}
        for path in pathList:
            tempList = []
            type = path.split('.')[1]
            try:
                if type == 'txt' or type == 'robot':
                    with open(path, 'r') as pf:
                        settingsFind = False
                        lines = pf.readlines()
                        for line in lines:
                            resourcePath = ""
                            if '*** Settings ***' in line or '*** Setting ***' in line:
                                settingsFind = True
                            elif '*** Test Cases ***' in line:
                                settingsFind = False
                                break
                            if settingsFind:
                                line = line.replace(" ", "").rstrip("\n")

                                if 'Resource' in line:
                                    resourcePath = line.replace("Resource", "")
                                elif 'Library' in line and line[-3:] == '.py':
                                    resourcePath = line.replace("Library", "")

                                resourceResult = []
                                if resourcePath != "":
                                    if '%{ROBOTREPO}' in resourcePath:
                                        resource = resourcePath.replace('%{ROBOTREPO}', self.repo)
                                        resourceResult.append(resource)
                                    elif resourcePath.startswith('%{'):
                                        pass
                                    elif '_${' in resourcePath:
                                        resource = os.path.dirname(path) + "/" + resourcePath
                                        resourcePath = os.path.abspath(resource).replace('\\', '/')
                                        (filepath, tempfilename) = os.path.split(resourcePath)
                                        (shotname, extension) = os.path.splitext(tempfilename)

                                        index1 = self.find_last(tempfilename, '_')
                                        resourceTemp = tempfilename[0:index1] + extension
                                        files = os.listdir(filepath)
                                        for file in files:
                                            index2 = self.find_last(file, '_')
                                            (shotname, extension) = os.path.splitext(file)
                                            fileTemp = file[0:index2] + extension
                                            if resourceTemp == fileTemp:
                                                resourceResult.append(filepath + '/' + file)
                                    else:
                                        resource = os.path.dirname(path) + "/" + resourcePath
                                        resource = os.path.abspath(resource).replace('\\', '/')

                                        resourceResult.append(resource)
                                    for resource in resourceResult:
                                        if resource not in tempList and (not resourcePath.startswith('#')):
                                            tag = 0
                                            for list in resourceListRes:
                                                if resource in list:
                                                    tag = 1
                                                    # print "tag==1"
                                            if tag == 0:
                                                if '\r' in resource:
                                                    resource = resource.replace("\r", "")
                                                if not os.path.exists(resource):
                                                    # print "not exitsts"
                                                    pass
                                                else:
                                                    tempList.append(resource)
            except IOError:
                pass

            res[path] = tempList
        return res

    def getAllResourceFiles(self, keywordfile):
        i = 0
        resourceListRes = []
        resourceListTemp = []
        resourceListTemp.append([keywordfile])
        resourceListRes.append({keywordfile: [keywordfile]})
        while (True):
            # print "while :",resourceListTemp[i]
            resourceList = self.getResources(resourceListTemp[i], resourceListTemp)
            tag = 0
            valueList = []
            for key, v in resourceList.items():
                valueList += v
                if len(v) > 0:
                    tag = 1
            if tag == 1:
                resourceListRes.append(resourceList)
                resourceListTemp.append(valueList)
                i += 1
            else:
                break
        return resourceListRes

    def getRelativePath(self, root, file):
        # root = "C://Borland//JBuilder2005//thirdparty"
        # file = "C://Documents and Settings//Administrator//My Documents//desktop_jpg//img_9_267_10.jpg"

        fileList = [file]
        rootList = []
        temp = os.path.dirname(file)

        while (True):

            if temp not in fileList:
                fileList.append(temp)
                temp = os.path.dirname(temp)
            else:
                break

        rootList.append(root);

        temp = os.path.dirname(root)
        while (True):
            if temp not in rootList:
                rootList.append(temp)
                temp = os.path.dirname(temp)
            else:
                break

        strTemp1 = ""

        for i in range(len(rootList)):
            fl1 = rootList[i]
            strTemp2 = ""
            for j in range(len(fileList)):
                fl2 = fileList[j]
                if (fl1 == fl2):
                    if (len(strTemp1) != 0):
                        index = len(strTemp1) - 1
                        strTemp1 = strTemp1[0:int(index)]

                    return (strTemp1 + strTemp2)

                strTemp2 = "/" + fl2.split('/')[-1] + strTemp2

            strTemp1 += "../"

        return None

    def orderDirList(self, DirList, root):
        # print "dir list is:",DirList
        resList = {}
        for file in DirList:
            num = 0
            relative = self.getRelativePath(root, file)
            for i in range(len(relative)):
                if relative[i] == '/':
                    num += 1
            resList[file] = num

        listSorted = sorted(resList.items(), lambda x, y: cmp(x[1], y[1]))
        resList = []
        for item in listSorted:
            resList.append(item[0])
        return resList

    def getKeywordsResources(self, keywordfile):
        resourceListRes = self.getAllResourceFiles(keywordfile)

        initTemp2 = self.getAllInitsResources(keywordfile)

        for initDic in initTemp2:
            resourceListRes.append(initDic)

        listTemp = []
        resNew = {}
        for resource in resourceListRes:
            for key, value in resource.items():
                if key not in listTemp:
                    listTemp.append(key)
                    resNew[key] = value
                else:
                    for item in value:
                        resNew[key].append(item)

        orderList = self.orderDirList(listTemp, keywordfile)

        resourceListRes2 = []

        for resource in orderList:
            resourceListRes2.append(resNew[resource])

        tt = []
        for item in resourceListRes2:
            tt += item

        ulkFiles = []
        for ulkdir, filelist in self.product_ULK.items():
            if ulkdir in keywordfile and (ulkdir != self.repo):
                ulkFiles += filelist
        resourceListRes2.append(ulkFiles)

        res = []
        for dir, keywordfilesList in self.commonKeywordsDic.items():
            for commonkeywordfile in keywordfilesList:
                if commonkeywordfile not in tt:
                    res.append(commonkeywordfile)
        resourceListRes2.append(res)

        resList = []
        for item in resourceListRes2:
            resList += item
        resList = sorted(set(resList), key=resList.index)
        return resList

    def getCaseAllResouces(self, caseResourceDic):
        productCaseResourceList = {}
        for product, info in caseResourceDic.items():
            productCaseResourceList[product] = {}
            for path in info.keys():
                resourceList = self.getKeywordsResources(path)
                productCaseResourceList[product][path] = resourceList
        return productCaseResourceList

    def getKeywordAllResources(self, keywordfile):
        keywordResourceList = {}
        resourceList = self.getKeywordsResources(keywordfile)
        keywordResourceList[keywordfile] = resourceList
        return keywordResourceList

    def getKeywordAllResourcesForPy(self, keywordfile):
        keywordResourceList = {}
        currentDir = os.path.dirname(keywordfile)
        moduleList = []

        with open(keywordfile, 'r') as pf:
            lines = pf.readlines()
            for line in lines:
                res = re.match('^(\s*)import(\s+)(.*)$', line, re.M | re.I)
                res2 = re.match('^(\s*)from(\s+)(.*)(\s+)import(\s+)(.*)$', line, re.M | re.I)
                # res3 = re.match('(\s*)(\w+)(\s*)=(\s*)(.*)', line, re.M | re.I)
                res4 = re.match('^(\s*)import(\s+)(.*)(,(\s*)(.*))*', line, re.M | re.I)
                if res:
                    if res.group(2) != ' ':
                        module = res.group(2)
                    else:
                        module = res.group(3)
                    moduleList.append(module.replace(' ', '').replace('\n', '').replace('\r', ''))
                elif res4:
                    moduleList += line.replace(' ', '').replace('\n', '').replace('\r', '').replace('import', '').split(
                        ',')
                elif res2:
                    if res2.group(2) != ' ':
                        module = res2.group(2)
                        func = res2.group(5)
                    else:
                        module = res2.group(3)
                        func = res2.group(6)
                    moduleList.append(module.replace(' ', '').replace('\n', '').replace('\r', ''))

        moduleNew = []
        for module in moduleList:
            if ',' in module:
                moduleNew += module.split(',')
            else:
                moduleNew.append(module)
        moduleList = moduleNew

        if 'ATS' in keywordfile:
            resourceList = []

            pyDeepDic = self.getPyFilesList(keywordfile)
            for ff, filepath in pyDeepDic.items():
                resDic = {}
                resDic[ff] = filepath
                resourceList.append(resDic)
            initTemp2 = self.getAllInitsResources(keywordfile)
            for item in initTemp2:
                for initfile, initresourceList in item.items():
                    initList = []
                    for initresource in initresourceList:
                        file_name = os.path.split(initresource)[-1]
                        if file_name.split('.')[-1] == 'py' and (file_name.split('.')[0] in moduleList):
                            initList.append(initresource)
                    if len(initList) > 0:
                        resourceList.append({initfile: initList})

            listTemp = []
            resNew = {}
            for resource in resourceList:
                for key, value in resource.items():
                    if key not in listTemp:
                        listTemp.append(key)
                        resNew[key] = value
            orderList = self.orderDirList(listTemp, keywordfile)
            resourceListRes2 = []

            for resource in orderList:
                resourceListRes2.append(resNew[resource])

            tt = []
            for item in resourceListRes2:
                tt += item

            res = []
            for dir, keywordfilesList in self.commonKeywordsDic.items():
                for commonkeywordfile in keywordfilesList:
                    if commonkeywordfile not in tt:
                        file_name = os.path.split(commonkeywordfile)[-1]
                        if file_name.split('.')[-1] == 'py' and (commonkeywordfile not in resourceList) and (
                                file_name.split('.')[0] in moduleList):
                            res.append(commonkeywordfile)

            resourceListRes2.append(res)

            resList = [keywordfile]
            for item in resourceListRes2:
                resList += item

            resList = sorted(set(resList), key=resList.index)
            keywordResourceList[keywordfile] = resList
        else:
            res = [keywordfile]
            for dir, keywordfilesList in self.commonKeywordsDic.items():
                for commonkeywordfile in keywordfilesList:
                    file_name = os.path.split(commonkeywordfile)[-1]
                    if file_name.split('.')[-1] == 'py' and (file_name.split('.')[0] in moduleList):
                        res.append(commonkeywordfile)
            keywordResourceList[keywordfile] = res
        return keywordResourceList

    def getResourceMap(self, resouceList):
        dic = collections.OrderedDict()
        listTemp = []
        for list in resouceList:
            listTemp += list

        for resource in listTemp:

            (filepath, tempfilename) = os.path.split(resource);
            (shotname, extension) = os.path.splitext(tempfilename);
            htmlName = resource.replace(self.repo + "/", '')
            htmlName = htmlName.replace('/', '%')

            htmlName = "http://" + self.ipAddr + ":" + self.portNum + "/" + self.htmlDir + "/" + htmlName + ".html"
            kwdList = []
            if '\r' in resource:
                resource = resource.replace("\r", "")
            try:
                kwdList = self.getKeyword(resource, extension)

            except IOError:
                pass

            dic[htmlName] = kwdList
        return dic

    def getKeyword(self, ff, suffix):
        kwdList = []
        with open(ff, 'r') as pf:
            if '.txt' in suffix or '.robot' in suffix:
                start_keyword = False
                lines = pf.readlines()
                for line in lines:
                    mat_tc = re.search('^\*\*\* Keywords \*\*\*', line)
                    mat_tc2 = re.search('^\*\*\* Keyword \*\*\*', line)
                    mat_tc3 = re.search('^\*\*\* keywords \*\*\*', line)
                    mat_tc4 = re.search('^\*\*\* keyword \*\*\*', line)

                    if mat_tc or mat_tc2 or mat_tc3 or mat_tc4:
                        start_keyword = True
                        continue
                    else:
                        if start_keyword and re.search('^\*\*\* ', line):
                            start_keyword = False
                            break
                    if start_keyword:
                        line = line.replace("\xc2\xa0", " ")
                        matched = re.search('^(\w.*)', line)
                        if matched:
                            target = matched.group(1).lower()
                            keywordName = target.strip()
                            if '\r' in keywordName:
                                keywordName = keywordName.rstrip('\r')
                            kwdList.append(keywordName)
            elif '.py' in suffix:
                lines = pf.readlines()
                for line in lines:
                    line = line.replace("\xc2\xa0", " ")
                    result = re.match("(\s*)def(\s+)(\w+)(\s*)\(.*", line)
                    if result:
                        keywordName = result.group(3).strip().lower()
                        if '\r' in keywordName:
                            keywordName = keywordName.rstrip('\r')
                        kwdList.append(keywordName)

        return kwdList

    def getCases(self, ff):
        caseList = []
        with open(ff, 'r') as pf:
            start_case = False
            lines = pf.readlines()
            for line in lines:
                mat_tc = re.search('^\*\*\* Test Cases \*\*\*', line)
                if mat_tc:
                    start_case = True
                    continue
                else:
                    if start_case and re.search('^\*\*\* ', line):
                        start_case = False
                        break
                if start_case:
                    line = line.replace("\xc2\xa0", " ")
                    matched = re.search('^(\w.*)', line)
                    if matched:
                        target = matched.group(1)
                        caseName = target.strip()
                        if '\r' in caseName:
                            caseName = caseName.rstrip('\r')
                        if '\n' in caseName:
                            caseName = caseName.rstrip('\n')
                        caseList.append(caseName.lower())
        return caseList

    def getKeywordResourcesMap(self, dicResource):
        sourceFilePath = dicResource.keys()[0]
        dic = {}
        res = self.getResourceMap(dicResource.values())
        dic[sourceFilePath] = res
        return dic

    def getCaseKeywordsResourceMap(self, productCaseResourceList):
        dic = collections.OrderedDict()
        for product, suiteResourceInfo in productCaseResourceList.items():
            dic[product] = collections.OrderedDict()
            for suitePath in suiteResourceInfo.keys():
                dicResourceKeywords = self.getResourceMap(suiteResourceInfo[suitePath])
                dic[product][suitePath] = dicResourceKeywords
        return dic

    def getInit(self, path):
        files = os.listdir(path)
        if '__init__.txt' in files:
            return '__init__.txt'
        elif '__init__.robot' in files:
            return '__init__.robot'
        else:
            return False

    def getPy(self, filepath):
        pyList = []
        files = os.listdir(filepath)
        for file in files:
            if '.' in file and file.split('.')[1] == 'py':
                pyList.append(file)
        return pyList

    def getPyFilesList(self, filepath):
        (path, tempfilename) = os.path.split(filepath)
        pyListTemp = [path]
        pyListResDic = {}
        i = 0
        while (True):
            res = self.getPy(pyListTemp[i])
            if res:
                for file in res:
                    if 'variable_' not in file:
                        pyListResDic[pyListTemp[i] + '/' + file] = [pyListTemp[i] + '/' + file]
                pyListTemp.append(os.path.abspath(pyListTemp[i] + '/../').replace("\\", '/'))
                i += 1

            elif pyListTemp[i] in self.TopDir or pyListTemp[i]==self.repo+'/ATS':
                break
            else:
                pyListTemp.append(os.path.abspath(pyListTemp[i] + '/../').replace("\\", '/'))
                i += 1
        return pyListResDic

    def getInitFileList(self, filepath):
        (path, tempfilename) = os.path.split(filepath)
        initListTemp = [path]
        initListRes = []
        i = 0
        while (True):
            res = self.getInit(initListTemp[i])
            if res:
                initListRes.append(initListTemp[i] + '/' + res)
                if initListTemp[i] in self.TopDir or initListTemp[i]==self.repo+'/ATS':
                    break
                else:
                    initListTemp.append(os.path.abspath(initListTemp[i] + '/../').replace("\\", '/'))
                    i += 1
            else:
                break
        return initListRes

    def getAllInitsResources(self, keywordfile):
        initTemp = []
        initList = self.getInitFileList(keywordfile)
        for initfile in initList:
            resourceInitListList = self.getAllResourceFiles(initfile)
            for resourceInitList in resourceInitListList:
                initTemp.append(resourceInitList)
        return initTemp

    ############################################################################
    def find_last(self, string, str):
        last_position = -1
        while True:
            position = string.find(str, last_position + 1)
            if position == -1:
                return last_position
            last_position = position

    def getAllKeywords(self, dic):
        keywordList = dic.values()
        resList = []
        for list in keywordList:
            resList += list
        return resList

    def addLink(self, node, keywordname, linkaddr):
        if not (node.has_class('gu') or node.prev().text() == 'def'):
            text = node.text()
            node.removeAttr('class')
            node.text('')
            linkaddr = linkaddr.replace("%", "%25")
            node.append(
                '<a class="nf" href="' + linkaddr + '#' + keywordname + '">' + text + '</a>')

    def getResourceWhether(self, keywordResourceDic, node):
        nodeText1 = node.text().encode('utf-8').replace("\xc2\xa0", " ").lower()
        matchObj = re.match('^([\w+\s]+\w)$', nodeText1)
        nodeText2 = ""
        if matchObj:
            nodeText2 = nodeText1.replace(" ", "_")

        for resourceHtml, keywordsList in keywordResourceDic.items():

            if (nodeText1 in keywordsList):
                self.addLink(node, nodeText1, resourceHtml)
                return [nodeText1, resourceHtml]

            elif (nodeText1 not in keywordsList) and matchObj:
                if nodeText2 in keywordsList:
                    self.addLink(node, nodeText2, resourceHtml)
                    return [nodeText2, resourceHtml]

        return None

    def formatHTMLKeywords(self, dicKeywords, htmlfile, type):
        print("html:", htmlfile)
        print("start time is:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))

        startKeywords = False
        temp = htmlfile.replace('.html', '')
        index = self.find_last(temp, '.')
        type = temp[index + 1:]

        tempDic = {}
        d = pq(filename=htmlfile)
        size = d('div').find('span').size()
        for i in range(size):
            node = d('div').find('span').eq(i)
            nodeText1 = node.text().encode('utf-8').replace("\xc2\xa0", " ").lower()

            matchObj = re.match('^([\w+\s]+\w)$', nodeText1)
            nodeText2 = ""
            if matchObj:
                nodeText2 = nodeText1.replace(" ", "_")

            if type == 'txt' or type == 'robot':
                if node.text() in self.keywordRegexp:
                    startKeywords = True
                if startKeywords == True and node.hasClass('gu'):
                    node.attr('id', nodeText1)
                if tempDic.has_key(nodeText1) or tempDic.has_key(nodeText2):
                    if tempDic.has_key(nodeText1):
                        self.addLink(node, nodeText1, tempDic[nodeText1])
                    else:
                        self.addLink(node, nodeText2, tempDic[nodeText2])
                else:
                    res = self.getResourceWhether(dicKeywords, node)

                    if res != None:
                        tempDic[res[0]] = res[1]
            elif type == 'py':
                # nodeTextOriginal=node.text().encode('utf-8').replace("\xc2\xa0", " ")

                if node.has_class("nn") or node.has_class("nc") or node.has_class("nf"):
                    node.css('text-decoration', 'none')
                    if node.has_class("nf"):
                        node.attr('id', nodeText1)

                elif tempDic.has_key(nodeText1) or tempDic.has_key(nodeText2):
                    if tempDic.has_key(nodeText1):
                        self.addLink(node, nodeText1, tempDic[nodeText1])
                    else:
                        self.addLink(node, nodeText2, tempDic[nodeText2])
                else:
                    res = self.getResourceWhether(dicKeywords, node)
                    if res != None:
                        tempDic[res[0]] = res[1]

        d('head').append("<script type=\"text/javascript\" src='js/jquery-1.12.4.js'></script>\n<script type=\"text/javascript\" src='js/script.js'></script>")
        f = file(htmlfile, 'w')
        f.write(d.outerHtml().encode('utf-8'))
        f.close()

        print("end time is:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))

    def formatHTML(self, htmlfile, keywordResourceDic):
        print("html:", htmlfile)
        print("start time is:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        temp = htmlfile.replace('.html', '')
        d = pq(filename=htmlfile)
        tempDic = {}

        nodeCaseKeyword = d('span').filter('.gu')
        size2 = nodeCaseKeyword.size()
        for i in range(size2):
            node = nodeCaseKeyword.eq(i)
            name = node.text().encode('utf-8').replace("\xc2\xa0", " ")
            node.attr('id', name.lower())

        obj1 = d('span').filter('.nf')
        obj2 = d('span').filter('.s')
        obj3 = d('span').filter('ge')
        objList = [obj1, obj2, obj3]
        for objItem in objList:
            for i in range(objItem.size()):
                node = objItem.eq(i)
                nodeText1 = node.text().encode('utf-8').replace("\xc2\xa0", " ").lower()

                matchObj = re.match('^([\w+\s]+\w)$', nodeText1)
                nodeText2 = ""
                if matchObj:
                    nodeText2 = nodeText1.replace(" ", "_")
                if tempDic.has_key(nodeText1) or tempDic.has_key(nodeText2):
                    if tempDic.has_key(nodeText1):
                        self.addLink(node, nodeText1, tempDic[nodeText1])
                    else:
                        self.addLink(node, nodeText2, tempDic[nodeText2])
                else:
                    res = self.getResourceWhether(keywordResourceDic, node)

                    if res != None:
                        tempDic[res[0]] = res[1]

        d('head').append("<script type=\"text/javascript\" src='js/jquery-1.12.4.js'></script>\n<script type=\"text/javascript\" src='js/script.js'></script>")
        f = file(htmlfile, 'w')
        f.write(d.outerHtml().encode('utf-8'))
        f.close()

        print("end time is:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))

    def htmlAddLink(self, path, KeywordHTMLName, dic, type):
        self.allRelated.append(path)
        filename = self.atcHTML + "/" + KeywordHTMLName
        if filename not in self.htmlList:
            if type == 'robot':
                command = "python " + self.genrateRobot + " " + '\'' + path + '\'' + " " + '\'' + self.atcHTML + "/" + KeywordHTMLName + '\'' + " native"
                os.system(command)
                self.htmlList.append(filename)
                self.formatHTML(filename, dic)
            else:
                command = "python " + self.generatePython + " " + '\'' + path + '\'' + " " + '\'' + self.atcHTML + "/" + KeywordHTMLName + '\'' + " native"
                os.system(command)
                self.htmlList.append(filename)
                self.formatHTMLKeywords(dic, filename, type)

    def deleteAllHtml(self):
        os.system("find %s -name '*.html' -exec rm -f {} \;" % self.atcHTML)

    def callAddLinkCase(self):
        finishNum = 0
        for pathDir, product in self.suiteTxt.items():
            KeywordHTMLName = pathDir.replace(self.repo + "/", "").replace("/", "%") + '.html'
            resourceList = self.getKeywordAllResources(pathDir)
            keywordResourcesDic = self.getKeywordResourcesMap(resourceList)
            dicKeywords = keywordResourcesDic[pathDir]
            self.htmlAddLink(pathDir, KeywordHTMLName, dicKeywords, 'robot')
            finishNum += 1
            print("case txt  executing ....   total num is:%s , finish num is:%s, remained num is:%s" % (
                len(self.suiteTxt.keys()), finishNum, len(self.suiteTxt.keys()) - finishNum))

    def callAddLinkKeywordTxt(self):
        finishNum = 0
        for pathDir in self.keywordTxt:
            KeywordHTMLName = pathDir.replace(self.repo + "/", "").replace("/", "%") + '.html'
            keywordResourceList = self.getKeywordAllResources(pathDir)

            keywordResourcesDic = self.getKeywordResourcesMap(keywordResourceList)
            dicKeywords = keywordResourcesDic[pathDir]
            self.htmlAddLink(pathDir, KeywordHTMLName, dicKeywords, 'robot')
            finishNum += 1
            print("keyword txt executing.....  total num is:%s , finish num is:%s, remained num is:%s" % (
                len(self.keywordTxt), finishNum, len(self.keywordTxt) - finishNum))

    def callAddLinkKeywordPy(self):

        l2 = list(set(self.keywordPy))
        l2.sort(key=self.keywordPy.index)
        keywordPytList = l2

        finishNum = 0
        for pathDir in keywordPytList:
            KeywordHTMLName = pathDir.replace(self.repo + "/", "").replace("/", "%") + '.html'
            keywordResourceListPy = self.getKeywordAllResourcesForPy(pathDir)
            keywordResourcesDic = self.getKeywordResourcesMap(keywordResourceListPy)
            dicKeywords = keywordResourcesDic[pathDir]
            self.htmlAddLink(pathDir, KeywordHTMLName, dicKeywords, 'py')
            finishNum += 1
            print("py file executing..... total num is:%s , finish num is:%s, remained num is:%s" % (
            len(keywordPytList), finishNum, len(keywordPytList) - finishNum))
     
    def callAddLinkInitWithoutCaseKwd(self):
       
        for filePath in self.initsWithoutCaseKwds:
            self.allRelated.append(filePath)
            KeywordHTMLName = filePath.replace(self.repo + "/", "").replace("/", "%") + '.html'
            filename = self.atcHTML + "/" + KeywordHTMLName
                
            if filename not in self.htmlList:
                if filePath[-4:] == '.txt' or filePath[-6:] == '.robot': 
                    command = "python " + self.genrateRobot + " " + '\'' + filePath + '\'' + " " + '\'' + self.atcHTML + "/" + KeywordHTMLName + '\'' + " native"
                if filePath[-3:] == '.py':
                    command = "python " + self.generatePython + " " + '\'' + filePath + '\'' + " " + '\'' + self.atcHTML + "/" + KeywordHTMLName + '\'' + " native"                   
                os.system(command)
                self.htmlList.append(filename)
                
    def callAddLinkOthers(self):
        allfiles=[]
        for currentDir, subDirs, filesList in os.walk(self.repo):
            if '/.' in currentDir:
                continue
            else:
                for fileItem in filesList:
                    (shortname,extension) = os.path.splitext(fileItem)
                    if extension not in ['.txt','.py','.yaml','.csv','.robot','.json','.resouce']:
                        continue
                    else:
                        allfiles.append(currentDir+'/'+fileItem)
                            
        retDiff = [ i for i in allfiles if i not in self.allRelated ]
        for filePath in retDiff:
            KeywordHTMLName = filePath.replace(self.repo + "/", "").replace("/", "%") + '.html'
            htmlUrl=self.atcHTML + "/" + KeywordHTMLName
            if htmlUrl not in self.htmlList:
                (shortname,extension) = os.path.splitext(filePath)
                if extension=='.txt' or extension=='.robot':
                    command = "python " + self.genrateRobot + " " + '\'' + filePath + '\'' + " " + '\'' + htmlUrl + '\'' + " native"
                elif extension=='.py':
                    command = "python " + self.generatePython + " " + '\'' + filePath + '\'' + " " + '\'' + htmlUrl + '\'' + " native"                   
                else:
                    command = "python " + self.generateYaml + " " + '\'' + filePath + '\'' + " " + '\'' + htmlUrl + '\'' + " native"
                os.system(command)
                self.htmlList.append(htmlUrl)

if __name__ == "__main__":
    #folddir = '/root/chenlin/'
    folddir = '/root/wwang046/robotKW/robot/periodicTask/'
    resourcePath = folddir + 'resource.xml'
    genrateRobot = folddir + 'generate.py'
    generatePython = folddir + 'generate_python.py'
    generateYaml= folddir + 'generate_yaml.py'
   
    obj = codeToHTML(resourcePath, genrateRobot, generatePython,generateYaml)
    obj2 = mongoOper(resourcePath)
    
    ################suite and case info#################################
    caseTagsDic=obj.getTagAndDirname()
 
    obj2.mongoDBConnection(obj2.mongoIp, int(obj2.mongoPort), obj2.dbName,obj2.collectionTAG)
    obj2.mongoDBRemove()
    for casePath, caseInfo in caseTagsDic.items():
        resMap = {}
        resMap[obj2.tagCollectionKey] = casePath
        resMap[obj2.tagCollectionValue] = caseInfo['tags']
        resMap[obj2.tagCollectionValueDocument] = caseInfo['document']
        resMap[obj2.tagCollectionCaseInfo]=caseInfo['caseInfo']
        resMap[obj2.tagCollectionSuiteInits]=caseInfo['inits']
        obj2.mongoDBWrite(obj2.collectionTAG, resMap) 

    #################belowing is used for searching ############################################
    obj.getAllTxtPyFiles()
    obj2.mongoDBConnection(obj2.mongoIp, int(obj2.mongoPort), obj2.dbName, obj2.collectionSearch)
    obj2.mongoDBRemove()

    filesDic = obj.searchResDic
    for ff in filesDic.keys():
        suffix = os.path.splitext(ff)[1]
        keywordList = obj.getKeyword(ff, suffix)
        caseList = obj.getCases(ff)
        resList = caseList + keywordList
        filesDic[ff] = resList
    for filename, keywords in filesDic.items():
        resMap = {}
        resMap[obj2.searchCollectionKey] = filename
        resMap[obj2.searchCollectionValue] = keywords

        obj2.mongoDBWrite(obj2.collectionSearch, resMap)


    ###################llk and ulk info#######################################
    obj2.mongoDBConnection(obj2.mongoIp, int(obj2.mongoPort), obj2.dbName, obj2.collectionLLK)
    obj2.mongoDBRemove()

    for ff in obj.LLK:
        suffix = os.path.splitext(ff)[1]
        kwdList = obj.getKeyword(ff, suffix)
        llkDic = {'filename': ff, 'kwdList': kwdList}
        obj2.mongoDBWrite(obj2.collectionLLK, llkDic)


    obj2.mongoDBConnection(obj2.mongoIp, int(obj2.mongoPort), obj2.dbName, obj2.collectionULK)
    obj2.mongoDBRemove()

    for ff in obj.ULKS:
        suffix = os.path.splitext(ff)[1]
        kwdList = obj.getKeyword(ff, suffix)
        ulkDic = {'filename': ff, 'kwdList': kwdList}
        obj2.mongoDBWrite(obj2.collectionULK, ulkDic)

    ####################converts to html###############################################
    
    obj.callAddLinkInitWithoutCaseKwd()
    obj.callAddLinkOthers()
      
    t1 = threading.Thread(target=obj.callAddLinkCase)
    t2 = threading.Thread(target=obj.callAddLinkKeywordTxt)
    t3 = threading.Thread(target=obj.callAddLinkKeywordPy)
    t1.start()
    t2.start()
    t3.start()

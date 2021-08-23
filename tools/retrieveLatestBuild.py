from pyquery import PyQuery as pq
import requests
import ftplib
import paramiko
from bs4 import BeautifulSoup
import re
import pysftp
import json

def ftpCheckFileExists(host,filePath,usr,pwd,fileList):
    ftp = ftplib.FTP(host,usr,pwd)
    try:
        ftp.cwd(filePath)
        fL = ftp.nlst()
        if set(fileList).issubset(fL):
            return True
    except Exception as e:
        print('Error :%s' % e)
    return False

def sftpCheckFileExists(host,username,password,pathList,port=22):
    t = paramiko.Transport((host,port))
    t.connect(username=username, password=password)
    sftp = paramiko.SFTPClient.from_transport(t)
    for path in pathList:
        try:
            sftp.stat(path)
            print('Path:%s exists' % path)
        except IOError as e:
            print('Path:%s not exists' % path)
            return False
    return True

def httpCheckFileExists(url,checkTarget):
    page = requests.get(url).text 
    soup = BeautifulSoup(page, 'html.parser')
    resList=[node.get('href').replace('/','') for node in soup.find_all('a')]
    if checkTarget in resList:
        return True
    else:
        return False

def getAvailableBuild(bServerL,release,buildID,RELEASE_MAP,hostFlag,productType,load='load'):
        print('--getAvailableBuild')
        print('release is:%s'%release)
        print('buildID is:%s'%buildID)
        print('RELEASE_MAP is:%s'%RELEASE_MAP)
        print('hostFlag is:%s'%hostFlag)
        LSRBuildID=''
        LSR=''
        try:
            LSR=RELEASE_MAP.get(release,'')
            if LSR:
                LSRBuildID=LSR.replace('.','')+'.'+buildID.split('.')[-1]
        except Exception as e:
            print(str(e))
        HostOrTarget='host' if hostFlag else 'target'
        exitPM=False
        regexpMoswa='^\d{2}\.\d{2}$'
        moswaRes=re.findall(regexpMoswa,release)
        if moswaRes:
            checkType=1
        regexpLegcyRes='^[2-9]\.\d\.0[1-6]|[2-9]\.\d$'
        legcyRes=re.findall(regexpLegcyRes,release)
        if legcyRes:
            releaseNum=release.replace('.','')
            releaseNum2=buildID.split('_')[-1].split('.')[0]
            if releaseNum!=releaseNum2:
                checkType=2
                LSRBuildID=release.replace('.','')+'.'+buildID.split('.')[-1]
            else:
                checkType=3
        print('LSRBuildID is:%s'%LSRBuildID)
        print("bServerL:%s" % bServerL)
        if HostOrTarget.lower()=='target':
            if 'pack' in buildID:
                buildR=buildID.split('_')[-1]
                if LSR:
                    rr=LSR.replace('.','')+'.'+buildID.split('.')[-1]
                    packagemeDirectoryParent=bServerL[2]+'/pack_'+rr
                    url='http://'+bServerL[1]+'/'+'pack_'+rr
                else:
                    packagemeDirectoryParent=bServerL[2]+'/'+buildID
                    url='http://'+bServerL[1]+'/'+buildID
            else:
                buildR=buildID
                packagemeDirectoryParent=bServerL[2]
                url='http://'+bServerL[1]
                
            checkPathSD=packagemeDirectoryParent+'/'
            buildFileName='SD_'+buildR+'.tar'
            buildFileName2='lightspan_'+buildR+'.tar'
            buildFileName3='lightspan-omci_'+buildR+'.tar'
            print('checkType is:%s'%checkType)
            print('productType is:%s'%productType)
            if checkType==1:
                buildFileList=[buildFileName2]
            elif checkType==2:
                legcyBuildID=release.replace('.','')+'.'+buildID.split('.')[-1]
                buildFileList=['SD_'+legcyBuildID+'.tar']
            elif checkType==3:
                if productType in ['NCDPU','SDFX','SDOLT']:
                    buildFileList=[buildFileName2]
                elif productType in ['NBN-4F']:
                    buildFileList=[buildFileName3]
                else:
                    buildFileList=[buildFileName]
            packagemeDirectory='packageme_'+buildR
            if not LSRBuildID:
                checkPathPackagemeList=[packagemeDirectory]
            else:
                packagemeDirectory2='packageme_'+LSRBuildID
                checkPathPackagemeList=[packagemeDirectory,packagemeDirectory2]
            print('checkPathPackagemeList is:%s'%checkPathPackagemeList)
            print('packagemeDirectoryParent is:%s'%packagemeDirectoryParent)
            #print('buildFileList is:%s'%buildFileList)
            exitPML=[]
            tarExitInPackageDir=''
            for packDirecItem in checkPathPackagemeList:
                if bServerL[0].lower() == 'ftp':
                    exitPMDir=ftpCheckFileExists(bServerL[1],packagemeDirectoryParent,bServerL[3],bServerL[4],[packDirecItem])
                elif bServerL[0].lower() == 'sftp':
                    pckDir=packagemeDirectoryParent+'/'+packDirecItem
                    exitPMDir=sftpCheckFileExists(bServerL[1],bServerL[3],bServerL[4],[pckDir])
                elif bServerL[0].lower() == 'http':
                    exitPMDir=httpCheckFileExists(url,packDirecItem)
                print('packageme %s exist:%s'%(packDirecItem,exitPMDir))
                if exitPMDir:
                    url+='/'+packDirecItem
                    for buildFileItem in buildFileList:
                        print('buildFileItem is:%s'%buildFileItem)
                        packDir=packagemeDirectoryParent+'/'+packDirecItem
                        if bServerL[0].lower() == 'ftp':
                            print('packDir is:%s'%packDir)
                            exitPMI=ftpCheckFileExists(bServerL[1],packDir,bServerL[3],bServerL[4],[buildFileItem])
                        elif bServerL[0].lower() == 'sftp':
                            pathList=[packDir+'/'+buildFileItem]
                            print('pathList is:%s'%pathList)
                            exitPMI=sftpCheckFileExists(bServerL[1],bServerL[3],bServerL[4],pathList)
                        elif bServerL[0].lower() == 'http':
                            print('url is:%s'%url)
                            exitPMI=httpCheckFileExists(url,buildFileItem)
                        print('tarExist is:%s'%exitPMI)
                        exitPML.append(exitPMI)
                        if exitPMI:
                            tarExitInPackageDir=packDirecItem
            exitPM=any(exitPML)
            print('tar exist in packageme directory:%s'%exitPM)
            if not exitPM:
                for buildFileItem in buildFileList:
                    print('buildFileItem is:%s'%buildFileItem)
                    if bServerL[0].lower() == 'ftp':
                        print('checkPathSD is:%s'%checkPathSD)
                        tarExistI=ftpCheckFileExists(bServerL[1],checkPathSD,bServerL[3],bServerL[4],[buildFileItem])
                    elif bServerL[0].lower() == 'sftp':
                        pathList=[checkPathSD+buildFileItem]
                        print('pathList is:%s'%pathList)
                        tarExistI=sftpCheckFileExists(bServerL[1],bServerL[3],bServerL[4],pathList)
                    elif bServerL[0].lower() == 'http':
                        print('url is:%s'%url)
                        tarExistI=httpCheckFileExists(url,buildFileItem)
                    print('tarExist is:%s'%tarExistI)
        if HostOrTarget == 'host':
            pass
            #Board = data['Board']
            #if bServerL[0].lower() == 'ftp':
            #    bServerL[2]=bServerL[2]+r'/' + Board + '/' + user + '/' + buildID
        elif re.search('pack',buildID):
            if exitPM:
                bServerL[2]=packagemeDirectoryParent+'/'+tarExitInPackageDir
            else:
                bServerL[2]=packagemeDirectoryParent
        elif load=='load':
            if exitPM:
                bServerL[2]=bServerL[2]+'/'+tarExitInPackageDir
        print('server path is:%s'%bServerL[2])
        BuildServer=':'.join(bServerL)
        return BuildServer

def MatchedBuilds(requestUrl):
    r = requests.get(requestUrl, stream=True)
    contentHtml=r.content
    d = pq(contentHtml)
   
    aList=d('a')
    fileList=[]
    for nodeA in aList:
        fileName=nodeA.text
        if fileName.endswith('/'):
            fileName=fileName.rstrip('/')
        fileList.append(fileName)
    return fileList

#in jenkins part, release is the same as the build release
#for legacy, release is like 6204,64,etc
#for lsr, release is 20.09,20.12,etc
def getBuildbyRel(REL,RELMap,Name,product):
      sideREL = ''
      mainREL = ''
      for item in RELMap:
          if REL==item :
              #for snmp,get mapping lsr release
              sideREL = REL
              mainREL = RELMap[item]
          elif REL == RELMap[item] and not product in ['NCDPU','SDFX','SDOLT','NBN-4F']:
              #this branch should never be touched,if backend is correct
              #for snmp, change release 20.09 to be 6.2.04
              sideREL = item
              mainREL = REL
              REL = sideREL
      Protocol,HOST,DIRN,username,password=Name
      print(Protocol,HOST,DIRN,username,password)
      fileList=[]
      protocolType=Protocol.strip().lower()
      print(protocolType)
      if protocolType=='ftp':
          try:
            f = ftplib.FTP(HOST)
          except ftplib.error_perm:
            print('Cannot connect to ftp server"%s"' % HOST)
            return
          print('Connected to ftp server"%s"' % HOST)

          try:
            f.login(username,password)
          except ftplib.error_perm:
            print('login failed')
            f.quit()
            return
          print('login sucessfully')

          try:
            f.cwd(DIRN)
            fileList=f.nlst()
          except ftplib.error_perm:
            print('failed to listed files')
            f.quit()
            return
      elif protocolType=='sftp':
          cnopts = pysftp.CnOpts()
          cnopts.hostkeys = None  
          f = pysftp.Connection(HOST, username=username, password=password,cnopts=cnopts)
          f.cwd(DIRN)
          fileList=f.listdir()
          #sftp.close()
      elif protocolType=='http':
          if 'http://' not in HOST and 'https://' not in HOST:
            requestUrl='http://'+HOST
          else:
            requestUrl=HOST
          print(requestUrl)
          fileList=MatchedBuilds(requestUrl)
      elif protocolType=='https':
          if 'http://' not in HOST and 'https://' not in HOST:
              requestUrl='https://'+HOST
          else:
              requestUrl=HOST
          print(requestUrl)
          fileList=MatchedBuilds(requestUrl)
      r = "^SD_[4-9]\d{1,3}\.\d{3,6}\.tar$"
      r2="^lightspan_[4-9]\d{1,3}\.\d{3}\.tar$"
      rf = "^pack_[4-9]\d{1,3}\.\d{3}$"
      pm = "^packageme_([4-9]\d{1,3})\.\d{3}$"
      omci = "^lightspan-omci_[4-9]\d{1,3}\.\d{3}\.tar$"
      ###new Release####
      pm1= "^packageme_\d{4}\.\d{3,6}$"
      r24= "^lightspan_\d{4}\.\d{3,6}\.tar$"
      omci2 ="^lightspan-omci_\d{4}\.\d{3,6}\.tar$"
      fileList2=[]
      res_pm1=''
      for item in fileList:
        item=item.strip()
        if re.findall(rf,item) or re.findall(pm,item) or re.findall(pm1,item):
            fileListSub=[]
            if protocolType=='ftp':
                f.cwd(DIRN+'/'+item)
                fileListSub=f.nlst()
            elif protocolType=='sftp':
                f.cwd(DIRN+'/'+item)
                fileListSub=f.listdir()
            elif protocolType=='http' or protocolType=='https':
                fileListSub=MatchedBuilds(requestUrl+'/'+item)
            if fileListSub:
                for ii in fileListSub:
                    ii=ii.strip()
                    if re.findall(r,ii) or re.findall(r2,ii) or re.findall(omci,ii) or re.findall(omci2,ii) or re.findall(r24,ii):
                        fileList2.append(ii)
        else:
            if re.findall(r,item) or re.findall(r2,item) or re.findall(omci,item) or re.findall(omci2,item) or re.findall(r24,item):
                fileList2.append(item)

      print('fileList is:%s'%fileList2)
      aa=[x.split('_')[0:1] + x.split('_')[1].split('.')[0:2] for x in fileList2]
      buildInfoDic={}
      for item in aa:
          buildT=item[0]
          releaseN=item[1]
          buildID=releaseN+'.'+item[2]
          if releaseN not in buildInfoDic:
              buildInfoDic[releaseN]={}
          if buildT not in buildInfoDic[releaseN]:
              buildInfoDic[releaseN][buildT]=[]
          buildInfoDic[releaseN][buildT].append(buildID) 
      #print('buildInfoDic is:%s'%buildInfoDic)
      print('product is:%s'%product)
      buildIDs = []
      REL = REL.replace('.','')
      sideREL = sideREL.replace('.','')
      mainREL = mainREL.replace('.','')
      listREL = [REL]
      if res_pm1:
          if mainREL:
              listREL = [sideREL,mainREL]
      print(listREL)
      for aREL in listREL:
          if aREL in buildInfoDic:
            buildIDAllTypeDic=buildInfoDic[REL]
            tmpList=[]
            if product in ['NCDPU','SDFX','SDOLT']:
                tmpList = buildIDAllTypeDic.get('lightspan',[])
            elif product in ['NBN-4F']:
                tmpList = buildIDAllTypeDic.get('lightspan-omci',[])
            else:
                tmpList = buildIDAllTypeDic.get('SD',[])
            if tmpList:
                tmpList.sort()
                buildIDs += tmpList
      buildIDs2=[]
      for buildItem in buildIDs:
        if '.' in buildItem:
            tailNum=str(buildItem.split('.')[1])
            if tailNum<'600':
                buildIDs2.append(buildItem)
        else:
            buildIDs2.append(buildItem)
      print('buildID is:%s'%buildIDs2)
      try:
          if protocolType=='ftp' or protocolType=='sftp':
            f.close()
      except:
          pass

      try:
          pullme_daily_packages = requests.get('https://artifactory-espoo2.int.net.nokia.com/artifactory/base-packages-local/pullme_daily_packages')
          msBuildList = re.findall('>([0-9]+\.[0-9]+)/</a>',pullme_daily_packages.content)

          if sideREL and not res_pm1:
              msBuildList=list(map(lambda x:x.replace(mainREL,sideREL),msBuildList))
          buildIDsL = sorted(set(msBuildList).intersection(set(buildIDs2)))
          if buildIDsL:
              buildIDs2=buildIDsL
      except Exception as e:
          print('Error :%s' % e)
      return buildIDs2
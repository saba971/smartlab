#!/usr/bin/python
import os,sys,time,inspect,re
import pexpect,logging
from optparse import OptionParser
import fileinput,getopt
import subprocess
import MySQLdb


def GetServerList(val_list):
  final_list=[]
  try:
    for value in val_list:
      value=value[0]
      if value is None or value == "":
          value="NULL"
      if ":" in value:
          value=value.split(":")
          if len(value)>=3:
              server_ip=value[0]
              server_port=value[1]
              server_user=value[2]
              server_pass=value[3]
              concat_str1=server_ip+":"+server_port+":"+server_user+":"+server_pass
              final_list.append(concat_str1)
          elif len(value)==3:
              server_ip=value[0]
              server_port=value[1]
              server_user=value[2]
              concat_str2=server_ip+":"+server_port+":"+server_user
              final_list.append(concat_str2)
          else:
              server_ip=value[0]
              server_port=value[1]
              concat_str3=server_ip+":"+server_port
              final_list.append(concat_str3)
      else:
          final_list.append(value)        
  except Exception as e:
    print(e)
    print "Get PCTA value failed"
  return final_list  

          
class db_operater():
    def __init__(self,logger=""):
      self.logger = logger
      self.conn = ""

    def connectToDatabase(self,host='135.251.206.145',port=3306,user='root',passwd='aitest',db='smartTest'):
      try:
        log = "Connecting DB server %s ... " %host
        cmd = "DB CMD -> MySQLdb.connect(host='%s', port=%d, user='%s',passwd='%s', db='%s')" %(host,port,user,passwd,db)
        self._printLogger(log)
        self._printLogger(cmd)
        self.conn = MySQLdb.connect(host=host, port=port, user=user,passwd=passwd, db=db)
      except Exception as e:
        log = "Connecting DB server %s fail: %s" %(host,e)
        self._printLogger(log)
      finally:
        log = "Connect DB server %s successful." %host
        self._printLogger(log)

    def disconnectFromDatabase(self):
      try:
        self._printLogger("Disconnecting DB server ... ")
        self.conn.close()
      except Exception as e:
        log = "Disconnecting DB server fail: %s" %e
        self._printLogger(log)
      finally:
        self._printLogger("Disconnec DB server successful.")

    def getItemFromTable(self,item="*",table="*",keys="*",iterate="default"):
      try:
        cur = self.conn.cursor()
        log = "Getting %s from table %s which key is %s" %(item,table,keys)
        self._printLogger(log)
        res = []
        if iterate != 'default':
            cmd = 'select %s from %s ORDER BY id ASC' %(item,table)
        else:
            cmd = 'select %s from %s' %(item,table)
        if keys != "*":
          lenKeyDir = len(keys) - 1
          cmd += " where"
          for index,key in enumerate(keys):
            cmd += " %s='%s'" %(key,keys[key])
            if index != lenKeyDir:
              cmd += " and"
        data = self.executeDBcmd(cur,cmd)
        if data:
          info = cur.fetchmany(data)
          for tmp in info:
            res.append(tmp)
        cur.close()
        self.conn.commit()
      except Exception as e:
        log = "Getting DB item fail: %s" %e
        self._printLogger(log)
      finally:
        log = "Got (%s) value successful: (%s)" %(item,res)
        self._printLogger(log)
      return res

    def insertItemToTable(self,table="",item="",itemVal=""):
      try:
        cur = self.conn.cursor()
        log = "inserting %s to table %s" %(item,table)
        self._printLogger(log)
        res = ""
        cmd = "insert INTO %s(%s) VALUES (%s)" %(table,item,itemVal)
        data = self.executeDBcmd(cur,cmd)
        cur.close()
        self.conn.commit()
      except Exception as e:
        log = "inserting DB item fail: %s" %e
        self._printLogger(log)
      finally:
        self._printLogger("Checking ...")
        nowItem = self.getItemFromTable(item=item,table=table)
        if nowItem:
          log = "inserted (%s) value successful: (%s)" %(item,itemVal)
          self._printLogger(log)
          return "PASS"
        else:
          log = "inserted (%s) value failed: current (%s)" %(item,nowItem)
          self._printLogger(log)
          return "FAIL"
    def updateItemToTable(self,table="",item="",itemVal="",key="",keyVal=""):
      try:
        cur = self.conn.cursor()
        log = "updating %s to table %s which key is %s,value is %s" %(item,table,key,keyVal)
        self._printLogger(log)
        res = ""
        cmd = "update %s set %s='%s' where %s='%s'" %(table,item,itemVal,key,keyVal)
        data = self.executeDBcmd(cur,cmd)
        cur.close()
        self.conn.commit()
      except Exception as e:
        log = "updating DB item fail: %s" %e
        self._printLogger(log)
      finally:
        self._printLogger("Checking ...")
        nowItem = self.getItemFromTable(item=item,table=table,keys={key:keyVal})
        if nowItem and nowItem[0][0] == itemVal:
          log = "updated (%s) value successful: (%s)" %(item,itemVal)
          self._printLogger(log)
          return "PASS"
        else:
          log = "updated (%s) value failed: current (%s)" %(item,nowItem)
          self._printLogger(log)
          return "FAIL"

    def executeDBcmd(self,cur,cmd):
      log = "CMD -> %s" %cmd
      self._printLogger(log)
      return cur.execute(cmd)

    def _printLogger(self,log=""):
      log = "DB :: "+log
      if self.logger:
        self.logger.info(log)
      else:
        print(("DB :: "+log))


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("--host_ip", dest="host_ip",default='', help="SERVER ip")
    parser.add_option("--mysql_port", dest="port",default=3306, help="Mysql port")
    parser.add_option("--mysql_user", dest="user",default='', help="Mysql user")
    parser.add_option("--mysql_pass", dest="password",default='', help="Mysql password")
    parser.add_option("--dbName", dest="database",default='', help="DB name")

    (options, args) = parser.parse_args(sys.argv[1:])
    localhost=options.host_ip
    port=options.port
    user=options.user
    passwd=options.password
    database=options.database
    name_list=[]
    name1_list=[]
    svr_list=[]
    index_list=[]
    final_list=[]
    ###Connect to MYSQL
    db_obj=db_operater()
    try:
        new_conn=db_obj.connectToDatabase(localhost,port,user,passwd,database)
    except Exception as inst:
        keyword_name = "Connect to MYSQL failed"
        raise AssertionError("%s:%s-> fail to connect MYSQL, exception: %s" \
        % (__name__,keyword_name, str(inst)))
    ####Get the PCTA & id list
    name_list=db_obj.getItemFromTable(item='PCTA',table='testPlatform',iterate='ascending')
    name1_list=db_obj.getItemFromTable(item='id',table='testPlatform',iterate='ascending')
    for id in name1_list:
        index_list.append(id[0])
    svr_list=GetServerList(name_list)
    ####Update the testplatform table in new execServer field
    for val1,val2 in zip(svr_list,index_list):
        db_obj.updateItemToTable(table='testPlatform',item="execServer",itemVal=val1,key="id",keyVal=val2)
    ####Disconnect MYSQL
    try:
        db_obj.disconnectFromDatabase()
    except Exception as inst:
        keyword_name = "Disconnect MYSQL failed"
        raise AssertionError("%s:%s-> fail to disconnect mysql session, exception: %s" \
        % (__name__,keyword_name, str(inst)))
    else:
        logging.debug("disconnect to MYSQL failed " )
   

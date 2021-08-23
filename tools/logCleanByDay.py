#coding=utf-8
import os,time,datetime,re,sys
#from argparse import ArgumentParser,ArgumentTypeError
from optparse import OptionParser

#parser = ArgumentParser()
parser = OptionParser()
parser.add_option("--Days", dest="Days",default="", help="Days")
parser.add_option("--Dirs", dest="Dirs",default="", help="Dirs")
#options = parser.parse_args()
(options, args) = parser.parse_args()

Days=options.Days
if not all([options.Dirs,Days]):
    print("Invalid arguments")
    print("Please input at least Days & Dir...")
    sys.exit(1)
Dirs=options.Dirs.split(',')
dataT=datetime.datetime.now() + datetime.timedelta(days=-int(Days))
date = dataT.strftime("%Y-%m-%d")
t2 = time.strptime(date,'%Y-%m-%d')
t2 = datetime.datetime(*t2[:3])
print "t2:",t2
dir_name = []
for data_dir in Dirs:
    validDir = filter(lambda x: re.match(r'((root|atxuser)-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[0-9]{8}|\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_PID\d+)',x), os.listdir(data_dir))
    for filename in validDir:
        filepath = os.path.join(data_dir,filename)
        if os.path.isdir(filepath):
          dir_date = os.popen(r"stat '%s'|sed -n '7p'|awk -F ': ' '{print $2}'|awk '{print $1}'" %filepath).read().strip()
          t = time.strptime(dir_date,'%Y-%m-%d')
          t1 = datetime.datetime(*t[:3])
          print "t1:",t1
          if t1>t2:
              print("Folder :%s used recently, Can not Delete" %filename)
          elif t2>t1:
              print("Folder :%s obsoleted more than %s days, Deleting %s...." %(filename,Days,filepath))
              os.system(r"rm -rf '%s'" %filepath)
              time.sleep(5)
          else:
              print("Folder :%s created about %s days，Waiting for next Clean...." % (filename,Days))



#0 0 * * * /usr/bin/python /root/wwang046/logCleanByDay.py --Days 40 --Dirs /tmp >>/tftpboot/logCleanByDay.log 2>&1

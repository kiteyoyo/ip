#!/usr/bin/env python
# -*- coding: utf-8 -*-
import datetime, telnetlib, re, os, time, sys, traceback, thread, threading, Queue, io, json, pprint, logging
from multiprocessing import Pool
from json import JSONEncoder

logging.basicConfig(level=logging.DEBUG)

#判斷輸入進來的mac碼的形式,以沒有特殊符號的方式儲存,再依要求回傳的特殊符號格式回傳
class MAC :
    def __init__(self, mac) :
        m=self.__analytic(mac)
        if m : 
            self.__mac=m.lower()
        else :
            self.__mac=''

    def __str__(self) :
        return self.getMac(':')

    def __hash__(self) :
        return hash(self.__mac)

    def __eq__(self, o) :
        return self.__mac==o.__mac

    def __analytic(self, m) :
        sym='[A-z0-9]'
        pat=sym+sym+':'+sym+sym+':'+sym+sym+':'+sym+sym+':'+sym+sym+':'+sym+sym
        result=re.search(pat, m)
        if result :
            a=result.group()
            return a[0:2]+a[3:5]+a[6:8]+a[9:11]+a[12:14]+a[15:17]
        pat=sym+sym+'-'+sym+sym+'-'+sym+sym+'-'+sym+sym+'-'+sym+sym+'-'+sym+sym
        result=re.search(pat, m)
        if result :
            a=result.group()
            return a[0:2]+a[3:5]+a[6:8]+a[9:11]+a[12:14]+a[15:17]
        pat=sym+sym+sym+sym+'\.'+sym+sym+sym+sym+'\.'+sym+sym+sym+sym
        result=re.search(pat, m)
        if result :
            a=result.group()
            return a[0:4]+a[5:9]+a[10:14]
        pat=sym+sym+sym+sym+sym+sym+sym+sym+sym+sym+sym+sym
        result=re.search(pat, m)
        if result :
            a=result.group()
            return a[0:12]
        return None
            
    def getMac(self, sym='') :
        if not self.__mac :
            return ''
        m=self.__mac
        if not sym :
            return self.__mac
        elif sym=='.' :
            return m[0:4]+'.'+m[4:8]+'.'+m[8:12]
        elif sym==':' :
            return m[0:2]+':'+m[2:4]+':'+m[4:6]+':'+m[6:8]+':'+m[8:10]+':'+m[10:12]
        return ''

#####################################################################
class IP :
    def __init__(self, i) :
        if isinstance(i, int):
            if i>0 and i<507 :
                self.number=i
                self.error=0
            else :
                self.number=0
                self.error=6
        elif isinstance(i, str) :
            self.error=0
            self.number=self.__analytic(i)
        elif isinstance(i, unicode) :
            self.error=0
            self.number=self.__analytic(i.encode('utf-8'))
        elif isinstance(i, IP) :
            self.number=i.number
            self.error=i.error
        else :
            raise Exception('IP input type error')

    def __str__(self) :
        return self.getIp()

    def __eq__(self, o) :
        if isinstance(o, IP) :
            return self.number==o.number
        elif isinstance(o, unicode) :
            return self.getIp()==o
        logging.error('can not judge o in __eq__ of IP')

    def __ne__(self, o) :
        return not self.__eq__(o)

    def __le__(self, o) :
        return self.number<=o.number

    def __lt__(self, o) :
        return self.number<o.number

    def __ge__(self, o) :
        return not self.__lt__(o)

    def __gt__(self, o) :
        return not self.__le__(o)

    def __hash__(self) :
        return hash(self.number)

    def __analytic(self, ip) :
        pat=r'.*\..*\..*\..*'
        if not re.search(pat, ip) :
            self.error=1
            return None
        pat=r'^\d*\.\d*\.\d*\.\d*$'
        if not re.search(pat, ip) :
            self.error=2
            return None
        pat=r'^([1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-3])\.([1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-3])\.([1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-3])\.([1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-3])$'
        if not re.search(pat, ip) :
            self.error=3
            return None
        pat=r'140\.115\..*\..*'
        if not re.search(pat, ip) :
            self.error=4
            return None
        pat1=r'140\.115\.2(5|6)\..*'
        if not re.search(pat1, ip) :
            self.error=5
            return None
        iptable=ip.split('.')
        if iptable[2]=='26' :
            return int(iptable[3])+253
        elif iptable[2]=='25' :
            return int(iptable[3])
        return None

    def isCorrect(self) :
        if self.error==0 :
            return True
        else :
            return False

    def getErrorMessage(self) :
        if self.error==0 :
            return 'It is correct'
        elif self.error==1 :
            return 'ERROR *.*.*.*'
        elif self.error==2 :
            return 'ERROR no English'
        elif self.error==3 :
            return 'ERROR input 1~253'
        elif self.error==4 :
            return 'ERROR 140.115.*.*'
        elif self.error==5 :
            return 'ERROR 140.115.25/26.*'
        elif self.error==6 :
            return 'ERROR input number range'
        else :
            raise Exception('ip analytic error')

    def getSection(self) :
        if self.number<254 :
            return 25
        else :
            return 26

    def getIp(self) :
        if self.getSection()==26 :
            return "140.115.26."+str(self.number-253)
        else :
            return "140.115.25."+str(self.number)

    def getNumber(self) :
        return self.number

    @staticmethod
    def range(start, end) :
        l=list()
        s=start.getNumber()
        e=end.getNumber()
        for i in range(s, e+1) :
            l.append(IP(i))
        return l

class IpData(threading.Thread) :
    def __init__(self, ip, someData=None) :
        super(IpData, self).__init__()
        self.ip=IP(ip)
        self.data=dict()

    def __str__(self, separ='default') :
        li=self.__list()
        for i in range(len(li)) :
            if isinstance(li[i], int) :
                li[i]=str(li[i])
            elif isinstance(li[i], MAC) :
                li[i]=li[i].__str__()
        me=list()
        if separ=='default' :
            t=True
            for l in li :
                me.append(l)
                if t :
                    me.append(': ')
                else :
                    me.append(', ')
                t=not t
        else :
            for l in li :
                me.append(l)
                me.append(separ)
        return ''.join(me)

    def __addData(self, someData) :
        for d in someData.keys() :
            value=someData[d]
            if isinstance(value, unicode) :
                value=value.encode('utf8')
            self.data.update({d:value})

    def getData(self, para) :
        if para=='ip' :
            return self.ip
        if para in self.data.keys() :
            return self.data[para]
        return None

    def __list(self) :
        data=self.data.copy()
        li=['ip', self.ip.__str__()]
        if 'mac' in data.keys() :
            for d in ['mac', 'switch', 'port'] :
                li.extend([d, data[d]])
                data.pop(d)
            if 'detail' in data.keys() :
                li.extend(['detail', data['detail']])
                data.pop('detail')
        for item in data.items() :
            li.extend(item)
        return li

    #################################################################
    # Search
    def updateNetwork(self, networkDatabase) :
        di=networkDatabase.search(self.ip)
        if di :
            self.__addData(di)

    def run(self) :
        if self.networkDatabase :
            self.updateNetwork(self.networkDatabase)
        else :
            raise Exception('please set networkDatabase')
        #print self.data

class MyEncoder(JSONEncoder):
    def default(self, o):
        return o.__dict__

class Format :
    @staticmethod
    def checkMac(mac) :
        m=MAC(mac).getMac()
        if m :
            return m
        raise Exception('macCheck error')

    @staticmethod
    def checkIP(ip) :
        i=IP(ip)
        if not i.isCorrect() :
            raise Exception(i.getErrorMessage())

    @staticmethod
    def argsChange(m) :
        message=m.__str__()
        pat=r':.*'
        result=re.search(pat, message)
        if result :
            return result.group()[1:]
        pat=r"'.*'"
        result=re.search(pat, str(message))
        return result.group()
    
#####################################################################
class Local :
    @staticmethod
    def getIp(section) :
        if section==25 :
            cmd="ifconfig | grep 140.115.25"
        elif section==26 :
            cmd="ifconfig | grep 140.115.26"
        else :
            raise Exception("input 25/26")
        msg=os.popen(cmd).read()
        if not msg :
            raise Exception("check ip data with ifconfig")
        ipdetail=msg.split()
        ipaddr=ipdetail[1]
        iplist=ipaddr.split(':')
        ip=IP(iplist[1])
        return ip

    @staticmethod
    def getMac() :
        cmd="ifconfig | grep eth0"
        msg=os.popen(cmd).read()
        mac_list=msg.split()
        mac=MAC(mac_list[4])
        return mac

    @staticmethod
    def getNetwork(ip) :
        networklist=ip.getIp().split('.')
        network=networklist[0]+'.'+networklist[1]+'.'+networklist[2]
        return network

################################################################################
class Login(object) :
    def __init__(self, host, setting) :
        self.host=host
        self.setting=setting
        for s in setting['switch_list'] :
            if s['ip']==host :
               self.switch=s
        if not self.switch :
            logging.error(host+' does not exist in switch_list')
            sys.exit(0)

    #登入並傳回connect
    def login(self) :
        connect=telnetlib.Telnet(self.host)
        if self.switch['type']=='juniper' :
            connect.read_until('login: ')
            connect.write(self.switch['user'].encode('utf-8')+'\n')
            connect.read_until('Password:')
            connect.write(self.switch['password'].encode('utf-8')+'\n')
        else :
            connect.read_until("Password: ")
            connect.write(self.switch['password'].encode('utf-8')+'\n')
        return connect

    #下載登入host關於mac table的資料,之後回傳
    def getAddressData(self) :
        connect=self.login()
        if self.switch['type']=='juniper' :
            connect.write("show ethernet-switching table \n")
            connect.write("         ")
        else :
            connect.write("show mac address-table\n         ")
        connect.write("exit\n")
        return connect.read_all()

###############################################################################
class Management(Login) :
    def __init__(self) :
        setting=NetworkDatabase.loadSetFile()
        super(Management, self).__init__(setting['top_switch_ip'], setting)

    def getBanIp(self) :
	result=self.getAddressData()
	pat=r'.*\..*\..*Drop'
        matchlist=re.findall(pat,result)
	drop_list=[]
        for onematch in matchlist :
	    splitmatch=onematch.split()
	    if splitmatch[0]=='--More---' :
                m=MAC(splitmatch[4])
                drop_list.append(m.getMac(':'))
	    else :
                m=MAC(splitmatch[1])
                drop_list.append(m.getMac(':'))
	return drop_list

    def banMac(self, mac, act='disable') :
        #password need global
        m=MAC(mac)
        standardMac=m.getMac(':')
	if act=='enable' :
	    cmd_list=['en', self.switch['password'], 'conf ter', 
                    'mac address-table static ' + standardMac + ' vlan 3025 drop',
		    'exit', 'exit']
	else :
	    cmd_list=['en', self.switch['password'], 'conf ter', 
	            'no mac address-table static '+ standardMac + ' vlan 3025 drop',
		    'exit', 'exit']
	connection=self.login()
	for cmd in cmd_list :
	    connection.write(cmd+'\n')
            time.sleep(0.1)
	connection.close()
############################################################################
class AddressTable(Login) :
    def __init__(self, host, setting) :
        super(AddressTable, self).__init__(host, setting)
        self.table=dict()
        self.cond=threading.Semaphore()
        if self.switch['type']=='juniper' :
            self.pat=r".*:.*:.*:.*:.*:.*"
            self.compare="---(more)---"
            self.pick=[2, 5, 1, 4 ]
        else :
            self.pat=r".*\..*\..*Gi.*"
            self.compare="--More--"
            if self.switch['type']=='cisco241' :
                self.pick=[4, 6, 1, 3 ]
            else :
                self.pick=[3, 5, 1, 3 ]
        self.number=self.switch['number']
        self.time=1

    def __str__(self) :
        return 'host: '+self.host

    #依是哪一台switch的port型態,移除不必要得資料,並回傳存port號
    #注意回傳的port為str型態,不為ιnt型態
    def __analyticPort(self, match, host) :
        splitport=match.split("/")
        if self.switch['type']=='juniper' :
            splitport2=splitport[self.number].split(".")
            return int(splitport2[0])
        else :
            return int(splitport[self.number])

    def __structTable(self) :
        self.time+=1
        table=dict()
        result=self.getAddressData()
        matchlist=re.findall(self.pat, result)
        for onematch in matchlist :
            splitmatch=onematch.split()
            if splitmatch[0]==self.compare :
                mac=MAC(splitmatch[self.pick[0]])
                port=self.__analyticPort(splitmatch[self.pick[1]], self.host)
                table.update({mac:port})
            else :
                mac=MAC(splitmatch[self.pick[2]])
                port=self.__analyticPort(splitmatch[self.pick[3]], self.host)
                table.update({mac:port})
        return table

    #############################################################################################
    def getPort(self, ip, mac) :
        m=mac
        while True :
            port=self.table.get(m)
            if port :
                return port
            self.cond.acquire()
            port=self.table.get(m)
            get_port_timeout=self.setting['get_port_timeout']
            if not port :
                self.table=self.__structTable()
            self.cond.release()
            if self.time==get_port_timeout[0] :
                thread.start_new_thread(self.__rescue, (ip, ))
            if self.time>=get_port_timeout[1] :
                raise Exception(ip.__str__()+' get port timeout')
            time.sleep(get_port_timeout[2])

    def __rescue(self, ip) :
        logging.info('start up rescue ability with '+str(self.time)+' times for '+ip.__str__()+' about '+self.host)
        cmd='ping '+ip.__str__()+"> /dev/null 2> /dev/null "
        os.system(cmd)

###########################################################################
class MacPortTable :
    def __init__(self, setting) :
        self.select=dict()
        self.setting=setting
        self.switchList=set()
        for s in setting['switch_list'] :
            logging.debug('switch ip: '+s['ip']+' is Unicode type: '+isinstance(s['ip'], unicode).__str__())
            self.switchList.add(IP(s['ip']))
        self.detailList=dict()
        for d in setting['detail_list'] :
            portList=dict()
            for m in d['map'] :
                portList.update({m['port'] : m['detail']})
            self.detailList.update({d['switch'] : portList})
        self.cond=threading.Semaphore()

    def __getNext(self, ip, switch, port) :
        for l in self.setting['line_list'] :
            if l['switch']['start']==switch and l['port']['start']==port and ip!=l['switch']['end'] :
                return l['switch']['end']
        return None

    def __isSwitch(self, ip) :
        if ip in self.switchList :
            return True
        else :
            return False

    def __getSwitchPort(self, ip, mac, host) :
        self.cond.acquire()
        table=self.select.get(host)
        if not table :
            table=AddressTable(host, self.setting)
            self.select.update({host:table})
        self.cond.release()
        #try :
        port=table.getPort(ip, mac)
        #except Exception as e :
            #return host, -1
        nextSwitch=self.__getNext(ip, host, port)
        if nextSwitch :
            return self.__getSwitchPort(ip, mac, nextSwitch)
        else :
            return {'switch': host, 'port' : port}

    def __getDetail(self, ip, di) :
        port=di['port']
        switch=di['switch']
        if self.__isSwitch(ip) :
            return 'this is switch'
        if port==-1 :
            return 'get port timeout'
        portList=self.detailList[switch]
        if portList :
            if port in portList.keys() :
                return portList[port]
        return None

    def getSwitchPortDetail(self, ip, mac) :
        di=self.__getSwitchPort(ip, mac, self.setting['top_switch_ip'])
        detail=self.__getDetail(ip, di)
        if detail :
            di.update({'detail' : detail})
        return di

##########################################################################
class NetworkDatabase(object) :
    def __init__(self) :
        self.local25=Local.getIp(25)
        self.local26=Local.getIp(26)
        self.setting=NetworkDatabase.loadSetting()
        self.macTable=dict()
        self.table=MacPortTable(self.setting)

    #ping全部所在網域裡的IP,可以選擇範圍或是全部,並使用指令arp -a IP 查詢,取得mac碼
    def __getMac(self, ip) :
        if ip==self.local25 or ip==self.local26 :
            return Local.getMac()
        else :
            pat=r"..:..:..:..:..:.."#以正規法的方式比較,找出符合的字串
            cmd="ping -c 1 " + ip.__str__() + "> /dev/null 2> /dev/null "
            os.system(cmd)
            time.sleep(1)
            arpmsg=os.popen("arp -a " + ip.__str__()).read()
            macpoint=re.search(pat,arpmsg)#拿取得的資料與正規表示法比較,找出符合的字串的第一組,並把位置存到macpoint裡
            if macpoint :
                return MAC(macpoint.group())#轉換從re.search裡找到的位置換為字串並存到mac裡
            else :
                return None

    #讀取mac與host登入遠端switch查詢,找出此mac所在的switch與port
    #回傳格式如 XX.XX.XX.XX, 7, None
    #@param  mac,host(如果沒有輸入host就是預設XX.XX.XX.XX
    #@return 所在的switch,port,詳細資料
    def search(self, ip) :
        mac=self.__getMac(ip)
        if not mac :
            self.macTable.pop(ip, 'not found')
            return None
        else :
            self.macTable.update({ ip:mac })
            di=self.table.getSwitchPortDetail(ip, mac)
            di.update({'mac' : mac})
            return di

    @staticmethod
    def loadSetting() :
        setting=NetworkDatabase.loadSetFile()
        if setting :
            d=NetworkDatabase.loadSetFromDatabase()
            if d :
                setting.update(d)
        else :
            logging.error('load setting error')
        return setting

    @staticmethod
    def loadSetFile() :
        path=os.path.dirname(os.path.realpath(__file__))+'/setting/local.json'
        if os.path.isfile(path) :
            read=open(path).read()
            try :
                setting=json.loads(read)
            except :
                logging.error('please check setting/local.json')
                return None
            return setting
        else :
            logging.error('please new setting/local.json')
            return None

    @staticmethod
    def loadSetFromDatabase() :
        project_path=os.path.dirname(os.path.dirname(os.path.realpath(__file__)))+'/'
        try :
            sys.path.append(project_path)
            os.environ['DJANGO_SETTINGS_MODULE'] ='manage.settings'
            #from mysite import settings
            import django
            django.setup()
         
            from ip.models import Switch, Line, Detail
            di=dict()
            switch_list=list()
            for a in Switch.objects.all() :
                d={ u'ip' : a.ip, u'type' : a.type, u'number' : int(a.number), u'user' : a.user, u'password' : a.password }
                switch_list.append(d)
            line_list=list()
            for a in Line.objects.all() :
                d={ u'switch' : { u'start' : a.upSwitch, u'end' : a.downSwitch }, u'port' : { u'start' : int(a.upPort), u'end' : int(a.downPort) } }
                line_list.append(d)
            detail_dict=dict()
            for a in Detail.objects.all() :
                if a.switch in detail_dict.keys() :
                    detail_dict[a.switch].update({ int(a.port) : a.detail })
                else :
                    detail_dict.update({ a.switch : { int(a.port) : a.detail } })
            detail_list=list()
            for di in detail_dict.items() :
                t=list()
                for i in di[1].items() :
                    t.append({ u'port' : i[0], u'detail' : i[1]})
                detail_list.append({u'switch' : di[0], u'map' : t})
                d={ u'switch' : a.switch, u'map' : { u'port' : a.port, u'detail' : a.detail } }
            return {u'switch_list' : switch_list, u'line_list' : line_list, u'detail_list' : detail_list}
        except :
            logging.error('load setting from database error')
            return None

class Database(object) :
    def __init__(self) :
        logging.debug('Database init')
        self.ipDict=dict()
        self.networkDatabase=None

    #查詢指定網域的所有資料
    #如果最前面的元素有寫的話就是指定此區段搜尋,如果沒有的話就是預設全部
    #有指定的情況下可以指定搜尋從哪裡到哪裡,分別是後面兩個元素
    def newIpSet(self, start=IP(1), end=IP(506)) :#506
        self.ipDict.clear()
        for ip in IP.range(start, end) :
            ipData=IpData(ip)
            self.ipDict.update({ip.__str__() : ipData})

    def updateIpSet(self, model='show', timer=False) :
        if not self.networkDatabase :
            self.networkDatabase=NetworkDatabase()
        t1=datetime.datetime.now()
        for thread in self.ipDict.values() :
            thread.networkDatabase=self.networkDatabase
            thread.start()
        for thread in self.ipDict.values() :
            thread.join()
            logging.debug(thread.ip.__str__()+' over now')
            if model=='show' :
                logging.info(thread.__str__())
        t2=datetime.datetime.now()
        if model=='save' :
            self.__save()
        t3=datetime.datetime.now()
        if timer :
            logging.info('Run  Time:'+(t2-t1).__str__())
            if model=='save' :
                logging.info('Save Time:'+(t3-t2).__str__())

    def __save(self) :
        project_path=os.path.dirname(os.path.dirname(os.path.realpath(__file__)))+'/'
        try :
            sys.path.append(project_path)
            os.environ['DJANGO_SETTINGS_MODULE'] ='manage.settings'
            #from mysite import settings
            import django
            django.setup()
        
            from ip.models import Ip

            al=Ip.objects.all()
            for a in al :
                ip=a.ip.encode('utf-8')
                if ip in self.ipDict.keys() :
                    m=self.ipDict[ip]
                    print m.__str__()
                    mac=m.getData('mac')
                    if mac :
                        a.activity=True
                        a.mac=mac.getMac()
                        a.switch=m.getData('switch')
                        a.port=m.getData('port')
                        detail=m.getData('detail')
                        if detail :
                            a.detail=detail
                    else :
                        a.activity=False
                        a.mac=''
                        a.switch=''
                        a.port=-1
                        a.detail=''
                    a.save()
        except Exception as e:
            traceback.print_exc()
            logging.error(e.__str__())
            logging.error('database save ip error')

    #        ip     site  hostname purpose admin   comment
    @staticmethod
    def loadOldFile(filename) :
        li=list()
        with io.open(filename, 'r', encoding='utf-8') as f :
            for line in f.readlines() :
                part=line.replace(u'　', '  ').replace('\t', '').split('|')

                #http://taizilongxu.gitbooks.io/stackoverflow-about-python/content/72/README.html
                di=dict()
                p=['site', 'hostname', 'purpose', 'admin', 'comment']
                for i in range(1, 7) :
                    part[i]=part[i].strip()
                for i in range(5) :
                    if len(part[i+2])!=0 :
                        di.update({p[i]: part[i+2]})
                logging.info(part[1]+'|'+part[2]+'|'+part[3]+'|'+part[4]+'|'+part[5]+'|'+part[6])
                li.append(IpData(part[1], di))
        return li

class Editor(object) :
    def __init__(self) :
        self.table=list()
        filename='/home/kite/bash/web/mac/mysite/25table'
        self.scan(filename)
        #self.show(filename)

    def show(self, filename) :
        #        ip     site  hostname purpose admin   comment
        table=[list(), list(), list(), list(), list(), list()]
        for i in range(1, 507) :
            m=Ip.objects.get(number=i)
            table[0].append(m.ip)
            table[1].append(m.site)
            table[2].append(m.hostname)
            table[3].append(m.purpose)
            table[4].append(m.admin)
            table[5].append(m.comment)
        mtable=list()
        #print len(table[0]), len(table[1]), len(table[2]), len(table[3]), len(table[4]), len(table[5]), 
        #for i in range(1, 507) :
            #print table[0][i], table[1][i], table[2][i], table[3][i], table[4][i], table[5][i]
        for t in table :
            mtable.append(max(t, key=len))
        logging.info(mtable)

def oldScan() :
    setting=loadSetFile()
    network=Scanner(setting)
    t=time.time()
    error_message=[]
    date_time=datetime.datetime.fromtimestamp(t).strftime('%Y,%m,%d')
    start_time=datetime.datetime.fromtimestamp(t).strftime('%H:%M:%S')
    try :
        network.scan()
    except Exception as e :
        traceback.print_exc()
        #print e.args
        error_message.append(Format.argsChange(e.args))
    d=time.time()
    end_time=datetime.datetime.fromtimestamp(d).strftime('%H:%M:%S')
    o=d-t
    run_time=datetime.datetime.fromtimestamp(o).strftime('%M:%S')
    print date_time+'\t'+start_time+'\t'+end_time+'\t'+run_time,

    if error_message :
        print '\t\t\t',
        print >> sys.stderr, date_time+'\t'+start_time+'\t'+end_time+'\t'+run_time+'\t\t\t',
        for message in error_message :
            print message,
            print >> sys.stderr, message,
        print >> sys.stderr, ''

    print ''

if __name__=='__main__' :
    #pprint.pprint(NetworkDatabase.loadSetFromDatabase())
    #pprint.pprint(NetworkDatabase.loadSetFile())
    database=Database()
    database.newIpSet()
    database.updateIpSet(model='save', timer=True)


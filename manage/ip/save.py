#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os, sys, io
sys.path.append('./manage/')
sys.path.append('./')
os.environ['DJANGO_SETTINGS_MODULE'] ='manage.settings'

#from mysite import settings
import django
django.setup()
 
from ip.models import Ip, Switch, Line, Detail

#把檔案中的資料存入資料庫
def save_ip(path) :
    with io.open(path, 'r', encoding='utf-8') as fi :
        for m in fi.readlines() :
            p=m.replace(u'　', '').replace(' ', '').replace('\t', '').replace('\n', '').split('|')
            a=Ip(ip=p[1])
            if p[2]=='True' :
                a.activity=True
                a.mac=p[3]
                a.switch=p[4]
                a.port=int(p[5])
                a.detail=p[6]
            else :
                a.activity=False
                a.mac=''
                a.switch=''
                a.port=-1
                a.detail=''
            if p[7] :
                a.default_switch=p[7]
            else :
                a.default_switch=''
            if p[8] :
                a.default_port=int(p[8])
            else :
                a.default_port=-1
            for i in range(9, 14) :
                if isinstance(p[i], unicode) :
                    p[i]=p[i].encode('utf-8')
            a.site=p[9]
            a.hostname=p[10]
            a.purpose=p[11]
            a.admin=p[12]
            a.comment=p[13]
            a.save()

#把資料庫中的資料存入檔案
def load_ip(path) :
    fi=open(path, 'w')
    al=Ip.objects.all()
    for m in al :
        data=[ m.ip, m.activity, m.get_mac(), m.get_switch(), m.get_port(), m.get_detail(), m.get_default_switch(), m.get_default_port(), m.site, m.hostname, m.purpose, m.admin, m.comment]
        for d in data :
            fi.write('|')
            if isinstance(d, str) :
                fi.write(d)
            elif isinstance(d, unicode) :
                fi.write(d.encode('utf-8'))
            else :
                fi.write(str(d))
        fi.write('\n')

def save_detail(path) :
    with open(path, 'r') as fi :
        for m in fi.readlines() :
            print m
            p=m.replace(u'　', '').replace('\t', '').replace('\n', '').split('|')
            a=Detail(switch=p[1], port=int(p[2]))
            if isinstance(p[3], unicode) :
                a.detail=p[3].encode('utf-8')
            else :
                a.detail=p[3]
            a.save()
            print a

def load_detail(path) :
    fi=open(path, 'w')
    al=Detail.objects.all()
    for m in al :
        data=[m.switch, m.port, m.detail]
        for d in data :
            fi.write('|')
            if isinstance(d, str) :
                fi.write(d)
            else :
                fi.write(str(d))

if __name__=='__main__' :
    if sys.argv[1]=='save' :
        if sys.argv[2]=='ip' :
            save_ip(sys.argv[3])
        elif sys.argv[2]=='detail' :
            save_detail(sys.argv[3])
    elif sys.argv[1]=='load' :
        if sys.argv[2]=='ip' :
            load_ip(sys.argv[3])
        elif sys.argv[2]=='detail' :
            load_detail(sys.argv[3])



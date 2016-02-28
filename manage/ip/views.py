from django.shortcuts import render

# Create your views here.

from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.http import Http404
from django.http import HttpResponseNotFound
from django.contrib import auth
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.shortcuts import render_to_response
from django.template import RequestContext
from ip.models import Ip
from ip.models import Switch
from ip.scan import Management, Format, IP, MAC
import re
def login(request) :
    if request.user.is_authenticated() :
        return HttpResponseRedirect('/frame/')
    username=request.POST.get('username', '')
    password=request.POST.get('password', '')
    user=auth.authenticate(username=username, password=password)
    if user is not None and user.is_active :
        auth.login(request, user)
        return HttpResponseRedirect('/frame/')
    else :
        return render_to_response('login.html',context=RequestContext(request))

def logout(request) :
    auth.logout(request)
    return HttpResponseRedirect('/frame/')

def register(request) :
    if not request.user.is_authenticated() :
        return HttpResponseRedirect('/accounts/login/')
    if request.method=='POST' :
        form=UserCreationForm(request.POST)
        if form.is_valid() :
            user=form.save()
            return HttpResponseRedirect('/accounts/login/')
    else :
        form=UserCreationForm()
    return HttpResponseRedirect('/register.html', locals())

def frame_index(request) :
    #response=checkUser(request)
    #if response :
    #    return response
    management=request.user.has_perm('ip.add_switch')
    page1=''
    page2='index/'
    ip=get_client_ip(request)
    return render_to_response('frame.html', RequestContext(request, locals()))

def frame_subIndex(request,sub) :
    page1='/frame'+sub
    page2=""#in factt, is not this
    return render_to_response('frame.html',locals())

def frame(request, sub1, sub2) :
    page1=sub1
    page2=sub2
    return render_to_response('frame.html',locals())

def index(request) :
    #return render_to_response('index.html', locals())
    return HttpResponse("Index")

def site(request) :
    set_list=[
	    map_list(1, "/site/map/", "Map"),
	    map_list(2, "/site/classroom/", "Classroom"),
	    map_list(3, "/site/professor/", "Professor"),
	    map_list(4, "/site/research/", "Research",
                items=['M115', 'M218', 'M313', 'M417', 'M201', 'M213','classroom'])]
    return render_to_response('typicalPage1.html', RequestContext(request, locals()))

def site_map(request) :
    return render_to_response('typicalTable.html')

def site_classroom(request) :
    ip_list=Ip.objects.all()[353:401]
    return render_to_response('site_classroom.html', RequestContext(request, locals()))

def site_professor(request) :
    ip_all=Ip.objects.all()
    room_list=[]
    name=['M108', 'M112', 'M116', 'M201-1', 'M202', 'M203', 'M204', 'M205', 'M206', 'M207', 'M209', 'M210', 'M211', 'M212', 'M301', 'M303', 'M303-1', 'M304', 'M305',  'M307', 'M308', 'M309', 'M310', 'M311', 'M312', 'M314', 'M315', 'M316', 'M316', 'M317', 'M401', 'M402', 'M403', 'M404', 'M405', 'M405-1', 'M406', 'M407', 'M408', 'M409', 'M410', 'M411', 'M412', 'M413', 'M414', 'M415', 'M416', 'M418', 'M419', 'M420', 'M421']
    for m in name :
        room_list.append(map_room(m,[]))
    for ip in ip_all :
        room_name=ip.get_detail()
        for r in room_list :
            if r.name==room_name :
                r.item.append(ip)
                break
    return render_to_response('site_site.html', RequestContext(request, locals()))

def site_research(request) :
    ip_all=Ip.objects.all()
    room_list=[
            map_room('M115', ip_all[324:341]),
            map_room('M218', ip_all[413:423]),
            map_room('M313', ip_all[423:435]),
            map_room('M417', ip_all[435:447]),
            map_room('M201', ip_all[447:473]),
            map_room('M213', ip_all[473:481]),
            map_room('Classroom', ip_all[481:487])]
    return render_to_response('site_site.html', RequestContext(request, locals()))

def switch(request) :
    set_list=[
            map_list(1, "/switch/network/", "Network"),
	    map_list(2, "/switch/172", "172.20.25.251"),
	    map_list(3, "/switch/241", "140.115.25.241"),
	    map_list(4, "/switch/242", "140.115.25.242"),
	    map_list(5, "/switch/246", "140.115.25.246"),
	    map_list(6, "/switch/251", "140.115.25.251"),
	    map_list(7, "/switch/p172", "p172.20.25.251"),
	    map_list(8, "/switch/p237", "p140.115.25.237"),
	    map_list(9, "/switch/p238", "p140.115.25.238"),
	    map_list(10, "/switch/p239", "p140.115.25.239"),
	    map_list(11, "/switch/p240", "p140.115.25.240"),
	    map_list(12, "/switch/p241", "p140.115.25.241"),
	    map_list(13, "/switch/p242", "p140.115.25.242"),
	    map_list(14, "/switch/p243", "p140.115.25.243"),
	    map_list(15, "/switch/p246", "p140.115.25.246"),
	    map_list(16, "/switch/p251", "p140.115.25.251")
            ]
    return render_to_response('typicalPage1.html', RequestContext(request, locals()))

def switch_network(request) :
    return render_to_response('typicalTable.html')

def switch_machine(request, machine) :
    if machine=='172' :
        title='172.20.25.251'
	ip_list=Ip.objects.filter(switch='172.20.25.251').order_by('port')
    elif machine=='241' :
        title='140.115.25.241'
	ip_list=Ip.objects.filter(switch='140.115.25.241').order_by('port')
    elif machine=='242' :
        title='140.115.25.242'
        ip_list=Ip.objects.filter(switch='140.115.25.242').order_by('port')
    elif machine=='246' :
        title='140.115.25.246'
        ip_list=Ip.objects.filter(switch='140.115.25.246').order_by('port')
    elif machine=='251' :
	title='140.115.25.251'
	ip_list=Ip.objects.filter(switch='140.115.25.251').order_by('port')
    else :
	return HttpResponse('error')
    return render_to_response('switch_machine.html', RequestContext(request, locals()))

def switch_port(request, machine) :
    if machine=='172' :
        title='172.20.25.251'
	port_list=Switch.objects.get(ip='172.20.25.251').port_set.all().order_by('port')
    elif machine=='237' :
        title='140.115.25.237'
	port_list=Switch.objects.get(ip='140.115.25.237').port_set.all().order_by('port')
    elif machine=='238' :
        title='140.115.25.238'
	port_list=Switch.objects.get(ip='140.115.25.238').port_set.all().order_by('port')
    elif machine=='239' :
        title='140.115.25.239'
	port_list=Switch.objects.get(ip='140.115.25.239').port_set.all().order_by('port')
    elif machine=='240' :
        title='140.115.25.240'
	port_list=Switch.objects.get(ip='140.115.25.240').port_set.all().order_by('port')
    elif machine=='241' :
        title='140.115.25.241'
	port_list=Switch.objects.get(ip='140.115.25.241').port_set.all().order_by('port')
    elif machine=='242' :
        title='140.115.25.242'
	port_list=Switch.objects.get(ip='140.115.25.242').port_set.all().order_by('port')
    elif machine=='243' :
        title='140.115.25.243'
	port_list=Switch.objects.get(ip='140.115.25.243').port_set.all().order_by('port')
    elif machine=='246' :
        title='140.115.25.246'
	port_list=Switch.objects.get(ip='140.115.25.246').port_set.all().order_by('port')
    elif machine=='251' :
	title='140.115.25.251'
	port_list=Switch.objects.get(ip='140.115.25.251').port_set.all().order_by('port')
    else :
	return HttpResponse('error')
    return render_to_response('switch_port.html', RequestContext(request, locals()))

def ip(request) :
    set_list=[
            map_list(1, "/ip/25/", "25"),
	    map_list(2, "/ip/26/", "26")]
    return render_to_response('typicalPage1.html', RequestContext(request, locals()))

def ip_ip(request,ip) :
    if ip=='25' :
    	ip_list=Ip.objects.all()[0:253]
    elif ip=='26' :
    	ip_list=Ip.objects.all()[253:]
    else :
        return HttpResponse('error')
    return render_to_response('ip_ip.html', RequestContext(request, locals()))

def special(request) :
    set_list=[
            map_list(1, "/special/unusedip/", "Unused IP"),
	    map_list(2, "/special/search/", "Search"),
            map_list(3, "/special/wrong/", "Wrong")]
    return render_to_response('typicalPage1.html', RequestContext(request, locals()))

def special_unusedip(request) :
    ip_25=Ip.objects.all()[0:253]
    ip_26=Ip.objects.all()[253:]
    ip_list_25=list()
    ip_list_26=list()
    for ip in ip_25 :
        if ip.activity==False :
            ip_list_25.append(ip)
    for ip in ip_26 :
        if ip.activity==False :
            ip_list_26.append(ip)
    return render_to_response('special_unusedip.html', RequestContext(request, locals()))

def special_search(request) :
    errors=[]
    if 'ok' in request.POST :
        success=False
        ip=request.POST['ip']
        mac=request.POST['mac']
        if not ip and not mac :
            errors.append("it can't blank")
        elif not ip and mac :
            m=MAC(mac).getMac()
            if m :
                try :
                    ipSet=Ip.objects.get(mac=m)
                    success=True
                except :
                    errors.append("ERROR Is not there this mac.")
            else :
                errors.append('check mac format')
        elif ip :
            i=IP(str(ip))
            if i.isCorrect() :
                try :
                    ipSet=Ip.objects.get(ip=ip)
                    success=True
                except :
                    errors.append("This ip is not used.")
            else :
                errors.append(i.getErrorMessage())
        if success and ipSet.activity:
            outIp=ipSet.ip
            outMac=ipSet.get_mac()
            outSwitch=ipSet.get_switch
            outPort=ipSet.get_port
            outDetail=ipSet.get_detail()
        else :
            if success :
                errors.append('this ip is not used.')
            outIp=ip
            outMac=mac
    return render_to_response('special_search.html', RequestContext(request, locals()))

def special_wrong(request) :
    ip_all=Ip.objects.all()
    wrong_ip=[]
    for ip in ip_all :
        success=True
        if ip.activity==False :
            success=False
        elif ip.default_port==-1 :
            success=False
        elif ip.switch==ip.default_switch and ip.port==ip.default_port :
            success=False
        if success :
            wrong_ip.append(ip)
    return render_to_response('special_wrong.html', RequestContext(request, locals()))

def management(request) :
    set_list=[
            map_list(1, "/management/lock/", "Lock"),
            map_list(2, "/admin", "Admin", target="_blank")]
    return render_to_response('typicalPage1.html', RequestContext(request, locals()))

def management_lock(request) :
    management=Management()
    errors=[]
    if 'ok' in request.POST :
        success=False
        act=request.POST['act']
        mac=request.POST['mac']
        if act=='ban' :
            try :
                management.banMac(mac.__str__(), 'enable')
                errors.append('success')
            except Exception as e :
                message=e.args
                errors.append(management.argsChange(message))
        elif act=='unban' :
            try :
                management.banMac(mac.__str__())
                errors.append('success')
            except Exception as e :
                message=e.args
                errors.append(management.argsChange(message))
    ban_list=management.getBanIp()
    
    return render_to_response('management_lock.html', RequestContext(request, locals()))

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
'''
def checkUser(request, management=False) :
    ip=get_client_ip(request)
    setting=Setting()
    pat='^140.115.2[56].([1-9]|[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-3])$'
    for h in setting.allow_host :
        if not re.search(pat, h) :
            raise Exception('allow_host set fail with '+h)
    for h in setting.deny_host :
        if not re.search(pat, h) :
            raise Exception('deny_host set fail with '+h)
    if setting.mode=='mathip' :
        success=False 
        if re.search(pat, ip) :
            success=True
    elif setting.mode=='allow' :
        success=False
        for h in setting.allow_host :
            if h==ip :
                success=True
                break
    elif setting.mode=='deny' :
        success=True
        for h in setting.deny_host :
            if h==ip :
                success=False
                break
    else :
        raise Exception('mode set fail!')
    if re.search('127\.0\.0\.1', ip) :
        success=True
    if not success :
        raise Http404('your ip is not allowed!')
    if not request.user.is_authenticated() :
        return HttpResponseRedirect('/accounts/login/')
    if management and not request.user.has_perm('ip.add_switch') :
        return HttpResponseRedirect('/accounts/login/')
    return None
'''
class map_list :
    def __init__(self, number,  path, name, target='page2', items=[]) :
        self.number=number
        self.path=path
        self.name=name
        self.target=target
        self.items=items
    def getMenu(self) :
        return 'menu'+str(self.number)
    def getOutline(self) :
        return 'menu'+str(self.number)+'outline'
    def getSign(self) :
        return 'menu'+str(self.number)+'sign'
class map_room :
    def __init__(self, name, item) :
        self.name=name
        self.item=item

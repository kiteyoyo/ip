from __future__ import unicode_literals

from django.db import models

# Create your models here.
class Ip (models.Model) :
    ip=models.CharField(unique=True, max_length=15)
    activity=models.BooleanField(default=True)
    mac=models.CharField(max_length=12, blank=True)
    switch=models.CharField(max_length=15, blank=True)
    port=models.IntegerField(blank=True)
    detail=models.TextField(blank=True)
    default_switch=models.CharField(max_length=15, blank=True)
    default_port=models.IntegerField(blank=True,default=-1)
    #room=models.TextField(blank=True)
    time=models.DateTimeField(auto_now=True)
    site=models.CharField(max_length=10, blank=True)
    hostname=models.CharField(max_length=30, blank=True)
    purpose=models.TextField(blank=True)
    admin=models.CharField(max_length=25, blank=True)
    comment=models.TextField(blank=True)

    def get_mac(self) :
        m=self.mac
        if not self.activity :
            return ''
        else :
            return m[0:2]+':'+m[2:4]+':'+m[4:6]+':'+m[6:8]+':'+m[8:10]+':'+m[10:12]
    def get_switch(self) :
        if not self.activity :
            return ''
        else :
            return self.switch

    def get_port(self) :
        if not self.activity :
            return ''
        else :
            return self.port

    def get_detail(self) :
        if not self.activity :
            return ''
        else :
            return self.detail
    
    def get_default_switch(self) :
        return self.default_switch

    def get_default_port(self) :
        if self.default_port<0 :
            return ''
        return self.default_port
    
    def get_room(self) :
        if self.default_switch=='N' or self.port<0 :
            return ''
        else :
            b=Detail.objects.filter(switch=self.default_switch)
            if b.count()>0 :
                b=b.filter(port=self.default_port)
                if b.count()>0 :
                    b=b.get(port=self.default_port)
                    return b.detail
            return ''
    def save(self, *args, **kwargs) :
        ip=self.ip
        iptable=ip.split('.')
        if len(iptable)==4 :
            if iptable[0]=='140' and iptable[1]=='115' and int(iptable[3])>0 and int(iptable[3])<254 :
        	if iptable[2]=='25' or iptable[2]=='26':
        	    super(Ip, self).save(*args, **kwargs)
        	    return True
        return False
    def __unicode__(self) :
        return self.ip
    class Meta :
        app_label='ip'
 
class Switch(models.Model) :
    ip=models.CharField(unique=True, max_length=15)
    type=models.CharField(max_length=20)
    number=models.IntegerField()
    user=models.CharField(max_length=20, blank=True)
    password=models.CharField(max_length=20)

    def __str__(self) :
	return self.ip
    class Meta :
        app_label='ip'
        ordering=['ip']

class Port(models.Model) :
    switch=models.ForeignKey(Switch)
    port=models.IntegerField()
    label=models.CharField(max_length=20, blank=True)
    info=models.TextField(blank=True)

    def __unicode__(self) :
        if self.label :
            return self.label+"["+self.switch.ip+":"+str(self.port)+"]"
        else :
            return "["+str(self.switch.ip)+":"+str(self.port)+"]"
    class Meta :
        app_label='ip'
        ordering=['switch', 'port']

class Line(models.Model) :
    upSwitch=models.CharField(max_length=15)
    upPort=models.IntegerField()
    downSwitch=models.CharField(max_length=15)
    downPort=models.IntegerField()

    def __str__(self) :
    	return self.upSwitch+'('+str(self.upPort)+')=>'+self.downSwitch+'('+str(self.downPort)+')'
    class Meta :
        app_label='ip'

class Detail(models.Model) :
    switch=models.CharField(max_length=15)
    port=models.IntegerField()
    detail=models.TextField(max_length=100)

    def __str__(self) :
	return self.switch+'('+str(self.port) +')'
    class Meta :
        app_label='ip'

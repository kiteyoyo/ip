from django.contrib import admin

# Register your models here.

from ip.models import Ip, Switch, Port, Line, Detail

class IpAdmin(admin.ModelAdmin) :
    list_display=('__unicode__', 'activity', 'get_mac', 'get_switch', 'get_port', 'get_default_switch', 'get_default_port', 'hostname', 'purpose', 'admin', 'comment', 'time')
    list_filter=('activity',)
    search_fields=('ip',)
    #ordering=('ip',)
    fields=('default_switch', 'default_port', 'hostname', 'purpose', 'admin', 'comment')


class SwitchAdmin(admin.ModelAdmin) :
    list_display=('ip', 'type', 'number', 'user', 'password')

class PortAdmin(admin.ModelAdmin) :
    list_display=('switch', 'port', 'label', 'info')

class LineAdmin(admin.ModelAdmin) :
    list_display=('upSwitch', 'upPort', 'downSwitch', 'downPort')

class DetailAdmin(admin.ModelAdmin) :
    list_display=('switch', 'port', 'detail')

admin.site.register(Ip, IpAdmin)
admin.site.register(Switch, SwitchAdmin)
admin.site.register(Port, PortAdmin)
admin.site.register(Line, LineAdmin)
admin.site.register(Detail, DetailAdmin)

'''
admin.site.register(Ip)
admin.site.register(Switch)
admin.site.register(Line)
admin.site.register(Detail)
'''

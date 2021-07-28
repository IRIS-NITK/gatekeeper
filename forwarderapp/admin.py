from django.contrib import admin

# Register your models here.
from rest_framework.authtoken.admin import TokenAdmin

from .models import Rule

class AuthorAdmin(admin.ModelAdmin):
    list_display = ['id',  'active', 'source_ip','forwarder_port', 'destination_ip' , 'destination_port']
    ordering = ['-id']
    list_filter = ['active']
admin.site.register(Rule, AuthorAdmin)

TokenAdmin.raw_id_fields = ['user']
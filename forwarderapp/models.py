import datetime

from django.db import models
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.http import HttpResponse, JsonResponse

PROTOCOLS = [("tcp", "tcp"), ("udp", "udp")]

# Create your models here.


class Rule(models.Model):
    rule_protocol = models.CharField(
        max_length=3, choices=PROTOCOLS, default="tcp")
    source_ip = models.CharField(max_length=60)
    expiry_period = models.DurationField(
        blank=False, default=datetime.timedelta(hours=4))
    forwarder_port = models.CharField(max_length=10)
    destination_ip = models.CharField(max_length=60)
    destination_port = models.CharField(max_length=10)
    active = models.BooleanField(default=False)
    renewal_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expiry_task_id = models.CharField(max_length=50)

    class Meta:
        ordering = ['created_at']


class Port(models.Model):
    active = models.BooleanField(default=False)
    port_number = models.IntegerField(primary_key=True)


from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)
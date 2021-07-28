from typing import Protocol

from django.contrib.auth.models import Group, User
from rest_framework import serializers
from rest_framework.validators import UniqueTogetherValidator

from .models import Rule
from .utils import *
import environ
# Initialise environment variables
env = environ.Env()
environ.Env.read_env()
from pathlib import Path
PROTOCOLS = [("tcp", "tcp"), ("udp", "udp")]
RESERVED_PORTS = env("RESERVED_PORTS")

class RuleSerializer(serializers.Serializer):

    # Below is list of params returned in a response
    id = serializers.IntegerField(read_only=True)
    rule_protocol = serializers.CharField(read_only=True)
    active = serializers.BooleanField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)
    renewal_count = serializers.IntegerField(read_only=True)

    # Below Params are required in a Request
    source_ip = serializers.CharField(max_length=60)
    forwarder_port = serializers.CharField(max_length=10)
    destination_ip = serializers.CharField(max_length=60)
    destination_port = serializers.CharField(max_length=10)
    expiry_period = serializers.DurationField()

    def validate(self, data):
        # Chek if the port requested is a reserved port
        if data['forwarder_port'] in RESERVED_PORTS:
         raise serializers.ValidationError(
                "Forwarder port passed is already in use")     
        # Check if an existing Rule is active with this forwarder port
        clashing_rule = Rule.objects.filter(
            active__exact=True, forwarder_port__exact=data['forwarder_port'])
        if clashing_rule:
            raise serializers.ValidationError(
                "Forwarder port passed is already in use")

        # Append this rule in NAT table
        try:
            append_rule_prerouting(data)
        except:
            raise serializers.ValidationError(
                "Error appending rule to PREROUTING Chain")

        try:
            append_rule_postrouting(data)
        except:
            raise serializers.ValidationError(
                "Error appending rule to POSTROUTING Chain")

        # Rule is appended, mark active as True
        data['active'] = True

        # If all validation checks passes, validation success
        return data

    def create(self, validated_data):
        return Rule.objects.create(**validated_data)

class PortSerializer(serializers.Serializer):
    active = serializers.BooleanField(default=False)
    port_number = serializers.IntegerField()

# class UserSerializer(serializers.HyperlinkedModelSerializer):
#     class Meta:
#         model = User
#         fields = ['url', 'username', 'email', 'groups']

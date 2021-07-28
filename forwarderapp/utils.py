import datetime
from re import search
from time import sleep
import iptc
from celery.result import *
from django.utils import timezone
from django.utils.dateparse import parse_duration
from .models import Port, Rule
from .tasks import *
from ipaddress import *
import environ
env = environ.Env()
environ.Env.read_env()
from pathlib import Path


FORWARDER_IP = env("FORWARDER_IP")
PROTOCOL = "tcp"
FORWARDER_INTERFACE = env("FORWARDER_INTERFACE")


def append_rule_prerouting(instance):
    prerouting_chain = getChain("PREROUTING")
    rule = iptc.Rule()
    rule.protocol = PROTOCOL
    rule.in_interface = FORWARDER_INTERFACE
    rule.src = instance['source_ip']
    rule.dst = FORWARDER_IP
    match = rule.create_match(PROTOCOL)
    match.dport = instance['forwarder_port']
    t = rule.create_target("DNAT")
    t.set_parameter(
        'to-destination', instance['destination_ip'] + ":" + instance['destination_port'])
    prerouting_chain.append_rule(rule)


def append_rule_postrouting(instance):
    postrouting_chain = getChain("POSTROUTING")
    rule = iptc.Rule()
    rule.protocol = PROTOCOL
    rule.out_interface = FORWARDER_INTERFACE
    rule.src = instance['source_ip']
    t = rule.create_target("SNAT")
    t.set_parameter('to-source', FORWARDER_IP)
    postrouting_chain.append_rule(rule)


def getChain(chain_name):
    return iptc.Chain(iptc.Table(iptc.Table.NAT), chain_name)


def getCurrentNATTable(ipv4=True):
    return iptc.easy.dump_table('nat', ipv6=not ipv4)


def force_expire_rule(rule_id):
    # Force delete a rule from chain if it exists
    rule = Rule.objects.get(pk=rule_id)

    if rule.active == False:
        return False, "Rule already expired"

    # Proceed with rule deletion
    try:
        delete_rule_prerouting(rule.source_ip, rule.destination_ip +
                               ":" + rule.destination_port, rule.forwarder_port)
    except:
        return False, "Error deleting rule from PREROUTING Chain"
    try:
        delete_rule_postrouting(rule.source_ip)
    except:
        return False, "Error deleting rule from POSTROUTING Chain"

    AsyncResult(id=rule.expiry_task_id).revoke(terminate=True)
    rule.active = False
    rule.save()
    return True, "Rule expired successfully"


def renew_expiry_period_rule(rule_id, new_expiry_period):
    # Extend expiry period of a rule if it's not already expired
    rule = Rule.objects.get(pk=rule_id)

    if rule.active == False:
        return False, "Rule already expired"

    # Cancel the scheduled deletion task of this rule and create another scheduled deletion task with new expiry period
    AsyncResult(id=rule.expiry_task_id).revoke(terminate=True)
    rule.expiry_period = parse_duration(new_expiry_period)
    rule.renewal_count = rule.renewal_count + 1
    rule.save()
    schedule_rule_deletion(rule.id)
    return True, "Rule Renewed Successfully"


def sync_rule(rule_id):
    prerouting_chain = getChain("PREROUTING")
    rule_to_check = Rule.objects.get(pk=rule_id)

    for rule in prerouting_chain.rules:
        if rule.src and ip_network(rule.src) == ip_network(rule_to_check.source_ip) and (rule.target.parameters['to_destination'] == (rule_to_check.destination_ip + ":" + rule_to_check.destination_port)) and rule.matches[0].dport == rule_to_check.forwarder_port:
            return
    # Rule not present in NAT, update rule in DB
    rule_to_check.active = False
    rule_to_check.save()


def delete_rule_prerouting(source_ip, destination, forwarder_port):
    prerouting_chain = getChain("PREROUTING")
    for rule in prerouting_chain.rules:
        if rule.src and ip_network(rule.src) == ip_network(source_ip) and rule.target.parameters['to_destination'] == destination and rule.matches[0].dport == forwarder_port:
            prerouting_chain.delete_rule(rule)
            break


def delete_rule_postrouting(source_ip):
    postrouting_chain = getChain("POSTROUTING")
    for rule in postrouting_chain.rules:
        if rule.src and ip_network(rule.src) == ip_network(source_ip):
            postrouting_chain.delete_rule(rule)
            break


def schedule_rule_deletion(rule_id):
    rule = Rule.objects.get(pk=rule_id)
    expire_time = timezone.now() + rule.expiry_period
    tag = 'new_tag'
    x = delete_rule_from_table.apply_async((rule_id, tag), eta=expire_time)
    # store task id and save
    rule = Rule.objects.get(pk=rule_id)
    rule.expiry_task_id = x.id

# Possible values of protocols
#  socket.IPPROTO_AH: "ah",
#  socket.IPPROTO_DSTOPTS: "dstopts",
#  socket.IPPROTO_EGP: "egp",
#  socket.IPPROTO_ESP: "esp",
#  socket.IPPROTO_FRAGMENT: "fragment",
#  socket.IPPROTO_GRE: "gre",
#  socket.IPPROTO_HOPOPTS: "hopopts",
#  socket.IPPROTO_ICMP: "icmp",
#  socket.IPPROTO_ICMPV6: "icmpv6",
#  socket.IPPROTO_IDP: "idp",
#  socket.IPPROTO_IGMP: "igmp",
#  socket.IPPROTO_IP: "ip",
#  socket.IPPROTO_IPIP: "ipip",
#  socket.IPPROTO_IPV6: "ipv6",
#  socket.IPPROTO_NONE: "none",
#  socket.IPPROTO_PIM: "pim",
#  socket.IPPROTO_PUP: "pup",
#  socket.IPPROTO_RAW: "raw",
#  socket.IPPROTO_ROUTING: "routing",
#  socket.IPPROTO_RSVP: "rsvp",
#  socket.IPPROTO_SCTP: "sctp",
#  socket.IPPROTO_TCP: "tcp",
#  socket.IPPROTO_TP: "tp",
#  socket.IPPROTO_UDP: "udp",

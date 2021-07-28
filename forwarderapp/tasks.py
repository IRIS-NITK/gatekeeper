import iptc
from celery import shared_task
from .models import Rule
from ipaddress import *

from celery.result import *


@shared_task(bind=True)
def delete_rule_from_table(task, rule_id, tag):
    rule = Rule.objects.get(pk=rule_id)
    if rule.active == True:
        delete_rule_prerouting(rule.source_ip, rule.destination_ip +
                               ":" + rule.destination_port, rule.forwarder_port)
        delete_rule_postrouting(rule.source_ip)
        rule.active = False
        rule.save()


def delete_rule_prerouting(source_ip, destination, forwarder_port):
    prerouting_chain = getChain("PREROUTING")
    for rule in prerouting_chain.rules:
        if rule.src and rule.src == source_ip and rule.target.parameters['to_destination'] == destination and rule.matches[0].dport == forwarder_port:
            prerouting_chain.delete_rule(rule)
            break


def delete_rule_postrouting(source_ip):
    postrouting_chain = getChain("POSTROUTING")
    for rule in postrouting_chain.rules:
        if rule.src and rule.src == source_ip:
            postrouting_chain.delete_rule(rule)
            break


def getChain(chain_name):
    return iptc.Chain(iptc.Table(iptc.Table.NAT), chain_name)


@shared_task(bind=True, max_retries = 0)
def sync_all_rules(task):
    prerouting_chain = getChain("PREROUTING")
    # get active_rules query_set
    active_rules = Rule.objects.filter(active__exact=True)
    for rule in active_rules:
        rule.active = False
    active_rule_ids = []
    for rule in prerouting_chain.rules:
        search_rule = active_rules.filter(forwarder_port__exact=rule.matches[0].dport).filter(
            source_ip=str(ip_network(rule.src).network_address)).first()
        if search_rule and (search_rule.destination_ip + ":" + search_rule.destination_port == rule.target.parameters['to_destination']):
            # mark active
            active_rule_ids.append(search_rule.id)
    # now active_ids array has all active rules, mark them as active and save all rules
    for rule in active_rules:
        if rule.id in active_rule_ids:
            rule.active = True
        else:
            # cancel deletion of rules that were marked as active in db but do not actually exist
            
            AsyncResult(id=rule.expiry_task_id).revoke(terminate=True)
        rule.save()

import json
from django.http import HttpResponse, JsonResponse
from rest_framework.parsers import JSONParser
from .models import Port, Rule
from .serializers import PortSerializer, RuleSerializer
from .utils import *
from rest_framework.views import APIView
from rest_framework import authentication
from rest_framework.permissions import IsAuthenticated
from .tasks import *


class Connections(APIView):
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        # sync all active rules as an async task
        # sync_all_rules.apply_async()
        if request.GET and 'active' in request.GET:
            query_param_active = request.GET['active']
            if query_param_active == "true" or query_param_active == "1":
                rules = Rule.objects.filter(active__exact=True)
            elif query_param_active == "false" or query_param_active == "0":
                rules = Rule.objects.filter(active__exact=False)
            else:
                rules = []
        else:
            rules = Rule.objects.all()
        serializer = RuleSerializer(rules, many=True)
        return JsonResponse(serializer.data, safe=False)

    def post(self, request, format=None):
        data = JSONParser().parse(request)
        serializer = RuleSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            schedule_rule_deletion(serializer.data["id"])
            return JsonResponse(serializer.data, status=201)
        return JsonResponse(serializer.errors, status=400)


class Connection(APIView):
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [IsAuthenticated]

    """
    GET /rules/:id Get details for a particular rule, refresh it's current status
    """

    def get(self, request, id):
        try:
            rule = Rule.objects.get(pk=id)
        except Rule.DoesNotExist:
            return HttpResponse(json.dumps({"error": ["Rule does not exist"]}), content_type="application/json", status=400)
        if rule.active == True:
            # sync rules
            sync_rule(id)
            rule = Rule.objects.get(pk=id)
        serializer = RuleSerializer(rule)
        return JsonResponse(serializer.data)


class Renew(APIView):
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [IsAuthenticated]

    """
    POST /rules/:id/renew_rule/ 
    """

    def post(self, request, id):
        try:
            rule = Rule.objects.get(pk=id)
        except Rule.DoesNotExist:
            return HttpResponse(json.dumps({"error": ["Rule does not exist"]}), content_type="application/json", status=400)

        # Use expiry_period passed in body params and renew this rule
        # TODO use data = JSONParser().parse(request) here instead of json.loads
        if request.body and 'new_expiry_period' in json.loads(request.body):
            new_expiry_period = json.loads(request.body)[
                'new_expiry_period']
            status, message = renew_expiry_period_rule(
                id, new_expiry_period)
            if status == True:
                rule = Rule.objects.get(pk=id)
                serializer = RuleSerializer(rule)
                return JsonResponse(serializer.data)
            else:
                return HttpResponse(json.dumps({"error": [message]}), content_type="application/json", status=400)
        else:
            return HttpResponse(json.dumps({"error": ["New expiry period not passed"]}), content_type="application/json", status=400)


class Expire(APIView):
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [IsAuthenticated]

    """
    POST /rules/:id/expire_rule/
    """

    def post(self, request, id):
        try:
            rule = Rule.objects.get(pk=id)
        except Rule.DoesNotExist:
            return HttpResponse(json.dumps({"error": ["Rule does not exist"]}), content_type="application/json", status=400)

        status, message = force_expire_rule(id)
        if status == True:
            return HttpResponse(json.dumps({"success": [message]}), content_type="application/json", status=200)
        else:
            return HttpResponse(json.dumps({"error": [message]}), content_type="application/json", status=400)


# """
# TODO return port numbers,active state and add query param to show active ports
# GET /ports
# """
# def ports(request):
#     if request.method == 'GET':
#         ports = Port.objects.all()
#         serializer = PortSerializer(ports, many=True)
#         return JsonResponse(serializer.data, safe=False)
#     else:
#         return HttpResponse(json.dumps({"error": ["Method not allowed"]}), content_type="application/json", status=405)


# """
# TODO return if port is active or not, if it is in use return rule which is using this port
# GET /ports/:port/
# """


# def port(request, port_number):
#     if request.method == 'GET':
#         try:
#             port = Port.objects.get(pk=port_number)
#             serializer = PortSerializer(port)
#             return JsonResponse(serializer.data)
#         except Port.DoesNotExist:
#             return HttpResponse(status=404)
#     else:
#         return HttpResponse(json.dumps({"error": ["Method not allowed"]}), content_type="application/json", status=405)


# """
# TODO TBD
# GET /statistics/
# """


# def statistics(request):
#     if request.method == 'GET':
#         rules = Rule.objects.all()
#         serializer = RuleSerializer(rules, many=True)
#         return JsonResponse(serializer.data, safe=False)
#     else:
#         return HttpResponse(json.dumps({"error": ["Method not allowed"]}), content_type="application/json", status=405)

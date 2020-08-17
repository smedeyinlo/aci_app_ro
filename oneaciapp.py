
# title           :oneaciapp.py
# description     :aci app ro
# author          :segun medeyinlo
# date            :08102018
# version         :2.5
# usage           :
# notes           :updated 17082020
# python_version  :3.8.3
# ==============================================================================

import time
import json
import requests
import ipaddress
import binascii
import os
from operator import itemgetter
from waitress import serve
from flask import Flask, render_template, session, redirect, url_for
from flask import flash, request, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_admin import BaseView, AdminIndexView, expose, Admin
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from itsdangerous import URLSafeTimedSerializer
from requests.packages.urllib3.exceptions import InsecureRequestWarning
#from requests.packages.urllib3.exceptions import InsecurePlatformWarning

class aciDB:
    def __init__(self, apic_url=None):
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        self.mysession = requests.Session()
        self.apic = str(apic_url)
        self.apic_site = ''
        self.mso_mysession = None
        self.mso_url = ''
        self.mso_domainid = ''
        self.mso_token = ''
        self.mso_schema = ''
        self.mso_template = ''
        self.mso_site = ''
        select_apic = self.apic.replace("https://", '')
        if apic_url:
            self.apic_site =[apic_dict[akey][0] for akey in apic_dict if select_apic == apic_dict[akey][2]][0]
            self.mso_site = [apic_dict[akey][4] for akey in apic_dict if select_apic == apic_dict[akey][2]][0]
            self.mso_schema = [apic_dict[akey][5] for akey in apic_dict if select_apic == apic_dict[akey][2]][0]
            self.mso_template = [apic_dict[akey][6] for akey in apic_dict if select_apic == apic_dict[akey][2]][0]
            self.mso_url = [apic_dict[akey][7] for akey in apic_dict if select_apic == apic_dict[akey][2]][0]
            self.mso_domainid = [apic_dict[akey][8] for akey in apic_dict if select_apic == apic_dict[akey][2]][0]


    def login(self, uid, pwd, apic):
        self.apic = str(apic)
        login_url = self.apic + '/api/aaaLogin.json'
        data = {'aaaUser': {'attributes': {'name': uid,
                                           'pwd': pwd}}}

        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        # requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
        self.mysession = requests.Session()

        for try_login_three_times in range(0,2, 1):
            post_resp = self.mysession.post(login_url, data=json.dumps(data, sort_keys=True), verify=False)
            post_resp_data = json.loads(post_resp.text)['imdata'][0]
            if post_resp.ok:
                timeout = post_resp_data['aaaLogin']['attributes']['refreshTimeoutSeconds']
                return timeout
        print ('Could not login to APIC1: ', self.apic, post_resp, post_resp.text)
        return None


    def refresh(self):
        refresh_url = self.apic + '/api/aaaRefresh.json'
        self.mysession.get(refresh_url)

    def logout(self):
        self.mysession.close()
        self.mysession = None

    def get_fabric_config(self):
        url = '/api/node/mo/uni.json?query-target=subtree&rsp-prop-include=config-only'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        result = json.loads(resp.text)['imdata']
        return result


    def get_tenant_json(self, tenant_name, limit='naming-only'):
        url = '/api/node/mo/uni/tn-' + tenant_name + \
              '.json?query-target=self&rsp-subtree=full&rsp-prop-include=' + limit
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        tenant_json = json.loads(resp.text)['imdata'][0]
        return tenant_json

    def get_tenants(self):
        tenants_list = []
        url = '/api/class/fvTenant.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        tenants = json.loads(resp.text)['imdata']

        for tenant in tenants:
            tenants_list.append(str(tenant['fvTenant']['attributes']['name']))
        return tenants_list

    def get_tenant_name_dict(self):
        tenant_name_dict = {}
        url = '/api/class/fvTenant.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        tenants = json.loads(resp.text)['imdata']
        
        for tenant in tenants:
            tenant_name = str(tenant['fvTenant']['attributes']['name'])
            tenant_name_dict[tenant_name] = {}
            tenant_name_dict[tenant_name]['name'] = tenant_name
            tenant_name_dict[tenant_name]['descr'] = str(tenant['fvTenant']['attributes']['descr'])
            tenant_name_dict[tenant_name]['alias'] = str(tenant['fvTenant']['attributes']['nameAlias'])
        return tenant_name_dict

    def get_tenant_dict(self):
        tenant_dict = {}
        url = '/api/class/fvTenant.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        tenants = json.loads(resp.text)['imdata']

        for tenant in tenants:
            tenant_name = str(tenant['fvTenant']['attributes']['name'])
            tenant_dict[tenant_name] = {}
            tenant_dict[tenant_name]['name'] = tenant_name
            tenant_dict[tenant_name]['descr'] = str(tenant['fvTenant']['attributes']['descr'])
            tenant_dict[tenant_name]['dn'] = str(tenant['fvTenant']['attributes']['dn'])
            tenant_dict[tenant_name]['alias'] = str(tenant['fvTenant']['attributes']['nameAlias'])
            tenant_dict[tenant_name]['annotation'] = ''
            if 'annotation' in tenant['fvTenant']['attributes']:
                tenant_dict[tenant_name]['annotation'] = str(tenant['fvTenant']['attributes']['annotation'])
            tenant_dict[tenant_name]['ctx'] = []
            tenant_dict[tenant_name]['bd'] = []
            tenant_dict[tenant_name]['app'] = []
            tenant_dict[tenant_name]['epg'] = []
            tenant_dict[tenant_name]['contract'] = []
            tenant_dict[tenant_name]['l3out'] = []

        ctx_dict = self.get_ctx_name_dict()
        for ctx_dn in ctx_dict.keys():
            tenant_dict[ctx_dict[ctx_dn]['tenant']]['ctx'].append(ctx_dn)
        bd_dict = self.get_bd_name_dict()
        for bd_dn in bd_dict.keys():
            tenant_dict[bd_dict[bd_dn]['tenant']]['bd'].append(bd_dn)
        app_dict = self.get_app_name_dict()
        for app_dn in app_dict.keys():
            tenant_dict[app_dict[app_dn]['tenant']]['app'].append(app_dn)
        epg_dict = self.get_epg_name_dict()
        for epg_dn in epg_dict.keys():
            tenant_dict[epg_dict[epg_dn]['tenant']]['epg'].append(epg_dn)
        contract_dict = self.get_contract_name_dict()
        for contract_dn in contract_dict.keys():
            tenant_dict[contract_dict[contract_dn]['tenant']]['contract'].append(contract_dn)
        l3out_dict = self.get_l3out_name_dict()
        for l3out_dn in l3out_dict.keys():
            tenant_dict[l3out_dict[l3out_dn]['tenant']]['l3out'].append(l3out_dn)

        return tenant_dict

    def get_switch_dict(self):
        switch_dict = {}
        url = '/api/node/class/fabricNode.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        nodes = json.loads(resp.text)['imdata']
        for node in nodes:
            node_id = str(node['fabricNode']['attributes']['id'])
            switch = str(node['fabricNode']['attributes']['name'])
            switch_dict[node_id] = node['fabricNode']['attributes']
            switch_dict[node_id]['pod'] = str(node['fabricNode']['attributes']['dn'].split('/pod-')[1].split('/')[0])
            switch_dict[switch] = node['fabricNode']['attributes']
            switch_dict[switch]['pod'] = str(node['fabricNode']['attributes']['dn'].split('/pod-')[1].split('/')[0])
            if 'controller' == str(node['fabricNode']['attributes']['role']):
                switch_dict[switch]['fabricSt'] = 'N/A'
        return switch_dict

    def get_rsbd_dict(self):
        rsbd_dict = {}
        url = '/api/class/fvRsBd.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        rsbds = json.loads(resp.text)['imdata']

        for rsbd in rsbds:
            if 'fvRsBd' in rsbd:
                rsbd_dn = str(rsbd['fvRsBd']['attributes']['dn'].split('/rsbd')[0])
                rsbd_tdn = str(rsbd['fvRsBd']['attributes']['tDn'])
                rsbd_name = str(rsbd['fvRsBd']['attributes']['tnFvBDName'])
                if rsbd_tdn:
                    rsbd_dict[rsbd_dn] = {}
                    rsbd_dict[rsbd_dn]['bd_tenant'] = str(rsbd_tdn.split('uni/tn-')[1].split('/')[0])
                    rsbd_dict[rsbd_dn]['name'] = rsbd_name
                    rsbd_dict[rsbd_dn]['dn'] = rsbd_dn
                    rsbd_dict[rsbd_dn]['tdn'] = rsbd_tdn
                    if rsbd_dict[rsbd_dn]['bd_tenant'] == 'common': rsbd_dict[rsbd_dn]['name'] = '*' + rsbd_name

        return rsbd_dict

    def get_bd_name_dict(self):
        bd_name_dict = {}
        url = '/api/class/fvBD.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        bds = json.loads(resp.text)['imdata']
        
        for bd in bds:
            if 'fvBD' in bd:
                bd_dn = str(bd['fvBD']['attributes']['dn'])
                bd_name_dict[bd_dn] = {}
                bd_name_dict[bd_dn]['name'] = str(bd['fvBD']['attributes']['name'])
                bd_name_dict[bd_dn]['descr'] = str(bd['fvBD']['attributes']['descr'])
                bd_name_dict[bd_dn]['tenant'] = str(bd_dn.split('uni/tn-')[1].split('/')[0])
        return bd_name_dict

    def get_bd_dict(self):
        bd_dict = {}
        url = '/api/class/fvBD.json?' \
                'rsp-subtree=full&rsp-subtree-class=fvRsCtx,fvRtBd,fvSubnet,dhcpLbl,fvRsBDToOut'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        bds = json.loads(resp.text)['imdata']
        
        for bd in bds:
            if 'fvBD' in bd:
                bd_dn = str(bd['fvBD']['attributes']['dn'])
                bd_dict[bd_dn] = {}
                bd_dict[bd_dn]['name'] = str(bd['fvBD']['attributes']['name'])
                bd_dict[bd_dn]['descr'] = str(bd['fvBD']['attributes']['descr'])
                bd_dict[bd_dn]['tenant'] = str(bd_dn.split('uni/tn-')[1].split('/')[0])
                bd_dict[bd_dn]['unicastRoute'] = str(bd['fvBD']['attributes']['unicastRoute'])
                bd_dict[bd_dn]['iplearning'] = str(bd['fvBD']['attributes']['ipLearning'])
                bd_dict[bd_dn]['limitiplearn'] = str(bd['fvBD']['attributes']['limitIpLearnToSubnets'])
                bd_dict[bd_dn]['arpflood'] = str(bd['fvBD']['attributes']['arpFlood'])
                bd_dict[bd_dn]['unkunicast'] = str(bd['fvBD']['attributes']['unkMacUcastAct'])
                bd_dict[bd_dn]['encapflood'] = str(bd['fvBD']['attributes']['multiDstPktAct'])
                bd_dict[bd_dn]['mac'] = str(bd['fvBD']['attributes']['mac'])
                bd_dict[bd_dn]['ctx_tenant'] = ''
                bd_dict[bd_dn]['ctx'] = ''
                bd_dict[bd_dn]['context_dn'] = ''
                bd_dict[bd_dn]['epg'] = []
                bd_dict[bd_dn]['subnet'] = []
                bd_dict[bd_dn]['dhcp'] = []
                bd_dict[bd_dn]['l3out'] = []
                bd_children = bd['fvBD']['children']
                for bd_child in bd_children:
                    if 'fvRsCtx' in bd_child:
                        bd_context_dn = str(bd_child['fvRsCtx']['attributes']['tDn'])
                        if bd_context_dn:
                            bd_dict[bd_dn]['ctx_tenant'] = str(bd_context_dn.split('uni/tn-')[1].split('/')[0])
                            bd_dict[bd_dn]['ctx'] = str(bd_context_dn.split('/ctx-')[1].split('/')[0])
                            bd_dict[bd_dn]['context_dn'] = str(bd_context_dn)
                    if 'fvRtBd' in bd_child:
                        bd_epg_dn = str(bd_child['fvRtBd']['attributes']['tDn'])
                        bd_dict[bd_dn]['epg'].append(str(bd_epg_dn))
                    if 'fvSubnet' in bd_child:
                        bd_subnet_ip = str(bd_child['fvSubnet']['attributes']['ip'])
                        bd_dict[bd_dn]['subnet'].append(str(bd_subnet_ip))
                    if 'dhcpLbl' in bd_child:
                        bd_dhcp = str(bd_child['dhcpLbl']['attributes']['name'])
                        bd_dict[bd_dn]['dhcp'].append(str(bd_dhcp))
                    if 'fvRsBDToOut' in bd_child:
                        bd_l3out = str(bd_child['fvRsBDToOut']['attributes']['tnL3extOutName'])
                        bd_dict[bd_dn]['l3out'].append(str(bd_l3out))

        return bd_dict

    def get_ctx_name_dict(self):
        ctx_name_dict = {}
        url = '/api/class/fvCtx.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        ctxs = json.loads(resp.text)['imdata']

        for ctx in ctxs:
            if 'fvCtx' in ctx:
                ctx_dn = str(ctx['fvCtx']['attributes']['dn'])
                ctx_name_dict[ctx_dn] = {}
                ctx_name_dict[ctx_dn]['name'] = str(ctx['fvCtx']['attributes']['name'])
                ctx_name_dict[ctx_dn]['descr'] = str(ctx['fvCtx']['attributes']['descr'])
                ctx_name_dict[ctx_dn]['tenant'] = str(ctx_dn.split('uni/tn-')[1].split('/')[0])
                ctx_name_dict[ctx_dn]['intractx'] = str(ctx['fvCtx']['attributes']['pcEnfPref'])

        return ctx_name_dict

    def get_app_name_dict(self):
        app_name_dict = {}
        url = '/api/class/fvAp.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        apps = json.loads(resp.text)['imdata']

        for app in apps:
            if 'fvAp' in app:
                app_dn = str(app['fvAp']['attributes']['dn'])
                app_name_dict[app_dn] = {}
                app_name_dict[app_dn]['name'] = str(app['fvAp']['attributes']['name'])
                app_name_dict[app_dn]['descr'] = str(app['fvAp']['attributes']['descr'])
                app_name_dict[app_dn]['tenant'] = str(app_dn.split('uni/tn-')[1].split('/')[0])

        return app_name_dict

    def get_epg_name_dict(self):
        epg_name_dict = {}
        url = '/api/class/fvAEPg.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        epgs = json.loads(resp.text)['imdata']

        for epg in epgs:
            if 'fvAEPg' in epg:
                epg_dn = str(epg['fvAEPg']['attributes']['dn'])
                epg_name_dict[epg_dn] = {}
                epg_name_dict[epg_dn]['tenant'] = str(epg_dn.split('uni/tn-')[1].split('/')[0])
                epg_name_dict[epg_dn]['app'] = str(epg_dn.split('/ap-')[1].split('/')[0])
                epg_name_dict[epg_dn]['name'] = str(epg['fvAEPg']['attributes']['name'])
                epg_name_dict[epg_dn]['descr'] = str(epg['fvAEPg']['attributes']['descr'])
        return epg_name_dict

    def get_epg_dict(self):
        epg_dict = {}
        bd_dict = self.get_bd_dict()
        url = '/api/class/fvAEPg.json?' \
              'rsp-subtree=full&rsp-subtree-class=fvRsDomAtt,fvRsPathAtt,fvRsCustQosPol&' \
              'rsp-prop-include=config-only'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        epgs = json.loads(resp.text)['imdata']
        
        for epg in epgs:
            if 'fvAEPg' in epg:
                epg_dn = str(epg['fvAEPg']['attributes']['dn'])
                epg_dict[epg_dn] = {}
                epg_dict[epg_dn]['tenant'] = str(epg_dn.split('uni/tn-')[1].split('/')[0])
                epg_dict[epg_dn]['app'] = str(epg_dn.split('/ap-')[1].split('/')[0])
                epg_dict[epg_dn]['name'] = str(epg['fvAEPg']['attributes']['name'])
                epg_dict[epg_dn]['alias'] = str(epg['fvAEPg']['attributes']['nameAlias'])
                epg_dict[epg_dn]['prefgrp'] = str(epg['fvAEPg']['attributes']['prefGrMemb'])
                epg_dict[epg_dn]['intraepg'] = str(epg['fvAEPg']['attributes']['pcEnfPref'])
                epg_dict[epg_dn]['useg'] = str(epg['fvAEPg']['attributes']['isAttrBasedEPg'])
                if 'encapflood' in epg['fvAEPg']['attributes']:
                    epg_dict[epg_dn]['encapflood'] = str(epg['fvAEPg']['attributes']['floodOnEncap'])
                epg_dict[epg_dn]['descr'] = str(epg['fvAEPg']['attributes']['descr'])
                epg_dict[epg_dn]['context'] = ''
                epg_dict[epg_dn]['bd'] = ''
                epg_dict[epg_dn]['bd_subnet'] = []
                epg_dict[epg_dn]['bd_tenant'] = ''
                epg_dict[epg_dn]['ctx'] = ''
                epg_dict[epg_dn]['ctx_tenant'] = ''
                epg_dict[epg_dn]['vlan'] = []
                epg_dict[epg_dn]['encap'] = []
                epg_dict[epg_dn]['path'] = []
                epg_dict[epg_dn]['domain'] = []
                if 'children' in epg['fvAEPg']:
                    epg_children = epg['fvAEPg']['children']
                    for child in epg_children:
                        if 'fvRsPathAtt' in child:
                            epg_dict[epg_dn]['path'].append(str(child['fvRsPathAtt']['attributes']['tDn']))
                            encap = str(child['fvRsPathAtt']['attributes']['encap'])
                            if encap not in epg_dict[epg_dn]['vlan']: epg_dict[epg_dn]['vlan'].append(encap)
                        if 'fvRsDomAtt' in child:
                            epg_dict[epg_dn]['domain'].append(str(child['fvRsDomAtt']['attributes']['tDn']))

        url = '/api/class/fvAEPg.json?' \
              'rsp-subtree=children&rsp-subtree-class=fvCEp,fvRsBd'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        epgs = json.loads(resp.text)['imdata']
        
        for epg in epgs:
            if 'fvAEPg' in epg:
                epg_dn = str(epg['fvAEPg']['attributes']['dn'])
                if 'children' in epg['fvAEPg']:
                    epg_children = epg['fvAEPg']['children']
                    for child in epg_children:
                        if 'fvRsBd' in child:
                            bd_dn = str(child['fvRsBd']['attributes']['tDn'])
                            if bd_dn in bd_dict.keys():
                                epg_dict[epg_dn]['bd'] = str(child['fvRsBd']['attributes']['tnFvBDName'])
                                epg_dict[epg_dn]['bd_subnet'] = bd_dict[bd_dn]['subnet']
                                epg_dict[epg_dn]['bd_tenant'] = str(bd_dn.split('uni/tn-')[1].split('/')[0])
                                context_dn = str(bd_dict[bd_dn]['context_dn'])
                                if '/ctx-' in context_dn:
                                    epg_dict[epg_dn]['ctx'] = str(context_dn.split('/ctx-')[1])
                                    epg_dict[epg_dn]['ctx_tenant'] = str(context_dn.split('uni/tn-')[1].split('/')[0])
                        if 'fvCEp' in child:
                            encap = str(child['fvCEp']['attributes']['encap'])
                            if encap not in epg_dict[epg_dn]['encap']: epg_dict[epg_dn]['encap'].append(encap)

        return epg_dict

    def get_contract_name_dict(self):
        contract_name_dict = {}
        url = '/api/class/vzBrCP.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        contracts = json.loads(resp.text)['imdata']

        for contract in contracts:
            if 'vzBrCP' in contract:
                contract_dn = str(contract['vzBrCP']['attributes']['dn'])
                contract_name_dict[contract_dn] = {}
                contract_name_dict[contract_dn]['name'] = str(contract['vzBrCP']['attributes']['name'])
                contract_name_dict[contract_dn]['tenant'] = str(contract_dn.split('uni/tn-')[1].split('/')[0])
                contract_name_dict[contract_dn]['scope'] = str(contract['vzBrCP']['attributes']['scope'])
        return contract_name_dict

    def get_contract_dict(self):
        contract_dict = {}
        cpif_dict = {}
        url = '/api/class/vzBrCP.json?rsp-subtree=full&rsp-subtree-class=vzSubj,vzRsSubjFiltAtt,' \
              'vzOutTerm,vzInTerm,vzRsSubjGraphAtt'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        contracts = json.loads(resp.text)['imdata']

        for contract in contracts:
            if 'vzBrCP' in contract:
                contract_dn = str(contract['vzBrCP']['attributes']['dn'])
                contract_dict[contract_dn] = {}
                contract_dict[contract_dn]['name'] = str(contract['vzBrCP']['attributes']['name'])
                contract_dict[contract_dn]['tenant'] = str(contract_dn.split('uni/tn-')[1].split('/')[0])
                contract_dict[contract_dn]['scope'] = str(contract['vzBrCP']['attributes']['scope'])
                contract_dict[contract_dn]['filter'] = []
                contract_dict[contract_dn]['ports'] = []
                contract_dict[contract_dn]['pepg'] = []
                contract_dict[contract_dn]['cepg'] = []
                contract_dict[contract_dn]['dir'] = []
                contract_dict[contract_dn]['servicegraph'] = ''
                contract_dict[contract_dn]['sg'] = ''

                if 'children' in contract['vzBrCP']:
                    contract_subjects = contract['vzBrCP']['children']
                    for contract_subject in contract_subjects:
                        revFltPorts = str(contract_subject['vzSubj']['attributes']['revFltPorts'])
                        if 'children' in contract_subject['vzSubj']:
                            filters = contract_subject['vzSubj']['children']
                            for filter in filters:
                                if 'vzRsSubjFiltAtt' in filter:
                                    filter_tdn = str(filter['vzRsSubjFiltAtt']['attributes']['tDn'])
                                    contract_dict[contract_dn]['filter'].append(filter_tdn)
                                    filter_name = str(filter['vzRsSubjFiltAtt']['attributes']['tnVzFilterName'])
                                    if revFltPorts == 'yes':
                                        filter_dir = 'bidir_reverse_port'
                                    else:
                                        filter_dir = 'bidir_same_port'
                                    contract_dict[contract_dn]['ports'].append(filter_name)
                                    contract_dict[contract_dn]['dir'].append(filter_dir)
                                if 'vzOutTerm' in filter:
                                    if 'children' in filter['vzOutTerm']:
                                        outfilters = filter['vzOutTerm']['children']
                                        for filter in outfilters:
                                            filter_tdn = str(filter['vzRsFiltAtt']['attributes']['tDn'])
                                            contract_dict[contract_dn]['filter'].append(filter_tdn)
                                            filter_name = str(filter['vzRsFiltAtt']['attributes']['tnVzFilterName'])
                                            filter_dir = 'unidir_out'
                                            contract_dict[contract_dn]['ports'].append(filter_name)
                                            contract_dict[contract_dn]['dir'].append(filter_dir)
                                if 'vzInTerm' in filter:
                                    if 'children' in filter['vzInTerm']:
                                        infilters = filter['vzInTerm']['children']
                                        for filter in infilters:
                                            filter_tdn = str(filter['vzRsFiltAtt']['attributes']['tDn'])
                                            contract_dict[contract_dn]['filter'].append(filter_tdn)
                                            filter_name = str(filter['vzRsFiltAtt']['attributes']['tnVzFilterName'])
                                            filter_dir = 'unidir_in'
                                            contract_dict[contract_dn]['ports'].append(filter_name)
                                            contract_dict[contract_dn]['dir'].append(filter_dir)
                                if 'vzRsSubjGraphAtt' in filter:
                                    contract_dict[contract_dn]['servicegraph'] = \
                                        str(filter['vzRsSubjGraphAtt']['attributes']['tDn'])
                                    contract_dict[contract_dn]['sg'] = \
                                        str(filter['vzRsSubjGraphAtt']['attributes']['tnVnsAbsGraphName'])

        url = '/api/class/vzCPIf.json?rsp-subtree=full&rsp-subtree-class=vzRsIf'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        cpifs = json.loads(resp.text)['imdata']

        for cpif in cpifs:
            if 'vzCPIf' in cpif:
                cpif_dn = str(cpif['vzCPIf']['attributes']['dn'])
                cpif_dict[cpif_dn] = ''
                if 'children' in cpif['vzCPIf']:
                    cpif_children = cpif['vzCPIf']['children']
                    for child in cpif_children:
                        if 'vzRsIf' in child:
                            contract_dn = str(child['vzRsIf']['attributes']['tDn'])
                            if str(child['vzRsIf']['attributes']['state']) == 'formed':
                                if contract_dn: cpif_dict[cpif_dn] = contract_dn

        url = '/api/class/vzAny.json?rsp-subtree=full&rsp-subtree-class=vzRsAnyToProv,vzRsAnyToCons,vzRsAnyToConsIf'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        vzanys = json.loads(resp.text)['imdata']

        for vzany in vzanys:
            if 'vzAny' in vzany:
                vzany_dn = str(vzany['vzAny']['attributes']['dn'])
                if 'children' in vzany['vzAny']:
                    vzany_children = vzany['vzAny']['children']
                    for child in vzany_children:
                        if 'vzRsAnyToProv' in child:
                            contract_dn = str(child['vzRsAnyToProv']['attributes']['tDn'])
                            if contract_dn: contract_dict[contract_dn]['pepg'].append(vzany_dn)
                        if 'vzRsAnyToCons' in child:
                            contract_dn = str(child['vzRsAnyToCons']['attributes']['tDn'])
                            if contract_dn: contract_dict[contract_dn]['cepg'].append(vzany_dn)
                        if 'vzRsAnyToConsIf' in child:
                            contract_dn = str(child['vzRsAnyToConsIf']['attributes']['tDn'])
                            contract_dn = str(cpif_dict[contract_dn])
                            if contract_dn: contract_dict[contract_dn]['cepg'].append(vzany_dn)
        
        url = '/api/class/fvAEPg.json?rsp-subtree=full&rsp-subtree-class=fvRsProv,fvRsCons'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        epgs = json.loads(resp.text)['imdata']
        
        for epg in epgs:
            if 'fvAEPg' in epg:
                epg_dn = str(epg['fvAEPg']['attributes']['dn'])
                if 'children' in epg['fvAEPg']:
                    epg_children = epg['fvAEPg']['children']
                    for child in epg_children:
                        if 'fvRsProv' in child:
                            contract_dn = child['fvRsProv']['attributes']['tDn']
                            if contract_dn: contract_dict[contract_dn]['pepg'].append(epg_dn)
                        if 'fvRsCons' in child:
                            contract_dn = child['fvRsCons']['attributes']['tDn']
                            if contract_dn: contract_dict[contract_dn]['cepg'].append(epg_dn)

        url = '/api/class/l3extInstP.json?rsp-subtree=full&rsp-subtree-class=fvRsProv,fvRsCons'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        l3exts = json.loads(resp.text)['imdata']

        for l3ext in l3exts:
            if 'l3extInstP' in l3ext:
                l3ext_dn = l3ext['l3extInstP']['attributes']['dn']
                l3ext_tenant = l3ext_dn.split('uni/tn-')[1].split('/')[0]
                l3ext_name = l3ext['l3extInstP']['attributes']['name']
                if 'children' in l3ext['l3extInstP']:
                    l3ext_children = l3ext['l3extInstP']['children']
                    for child in l3ext_children:
                        if 'fvRsProv' in child:
                            contract_dn = child['fvRsProv']['attributes']['tDn']
                            if contract_dn: contract_dict[contract_dn]['pepg'].append(l3ext_dn)
                        if 'fvRsCons' in child:
                            contract_dn = child['fvRsCons']['attributes']['tDn']
                            if contract_dn: contract_dict[contract_dn]['cepg'].append(l3ext_dn)

        return contract_dict

    def get_filter_dict(self):
        filter_dict = {}
        url = '/api/class/vzFilter.json?rsp-subtree=full&rsp-subtree-class=vzEntry'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        filters = json.loads(resp.text)['imdata']

        for filter in filters:
            if 'vzFilter' in filter:
                filter_dn = str(filter['vzFilter']['attributes']['dn'])
                filter_dict[filter_dn] = {}
                filter_dict[filter_dn]['name'] = str(filter['vzFilter']['attributes']['name'])
                if 'children' in filter['vzFilter']:
                    filter_dict[filter_dn]['entries'] = filter['vzFilter']['children']
                else:
                    filter_dict[filter_dn]['entries'] = []
        return filter_dict

    def get_interface_dict(self):
        intf_dict = {}
        node_dict = {}
        fex_dict = {}
        switch_dict = self.get_switch_dict()

        # get nodes
        url = '/api/node/mo/uni/infra/.json?rsp-subtree=full&rsp-subtree-class=infraNodeP'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        infra = json.loads(resp.text)['imdata'][0]

        if 'children' in infra['infraInfra']:
            nodeps = infra['infraInfra']['children']
            for nodep in nodeps:
                if 'infraNodeP' in nodep:
                    node_name = str(nodep['infraNodeP']['attributes']['name'])
                    nodes = []
                    if 'children' in nodep['infraNodeP']:
                        nodep_children = nodep['infraNodeP']['children']
                        for leafs in nodep_children:
                            if 'infraLeafS' in leafs:
                                if 'children' in leafs['infraLeafS']:
                                    leafs_children = leafs['infraLeafS']['children']
                                    for nodeblk in leafs_children:
                                        if 'infraNodeBlk' in nodeblk:
                                            node1 = str(nodeblk['infraNodeBlk']['attributes']['from_'])
                                            node2 = str(nodeblk['infraNodeBlk']['attributes']['to_'])
                                            for node in range(int(node1), int(node2) + 1, 1):
                                                nodes.append(str(node))
                        for accportp in nodep_children:
                            if 'infraRsAccPortP' in accportp:
                                accportp_rn = str(accportp['infraRsAccPortP']['attributes']['tDn'].split('/')[2])
                                node_dict[accportp_rn] = nodes

        # get interfaces
        url = '/api/node/mo/uni/infra/.json?rsp-subtree=full&rsp-subtree-class=infraAccPortP'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        infra = json.loads(resp.text)['imdata'][0]

        if 'children' in infra['infraInfra']:
            accportps = infra['infraInfra']['children']
            for accportp in accportps:
                if 'infraAccPortP' in accportp:
                    accportp_rn = str(accportp['infraAccPortP']['attributes']['rn'])
                    accportp_name = str(accportp['infraAccPortP']['attributes']['name'])
                    if accportp_rn in node_dict.keys():
                        intf_nodes = node_dict[accportp_rn]
                    else:
                        continue
                    if 'children' in accportp['infraAccPortP']:
                        accportp_children = accportp['infraAccPortP']['children']
                        for hports in accportp_children:
                            if 'infraHPortS' in hports:
                                ipg_name = ''
                                ipg_type = ''
                                fex_id = ''
                                hport_name = hports['infraHPortS']['attributes']['name']
                                if 'children' in hports['infraHPortS']:
                                    hports_children = hports['infraHPortS']['children']
                                    for accbasegrp in hports_children:
                                        if 'infraRsAccBaseGrp' in accbasegrp:
                                            if str(accbasegrp['infraRsAccBaseGrp']['attributes']['state']) == 'formed':
                                                accbasegrp_dn = str(
                                                    accbasegrp['infraRsAccBaseGrp']['attributes']['tDn'])
                                                accbasegrp_rn = str(
                                                    accbasegrp['infraRsAccBaseGrp']['attributes']['tDn'].split('/')[2])
                                                accport_tcl = str(accbasegrp['infraRsAccBaseGrp']['attributes']['tCl'])
                                                if accport_tcl == 'infraAccBndlGrp':
                                                    ipg_name = accbasegrp_dn.split('uni/infra/funcprof/accbundle-')[1]
                                                    ipg_type = 'accbundle'
                                                elif accport_tcl == 'infraAccPortGrp':
                                                    ipg_name = accbasegrp_dn.split('uni/infra/funcprof/accportgrp-')[1]
                                                    ipg_type = 'accportgrp'
                                                elif accport_tcl == 'infraFexBndlGrp':
                                                    fex_id = str(accbasegrp['infraRsAccBaseGrp']['attributes']['fexId'])
                                                    fex_dict[accbasegrp_rn] = fex_id
                                                    node_dict[accbasegrp_rn] = intf_nodes
                                                    ipg_name = str(
                                                        accbasegrp_dn.split('/fexprof-')[1].split('/')[0]) + '/' + str(
                                                        accbasegrp_dn.split('/fexbundle-')[1])
                                                    ipg_type = 'fexbundle'
                                    for portblk in hports_children:
                                        if 'infraPortBlk' in portblk:
                                            port1 = str(portblk['infraPortBlk']['attributes']['fromPort'])
                                            port2 = str(portblk['infraPortBlk']['attributes']['toPort'])
                                            mod = str(portblk['infraPortBlk']['attributes']['fromCard'])
                                            descr = str(portblk['infraPortBlk']['attributes']['descr'])
                                            portblk_name = str(portblk['infraPortBlk']['attributes']['name'])
                                            portblk_port = [str(port) for port in range(int(port1), int(port2) + 1, 1)]
                                            for port in portblk_port:
                                                for node in intf_nodes:
                                                    if node in switch_dict.keys():
                                                        switch_name = switch_dict[node]['name']
                                                    else:
                                                        switch_name = ''
                                                    intf_name = node + '-eth' + mod + '/' + str(port)
                                                    intf_dict[intf_name] = {}
                                                    intf_dict[intf_name]['name'] = intf_name
                                                    intf_dict[intf_name]['descr'] = descr
                                                    intf_dict[intf_name]['switch'] = switch_name
                                                    intf_dict[intf_name]['node'] = node
                                                    intf_dict[intf_name]['fexid'] = fex_id
                                                    intf_dict[intf_name]['ipg'] = ipg_name
                                                    intf_dict[intf_name]['leaf_profile'] = accportp_name
                                                    intf_dict[intf_name]['selector'] = hport_name
                                                    intf_dict[intf_name]['blockname'] = portblk_name
                                                    intf_dict[intf_name]['blockport'] = portblk_port
                                                    intf_dict[intf_name]['type'] = ipg_type
                                                    intf_dict[intf_name]['aep'] = ''
                                                    intf_dict[intf_name]['domain'] = []
                                                    intf_dict[intf_name]['poolname'] = []
                                                    intf_dict[intf_name]['domain_type'] = []
                                                    intf_dict[intf_name]['poolvlan'] = []
                                                    intf_dict[intf_name]['mode'] = []
                                                    intf_dict[intf_name]['encap'] = []
                                                    intf_dict[intf_name]['epg'] = []
                                                    intf_dict[intf_name]['bd'] = []
        # get fex interfaces
        url = '/api/node/mo/uni/infra/.json?rsp-subtree=full&rsp-subtree-class=infraFexP'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        infra = json.loads(resp.text)['imdata'][0]

        if 'children' in infra['infraInfra']:
            accportps = infra['infraInfra']['children']
            for accportp in accportps:
                if 'infraFexP' in accportp:
                    accportp_rn = str(accportp['infraFexP']['attributes']['rn'])
                    accportp_name = str(accportp['infraFexP']['attributes']['name'])
                    # accportp_dn = 'uni/infra/' + accportp_rn
                    if accportp_rn in node_dict.keys():
                        intf_nodes = node_dict[accportp_rn]
                    else:
                        continue
                    if 'children' in accportp['infraFexP']:
                        accportp_children = accportp['infraFexP']['children']
                        for hports in accportp_children:
                            if 'infraHPortS' in hports:
                                hport_name = hports['infraHPortS']['attributes']['name']
                                if 'children' in hports['infraHPortS']:
                                    hports_children = hports['infraHPortS']['children']
                                    ipg_name = ''
                                    fex_id = ''
                                    for accbasegrp in hports_children:
                                        if 'infraRsAccBaseGrp' in accbasegrp:
                                            accbasegrp_dn = str(accbasegrp['infraRsAccBaseGrp']['attributes']['tDn'])
                                            accport_tcl = str(accbasegrp['infraRsAccBaseGrp']['attributes']['tCl'])
                                            fex_id = str(accbasegrp['infraRsAccBaseGrp']['attributes']['fexId'])
                                            if accport_tcl == 'infraAccBndlGrp':
                                                ipg_name = accbasegrp_dn.split('uni/infra/funcprof/accbundle-')[1]
                                            elif accport_tcl == 'infraAccPortGrp':
                                                ipg_name = accbasegrp_dn.split('uni/infra/funcprof/accportgrp-')[1]
                                    for portblk in hports_children:
                                        if 'infraPortBlk' in portblk:
                                            port1 = str(portblk['infraPortBlk']['attributes']['fromPort'])
                                            port2 = str(portblk['infraPortBlk']['attributes']['toPort'])
                                            mod = str(portblk['infraPortBlk']['attributes']['fromCard'])
                                            descr = str(portblk['infraPortBlk']['attributes']['descr'])
                                            portblk_name = str(portblk['infraPortBlk']['attributes']['name'])
                                            portblk_port = [str(port) for port in range(int(port1), int(port2) + 1, 1)]
                                            if accportp_rn in node_dict.keys():
                                                fex = fex_dict[accportp_rn]
                                                for port in portblk_port:
                                                    for node in intf_nodes:
                                                        if node in switch_dict.keys():
                                                            switch_name = switch_dict[node]['name']
                                                        else:
                                                            switch_name = ''
                                                        intf_name = node + '-eth' + fex + '/' + mod + '/' + str(port)
                                                        intf_dict[intf_name] = {}
                                                        intf_dict[intf_name]['name'] = intf_name
                                                        intf_dict[intf_name]['descr'] = descr
                                                        intf_dict[intf_name]['switch'] = switch_name
                                                        intf_dict[intf_name]['node'] = node
                                                        intf_dict[intf_name]['fexid'] = fex_id
                                                        intf_dict[intf_name]['ipg'] = ipg_name
                                                        intf_dict[intf_name]['leaf_profile'] = accportp_name
                                                        intf_dict[intf_name]['selector'] = hport_name
                                                        intf_dict[intf_name]['blockname'] = portblk_name
                                                        intf_dict[intf_name]['blockport'] = portblk_port
                                                        intf_dict[intf_name]['type'] = ''
                                                        intf_dict[intf_name]['aep'] = ''
                                                        intf_dict[intf_name]['domain'] = []
                                                        intf_dict[intf_name]['poolname'] = []
                                                        intf_dict[intf_name]['domain_type'] = []
                                                        intf_dict[intf_name]['poolvlan'] = []
                                                        intf_dict[intf_name]['mode'] = []
                                                        intf_dict[intf_name]['encap'] = []
                                                        intf_dict[intf_name]['epg'] = []
                                                        intf_dict[intf_name]['bd'] = []
        return intf_dict

    def get_intf_dict(self):
        intf_dict = self.get_interface_dict()
        path_dict = self.get_path_dict()
        ipg_dict = self.get_ipg_dict('basic')
        intf_list = []
        for intf_name in intf_dict.keys():
            nodenum = int(intf_dict[intf_name]['name'].split('-')[0])
            portnum = []
            for pnum in intf_dict[intf_name]['name'].split('eth')[1].split('/'):
                if len(pnum) < 2:
                    pnum = '0' + str(pnum)
                portnum.append(pnum)
            portnum = int(''.join(portnum))
            intf_list.append([nodenum, portnum, intf_dict[intf_name]['name']])

        for intf_names in sorted(intf_list):
            intf_name = intf_names[2]
            ipg_name = intf_dict[intf_name]['ipg']
            if ipg_name in ipg_dict.keys():
                intf_dict[intf_name]['type'] = ipg_dict[ipg_name]['type']
                intf_dict[intf_name]['aep'] = ipg_dict[ipg_name]['aep']
                intf_dict[intf_name]['domain'] = ipg_dict[ipg_name]['domain']
                intf_dict[intf_name]['poolname'] = ipg_dict[ipg_name]['poolname']
                intf_dict[intf_name]['domain_type'] = ipg_dict[ipg_name]['domain_type']
                intf_dict[intf_name]['poolvlan'] = ipg_dict[ipg_name]['poolvlan']

            if intf_name in path_dict.keys() or ipg_name in path_dict.keys():

                if intf_name in path_dict.keys():
                    intf_dict[intf_name]['mode'] = path_dict[intf_name]['mode']
                    intf_dict[intf_name]['encap'] = path_dict[intf_name]['encap']
                    intf_dict[intf_name]['epg'] = path_dict[intf_name]['epg']
                    intf_dict[intf_name]['epg_descr'] = path_dict[intf_name]['epg_descr']
                    intf_dict[intf_name]['bd'] = path_dict[intf_name]['bd']

                elif ipg_name in path_dict.keys():
                    intf_dict[intf_name]['mode'] = path_dict[ipg_name]['mode']
                    intf_dict[intf_name]['encap'] = path_dict[ipg_name]['encap']
                    intf_dict[intf_name]['epg'] = path_dict[ipg_name]['epg']
                    intf_dict[intf_name]['epg_descr'] = path_dict[ipg_name]['epg_descr']
                    intf_dict[intf_name]['bd'] = path_dict[ipg_name]['bd']
        return intf_dict

    def get_ipg_name_dict(self):
        ipg_name_dict = {}
        url = '/api/node/class/infraFuncP.json?rsp-subtree=children&' \
              'rsp-subtree-class=infraAccPortGrp,infraAccBndlGrp'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        funcp = json.loads(resp.text)['imdata'][0]
        
        if 'children' in funcp['infraFuncP']:
            ipgs = funcp['infraFuncP']['children']
            for ipg in ipgs:
                if 'infraAccPortGrp' in ipg or "infraAccBndlGrp" in ipg:
                    ipg_name = str(ipg[ipg.keys()[0]]['attributes']['name'])
                    ipg_rn = str(ipg[ipg.keys()[0]]['attributes']['rn'])
                    ipg_name_dict[ipg_name] = {}
                    ipg_name_dict[ipg_name]['name'] = str(ipg[ipg.keys()[0]]['attributes']['name'])
                    ipg_name_dict[ipg_name]['descr'] = str(ipg[ipg.keys()[0]]['attributes']['descr'])
                    ipg_type = str(ipg_rn.split('-')[0])
                    if 'lagT' in ipg[ipg.keys()[0]]['attributes']:
                        ipg_name_dict[ipg_name]['type'] = ipg_type + '-' + str(ipg[ipg.keys()[0]]['attributes']['lagT'])
                    else:
                        ipg_name_dict[ipg_name]['type'] = ipg_type
        return ipg_name_dict

    def get_ipg_dict(self, limit=None):
        ipg_dict = {}
        url = '/api/node/class/infraFuncP.json?query-target=self&rsp-subtree=full&' \
              'rsp-subtree-class=infraRsAttEntP,infraRsCdpIfPol,infraRsHIfPol,infraRsLldpIfPol,infraRsLacpPol,infraRsMcpIfPol,infraRsL2IfPol'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        funcp = json.loads(resp.text)['imdata'][0]

        if 'children' in funcp['infraFuncP']:
            ipgs = funcp['infraFuncP']['children']
            for ipg in ipgs:
                ipg_lacp = 'N/A'
                ipg_aep = ''
                ipg_speed = ''
                ipg_cdp = ''
                ipg_lldp = ''
                ipg_mcp = ''
                ipg_l2int = ''

                if 'infraAccPortGrp' in ipg or "infraAccBndlGrp" in ipg:
                    ipgkey = list(ipg.keys())[0]
                    ipg_name = str(ipg[ipgkey]['attributes']['name'])
                    ipg_descr = str(ipg[ipgkey]['attributes']['descr'])
                    ipg_dict[ipg_name] = {}
                    ipg_rn = str(ipg[ipgkey]['attributes']['rn'])
                    ipg_type = str(ipg_rn.split('-')[0])
                    if 'lagT' in ipg[ipgkey]['attributes']: ipg_type = ipg_type + '-' + str(
                        ipg[ipgkey]['attributes']['lagT'])

                    if 'children' in ipg[ipgkey]:
                        ipg_children = ipg[ipgkey]['children']
                        for child in ipg_children:
                            childkey = list(child.keys())[0]
                            child_dn = child[childkey]['attributes']['tDn']
                            if 'uni/infra/lacplagp-' in child_dn: ipg_lacp = str(
                                child_dn.split('uni/infra/lacplagp-')[1])
                            if 'uni/infra/attentp-' in child_dn: ipg_aep = str(child_dn.split('uni/infra/attentp-')[1])
                            if 'uni/infra/hintfpol-' in child_dn: ipg_speed = str(
                                child_dn.split('uni/infra/hintfpol-')[1])
                            if 'uni/infra/cdpIfP-' in child_dn: ipg_cdp = str(child_dn.split('uni/infra/cdpIfP-')[1])
                            if 'uni/infra/lldpIfP-' in child_dn: ipg_lldp = str(child_dn.split('uni/infra/lldpIfP-')[1])
                            if 'uni/infra/mcpIfP-' in child_dn: ipg_mcp = str(child_dn.split('uni/infra/mcpIfP-')[1])
                            if 'uni/infra/l2IfP-' in child_dn: ipg_l2int = str(child_dn.split('uni/infra/l2IfP-')[1])
                        ipg_dict[ipg_name]['name'] = ipg_name
                        ipg_dict[ipg_name]['descr'] = ipg_descr
                        ipg_dict[ipg_name]['lacp'] = ipg_lacp
                        ipg_dict[ipg_name]['aep'] = ipg_aep
                        ipg_dict[ipg_name]['speed'] = ipg_speed
                        ipg_dict[ipg_name]['cdp'] = ipg_cdp
                        ipg_dict[ipg_name]['lldp'] = ipg_lldp
                        ipg_dict[ipg_name]['type'] = ipg_type
                        ipg_dict[ipg_name]['mcp'] = ipg_mcp
                        ipg_dict[ipg_name]['l2int'] = ipg_l2int
                        ipg_dict[ipg_name]['rn'] = ipg_rn
                        ipg_dict[ipg_name]['interfaces'] = []
                        ipg_dict[ipg_name]['intf_descr'] = []
                        ipg_dict[ipg_name]['nodes'] = []
                        ipg_dict[ipg_name]['switches'] = []
                        ipg_dict[ipg_name]['ipg_nodes'] = []
                        ipg_dict[ipg_name]['ipg_switches'] = []
                        ipg_dict[ipg_name]['domain'] = []
                        ipg_dict[ipg_name]['poolname'] = []
                        ipg_dict[ipg_name]['domain_type'] = []
                        ipg_dict[ipg_name]['poolvlan'] = []

        # add domain information to ipg_dict

        aep_dict = self.get_aep_dict()
        for aep_name in aep_dict.keys():
            ipg_names = aep_dict[aep_name]['ipg']
            for ipg_name in ipg_names:
                if ipg_name in ipg_dict.keys():
                    ipg_dict[ipg_name]['domain'] = aep_dict[aep_name]['domain']
                    ipg_dict[ipg_name]['poolname'] = aep_dict[aep_name]['poolname']
                    ipg_dict[ipg_name]['domain_type'] = aep_dict[aep_name]['domain_type']
                    ipg_dict[ipg_name]['poolvlan'] = aep_dict[aep_name]['poolvlan']

        # add interfaces to ipg_dict
        if limit is None:
            intf_dict = self.get_interface_dict()
            for intf in intf_dict.keys():
                ipg_name = intf_dict[intf]['ipg']
                if ipg_name in ipg_dict.keys():
                    ipg_dict[ipg_name]['interfaces'].append(intf_dict[intf]['name'])
                    ipg_dict[ipg_name]['intf_descr'].append(intf_dict[intf]['descr'])
                    ipg_dict[ipg_name]['nodes'].append(intf_dict[intf]['node'])
                    ipg_dict[ipg_name]['switches'].append(intf_dict[intf]['switch'])
                    if intf_dict[intf]['node'] not in ipg_dict[ipg_name]['ipg_nodes']:
                        ipg_dict[ipg_name]['ipg_nodes'].append(intf_dict[intf]['node'])
                    if intf_dict[intf]['switch'] not in ipg_dict[ipg_name]['ipg_switches']:
                        ipg_dict[ipg_name]['ipg_switches'].append(intf_dict[intf]['switch'])

        return ipg_dict

    def get_fex_dict(self):
        fex_dict = {}
        intf_dict = self.get_interface_dict()
        url = '/api/node/class/infraFexP.json?query-target=self&rsp-subtree=full&' \
              'rsp-subtree-class=infraFexBndlGrp'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        fexps = json.loads(resp.text)['imdata']

        for fexp in fexps:
            fexp_name = str(fexp['infraFexP']['attributes']['name'])
            if 'children' in fexp['infraFexP']:
                fexs = fexp['infraFexP']['children']
                for fex in fexs:
                    if 'infraFexBndlGrp' in fex:
                        fex_name = fexp_name + '/' + str(fex['infraFexBndlGrp']['attributes']['name'])
                        fex_descr = str(fex['infraFexBndlGrp']['attributes']['descr'])
                        fex_dict[fex_name] = {}
                        fex_dict[fex_name]['name'] = fexp_name
                        fex_dict[fex_name]['ipg'] = str(fex['infraFexBndlGrp']['attributes']['name'])
                        fex_dict[fex_name]['descr'] = fex_descr
                        fex_dict[fex_name]['type'] = 'fexbundle'
                        fex_dict[fex_name]['interfaces'] = []
                        fex_dict[fex_name]['intf_descr'] = []
                        fex_dict[fex_name]['fexid'] = []
                        fex_dict[fex_name]['nodes'] = []
                        fex_dict[fex_name]['switches'] = []

        for intf in intf_dict.keys():
            fex_name = intf_dict[intf]['ipg']
            if fex_name in fex_dict.keys():
                fex_dict[fex_name]['interfaces'].append(intf_dict[intf]['name'])
                fex_dict[fex_name]['intf_descr'].append(intf_dict[intf]['descr'])
                if intf_dict[intf]['fexid'] not in fex_dict[fex_name]['fexid']:
                    fex_dict[fex_name]['fexid'].append(intf_dict[intf]['fexid'])
                if intf_dict[intf]['node'] not in fex_dict[fex_name]['nodes']:
                    fex_dict[fex_name]['nodes'].append(intf_dict[intf]['node'])
                if intf_dict[intf]['switch'] not in fex_dict[fex_name]['switches']:
                    fex_dict[fex_name]['switches'].append(intf_dict[intf]['switch'])

        return fex_dict

    def get_path_dict(self):
        path_dict = {}
        rsbd_dict = self.get_rsbd_dict()
        epg_name_dict = self.get_epg_name_dict()
        url = '/api/class/fvIfConn.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        paths = json.loads(resp.text)['imdata']

        for path in paths:
            if "fvIfConn" in path:
                path_name = ''
                path_dn = str(path['fvIfConn']['attributes']['dn'])
                path_mode = str(path['fvIfConn']['attributes']['mode'])
                path_encap = str(path['fvIfConn']['attributes']['encap'])
                path_imedcy = str(path['fvIfConn']['attributes']['resImedcy'])
                path_node = str(path_dn.split('/node-')[1].split('/')[0])
                if '/stpathatt-' in path_dn:
                    path_name = str(path_dn.split('/stpathatt-[')[1].split(']')[0])
                    if len(path_name.split('/')) > 1:
                        path_name = path_node + '-' + 'eth' + str(path_dn.split('/stpathatt-[eth')[1].split(']')[0])
                elif '/extstpathatt-' in path_dn:
                    path_name = str(path_dn.split('/extstpathatt-[')[1].split(']')[0])
                    if len(path_name.split('/')) > 1:
                        path_fex = 'eth' + str(path_dn.split(']-extchid-')[1].split('/')[0]) + '/'
                        path_name = path_node + '-' + path_fex + str(
                            path_dn.split('/extstpathatt-[eth')[1].split(']')[0])
                elif '/dyatt-' in path_dn:
                    path_name = str(path_dn.split('/pathep-[')[1].split(']')[0])
                    if len(path_name.split('/')) > 1:
                        path_name = path_node + '-' + 'eth' + str(path_dn.split('/pathep-[eth')[1].split(']')[0])
                if path_name not in path_dict.keys():
                    path_dict[path_name] = {}
                    path_dict[path_name]['name'] = path_name
                    path_dict[path_name]['descr'] = ''
                    path_dict[path_name]['dn'] = []
                    path_dict[path_name]['mode'] = []
                    path_dict[path_name]['encap'] = []
                    path_dict[path_name]['epg'] = []
                    path_dict[path_name]['epg_descr'] = []
                    path_dict[path_name]['bd'] = []
                if 'unknown' == path_encap: path_encap = 'N/A'
                path_dict[path_name]['dn'].append(path_dn)

                if 'uni/epp/fv-' in path_dn and '/ap-' in path_dn and '/epg-' in path_dn:
                    path_locale = str(path_dn.split('uni/epp/fv-[')[1].split(']')[0])
                    path_dict[path_name]['mode'].append(path_mode)
                    path_dict[path_name]['encap'].append(path_encap)
                    path_dict[path_name]['epg'].append(path_locale)
                    if path_locale in epg_name_dict.keys():
                        path_dict[path_name]['epg_descr'].append(epg_name_dict[path_locale]['descr'])
                    else:
                        path_dict[path_name]['epg_descr'].append('')
                    if path_locale in rsbd_dict.keys():
                        path_dict[path_name]['bd'].append(rsbd_dict[path_locale]['name'])
                    else:
                        path_dict[path_name]['bd'].append('')
                if 'uni/epp/fv-' in path_dn and '/lDevVip-' in path_dn and ']-ctx-[' in path_dn and ']-bd-[' in path_dn and '/BD-' in path_dn:
                    path_locale = str(path_dn.split('uni/epp/fv-[')[1])
                    path_dict[path_name]['mode'].append(path_mode)
                    path_dict[path_name]['encap'].append(path_encap)
                    path_dict[path_name]['epg'].append(path_locale.split('uni/ldev-[')[1].split(']')[0])
                    path_dict[path_name]['epg_descr'].append('L4_L7_Device')
                    path_bd = path_locale.split(']-bd-[')[1].split('/BD-')[1].split(']')[0]
                    path_bd_tenant = path_locale.split(']-bd-[')[1].split('/tn-')[1].split('/')[0]
                    if path_bd_tenant == 'common': path_bd = '*' + path_bd
                    path_dict[path_name]['bd'].append(path_bd)
                if 'uni/epp/rtd-' in path_dn and '/out-' in path_dn and '/instP-' in path_dn:
                    path_locale = str(path_dn.split('uni/epp/rtd-[')[1].split(']')[0])
                    path_dict[path_name]['mode'].append(path_mode)
                    path_dict[path_name]['encap'].append(path_encap)
                    path_dict[path_name]['epg'].append(path_locale)
                    path_dict[path_name]['epg_descr'].append('External_EPG')
                    path_dict[path_name]['bd'].append('N/A')
        return path_dict

    def get_vlan_dict(self):
        vlan_dict = {}
        intf_dict = self.get_intf_dict()
        ipg_dict = self.get_ipg_dict('basic')

        for intf_name in intf_dict.keys():
            for n, path_encap in enumerate(intf_dict[intf_name]['encap']):
                if path_encap not in vlan_dict.keys():
                    vlan_dict[path_encap] = {}
                    vlan_dict[path_encap]['name'] = path_encap
                    vlan_dict[path_encap]['id'] = '0'
                    vlan_dict[path_encap]['intf_descr'] = []
                    vlan_dict[path_encap]['interfaces'] = []
                    vlan_dict[path_encap]['dn'] = []
                    vlan_dict[path_encap]['mode'] = []
                    vlan_dict[path_encap]['epg'] = []
                    vlan_dict[path_encap]['epg_descr'] = []
                    vlan_dict[path_encap]['bd'] = []
                    vlan_dict[path_encap]['switch'] = []
                    vlan_dict[path_encap]['node'] = []
                    vlan_dict[path_encap]['ipg'] = []
                    vlan_dict[path_encap]['type'] = []
                    vlan_dict[path_encap]['aep'] = []
                    vlan_dict[path_encap]['domain'] = []
                    vlan_dict[path_encap]['poolname'] = []
                    vlan_dict[path_encap]['domain_type'] = []
                    vlan_dict[path_encap]['poolvlan'] = []

                if 'unknown' in path_encap: vlan_dict[path_encap]['name'] = ''
                if 'vlan-' in path_encap: vlan_dict[path_encap]['id'] = path_encap.split('vlan-')[1]
                vlan_dict[path_encap]['interfaces'].append(intf_dict[intf_name]['name'])
                vlan_dict[path_encap]['intf_descr'].append(intf_dict[intf_name]['descr'])
                vlan_dict[path_encap]['mode'].append(intf_dict[intf_name]['mode'][n])
                vlan_dict[path_encap]['epg'].append(intf_dict[intf_name]['epg'][n])
                vlan_dict[path_encap]['epg_descr'].append(intf_dict[intf_name]['epg_descr'][n])
                vlan_dict[path_encap]['bd'].append(intf_dict[intf_name]['bd'][n])
                vlan_dict[path_encap]['switch'].append(intf_dict[intf_name]['switch'])
                vlan_dict[path_encap]['node'].append(intf_dict[intf_name]['node'])
                vlan_dict[path_encap]['ipg'].append(intf_dict[intf_name]['ipg'])

                # add domain information from ipg_dict
                ipg_name = intf_dict[intf_name]['ipg']
                if ipg_name in ipg_dict.keys():
                    vlan_dict[path_encap]['aep'].append(ipg_dict[ipg_name]['aep'])
                    vlan_dict[path_encap]['domain'].extend(ipg_dict[ipg_name]['domain'])
                    vlan_dict[path_encap]['poolname'].extend(ipg_dict[ipg_name]['poolname'])
                    vlan_dict[path_encap]['domain_type'].extend(ipg_dict[ipg_name]['domain_type'])
                    vlan_dict[path_encap]['poolvlan'].extend(ipg_dict[ipg_name]['poolvlan'])
        return vlan_dict

    def get_vlanpool_name_dict(self):
        vlanpool_name_dict = {}
        url = '/api/class/fvnsVlanInstP.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        vlanpools = json.loads(resp.text)['imdata']
        
        for pool in vlanpools:
            if "fvnsVlanInstP" in pool:
                pool_dn = str(pool['fvnsVlanInstP']['attributes']['dn'])
                vlanpool_name_dict[pool_dn] = {}
                vlanpool_name_dict[pool_dn]['name'] = str(pool['fvnsVlanInstP']['attributes']['name'])
                vlanpool_name_dict[pool_dn]['descr'] = str(pool['fvnsVlanInstP']['attributes']['descr'])
                vlanpool_name_dict[pool_dn]['type'] = str(pool['fvnsVlanInstP']['attributes']['allocMode'])
        return vlanpool_name_dict

    def get_vlanpool_dict(self):
        vlanpool_dict = {}
        url = '/api/class/fvnsVlanInstP.json?rsp-subtree=full&' \
              'rsp-subtree-class=fvnsEncapBlk,fvnsRtVlanNs'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        vlanpools = json.loads(resp.text)['imdata']
        
        for pool in vlanpools:
            if "fvnsVlanInstP" in pool:
                pool_dn = str(pool['fvnsVlanInstP']['attributes']['dn'])
                vlanpool_dict[pool_dn] = {}
                vlanpool_dict[pool_dn]['name'] = str(pool['fvnsVlanInstP']['attributes']['name'])
                vlanpool_dict[pool_dn]['descr'] = str(pool['fvnsVlanInstP']['attributes']['descr'])
                vlanpool_dict[pool_dn]['type'] = str(pool['fvnsVlanInstP']['attributes']['allocMode'])
                vlanpool_dict[pool_dn]['domain'] = []
                vlanpool_dict[pool_dn]['domain_type'] = []
                vlanpool_dict[pool_dn]['domain_dn'] = []
                vlanpool_dict[pool_dn]['vlan'] = []
                vlanpool_dict[pool_dn]['poolvlan'] = []
                vlanid_list = []
                if 'children' in pool['fvnsVlanInstP']:
                    pool_children = pool['fvnsVlanInstP']['children']
                    for child in pool_children:
                        if 'fvnsRtVlanNs' in child:
                            if str(child['fvnsRtVlanNs']['attributes']['tDn']):
                                dom_dn = str(child['fvnsRtVlanNs']['attributes']['tDn'])
                                dom_type = str(child['fvnsRtVlanNs']['attributes']['tCl'])
                                vlanpool_dict[pool_dn]['domain_dn'].append(dom_dn)
                                vlanpool_dict[pool_dn]['domain_type'].append(dom_type)
                                if 'uni/phys-' in dom_dn:
                                    dom_name = str(dom_dn.split('uni/phys-')[1])
                                elif 'uni/l2dom-' in dom_dn:
                                    dom_name = str(dom_dn.split('uni/l2dom-')[1])
                                elif 'uni/l3dom-' in dom_dn:
                                    dom_name = str(dom_dn.split('uni/l3dom-')[1])
                                elif 'uni/vmmp-VMware/dom-' in dom_dn:
                                    dom_name = str(dom_dn.split('uni/vmmp-VMware/dom-')[1])
                                else:
                                    dom_name = dom_dn
                                vlanpool_dict[pool_dn]['domain'].append(dom_name)
                        if 'fvnsEncapBlk' in child:
                            vlanid_from = int(str(child['fvnsEncapBlk']['attributes']['from']).split('vlan-')[1])
                            vlanid_to = int(str(child['fvnsEncapBlk']['attributes']['to']).split('vlan-')[1])
                            for vlanid in range(vlanid_from, vlanid_to + 1, 1):
                                vlanid_list.append(vlanid)
                vlanpool_dict[pool_dn]['vlan'] = sorted(vlanid_list)

                # compress the vlanid_list
                vlanid_from_list = []
                vlanid_to_list = []

                vlanid_list = sorted(vlanid_list)
                for n in range(0, len(vlanid_list), 1):
                    if n == 0:
                        vlanid_from_list.append(vlanid_list[n])

                    if n != len(vlanid_list) - 1:
                        if vlanid_list[n] + 1 == vlanid_list[n + 1]:
                            continue
                        else:
                            vlanid_from_list.append(vlanid_list[n + 1])
                            vlanid_to_list.append(vlanid_list[n])
                    if n == len(vlanid_list) - 1:
                        vlanid_to_list.append(vlanid_list[n])

                vlanid_range_list = []
                for n in range(0, len(vlanid_from_list), 1):
                    if vlanid_from_list[n] == vlanid_to_list[n]:
                        vlanid_range_list.append(str(vlanid_from_list[n]))
                    else:
                        vlanid_range_list.append(
                            str(vlanid_from_list[n]) + '-' + str(vlanid_to_list[n]))
                vlanpool_dict[pool_dn]['poolvlan'] = vlanid_range_list
        return vlanpool_dict

    def get_domain_name_dict(self):
        domain_name_dict = {}
        url = '/api/class/physDomP.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        domains = json.loads(resp.text)['imdata']
        
        for domain in domains:
            if "physDomP" in domain:
                domain_dn = str(domain['physDomP']['attributes']['dn'])
                domain_name_dict[domain_dn] = {}
                domain_name_dict[domain_dn]['name'] = str(domain['physDomP']['attributes']['name'])
                domain_name_dict[domain_dn]['type'] = 'physDomP'

        url = '/api/class/vmmDomP.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        domains = json.loads(resp.text)['imdata']
        
        for domain in domains:
            if "vmmDomP" in domain:
                domain_dn = str(domain['vmmDomP']['attributes']['dn'])
                domain_name_dict[domain_dn] = {}
                domain_name_dict[domain_dn]['name'] = str(domain['vmmDomP']['attributes']['name'])
                domain_name_dict[domain_dn]['type'] = 'vmmDomP'

        url = '/api/class/l3extDomP.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        domains = json.loads(resp.text)['imdata']
        
        for domain in domains:
            if "l3extDomP" in domain:
                domain_dn = str(domain['l3extDomP']['attributes']['dn'])
                domain_name_dict[domain_dn] = {}
                domain_name_dict[domain_dn]['name'] = str(domain['l3extDomP']['attributes']['name'])
                domain_name_dict[domain_dn]['type'] = 'l3extDomP'

        url = '/api/class/l2extDomP.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        domains = json.loads(resp.text)['imdata']
        
        for domain in domains:
            if "l2extDomP" in domain:
                domain_dn = str(domain['l2extDomP']['attributes']['dn'])
                domain_name_dict[domain_dn] = {}
                domain_name_dict[domain_dn]['name'] = str(domain['l2extDomP']['attributes']['name'])
                domain_name_dict[domain_dn]['type'] = 'l2extDomP'
        return domain_name_dict

    def get_domain_dict(self):
        domain_dict = {}
        vlanpool_dict = self.get_vlanpool_dict()
        url = '/api/class/physDomP.json?rsp-subtree=full&rsp-subtree-class=infraRtDomP,infraRsVlanNs'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        domains = json.loads(resp.text)['imdata']
        
        for domain in domains:
            if "physDomP" in domain:
                domain_dn = str(domain['physDomP']['attributes']['dn'])
                domain_dict[domain_dn] = {}
                domain_dict[domain_dn]['name'] = str(domain['physDomP']['attributes']['name'])
                domain_dict[domain_dn]['type'] = 'physDomP'
                domain_dict[domain_dn]['aep'] = []
                domain_dict[domain_dn]['poolname'] = ''
                domain_dict[domain_dn]['poolvlan'] = []
                domain_dict[domain_dn]['vlan'] = []
                if 'children' in domain['physDomP']:
                    domain_children = domain['physDomP']['children']
                    for child in domain_children:
                        if 'infraRsVlanNs' in child:
                            if str(child['infraRsVlanNs']['attributes']['tDn']):
                                vlanpool_dn = str(child['infraRsVlanNs']['attributes']['tDn'])
                                if vlanpool_dn in vlanpool_dict.keys():
                                    domain_dict[domain_dn]['poolname'] = vlanpool_dict[vlanpool_dn]['name']
                                    domain_dict[domain_dn]['poolvlan'] = vlanpool_dict[vlanpool_dn]['poolvlan']
                                    domain_dict[domain_dn]['vlan'] = vlanpool_dict[vlanpool_dn]['vlan']
                        if 'infraRtDomP' in child:
                            if str(child['infraRtDomP']['attributes']['tDn']):
                                aep_dn = str(child['infraRtDomP']['attributes']['tDn'])
                                domain_dict[domain_dn]['aep'].append(aep_dn.split('uni/infra/attentp-')[1])

        url = '/api/class/vmmDomP.json?rsp-subtree=full&rsp-subtree-class=infraRtDomP,infraRsVlanNs'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        domains = json.loads(resp.text)['imdata']
        
        for domain in domains:
            if "vmmDomP" in domain:
                domain_dn = str(domain['vmmDomP']['attributes']['dn'])
                domain_dict[domain_dn] = {}
                domain_dict[domain_dn]['name'] = str(domain['vmmDomP']['attributes']['name'])
                domain_dict[domain_dn]['type'] = 'vmmDomP'
                domain_dict[domain_dn]['aep'] = []
                domain_dict[domain_dn]['poolname'] = ''
                domain_dict[domain_dn]['poolvlan'] = []
                domain_dict[domain_dn]['vlan'] = []
                if 'children' in domain['vmmDomP']:
                    domain_children = domain['vmmDomP']['children']
                    for child in domain_children:
                        if 'infraRsVlanNs' in child:
                            if str(child['infraRsVlanNs']['attributes']['tDn']):
                                vlanpool_dn = str(child['infraRsVlanNs']['attributes']['tDn'])
                                if vlanpool_dn in vlanpool_dict.keys():
                                    domain_dict[domain_dn]['poolname'] = vlanpool_dict[vlanpool_dn]['name']
                                    domain_dict[domain_dn]['poolvlan'] = vlanpool_dict[vlanpool_dn]['poolvlan']
                                    domain_dict[domain_dn]['vlan'] = vlanpool_dict[vlanpool_dn]['vlan']
                            if 'infraRtDomP' in child:
                                if str(child['infraRtDomP']['attributes']['tDn']):
                                    aep_dn = str(child['infraRtDomP']['attributes']['tDn'])
                                    domain_dict[domain_dn]['aep'].append(aep_dn.split('uni/infra/attentp-')[1])

        url = '/api/class/l3extDomP.json?rsp-subtree=full&rsp-subtree-class=infraRtDomP,infraRsVlanNs'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        domains = json.loads(resp.text)['imdata']
        
        for domain in domains:
            if "l3extDomP" in domain:
                domain_dn = str(domain['l3extDomP']['attributes']['dn'])
                domain_dict[domain_dn] = {}
                domain_dict[domain_dn]['name'] = str(domain['l3extDomP']['attributes']['name'])
                domain_dict[domain_dn]['type'] = 'l3extDomP'
                domain_dict[domain_dn]['aep'] = []
                domain_dict[domain_dn]['poolname'] = ''
                domain_dict[domain_dn]['poolvlan'] = []
                domain_dict[domain_dn]['vlan'] = []
                if 'children' in domain['l3extDomP']:
                    domain_children = domain['l3extDomP']['children']
                    for child in domain_children:
                        if 'infraRsVlanNs' in child:
                            if str(child['infraRsVlanNs']['attributes']['tDn']):
                                vlanpool_dn = str(child['infraRsVlanNs']['attributes']['tDn'])
                                if vlanpool_dn in vlanpool_dict.keys():
                                    domain_dict[domain_dn]['poolname'] = vlanpool_dict[vlanpool_dn]['name']
                                    domain_dict[domain_dn]['poolvlan'] = vlanpool_dict[vlanpool_dn]['poolvlan']
                                    domain_dict[domain_dn]['vlan'] = vlanpool_dict[vlanpool_dn]['vlan']
                        if 'infraRtDomP' in child:
                            if str(child['infraRtDomP']['attributes']['tDn']):
                                aep_dn = str(child['infraRtDomP']['attributes']['tDn'])
                                domain_dict[domain_dn]['aep'].append(aep_dn.split('uni/infra/attentp-')[1])

        url = '/api/class/l2extDomP.json?rsp-subtree=full&rsp-subtree-class=infraRtDomP,infraRsVlanNs'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        domains = json.loads(resp.text)['imdata']
        
        for domain in domains:
            if "l2extDomP" in domain:
                domain_dn = str(domain['l2extDomP']['attributes']['dn'])
                domain_dict[domain_dn] = {}
                domain_dict[domain_dn]['name'] = str(domain['l2extDomP']['attributes']['name'])
                domain_dict[domain_dn]['type'] = 'l2extDomP'
                domain_dict[domain_dn]['aep'] = []
                domain_dict[domain_dn]['poolname'] = ''
                domain_dict[domain_dn]['poolvlan'] = []
                domain_dict[domain_dn]['vlan'] = []
                if 'children' in domain['l2extDomP']:
                    domain_children = domain['l2extDomP']['children']
                    for child in domain_children:
                        if 'infraRsVlanNs' in child:
                            if str(child['infraRsVlanNs']['attributes']['tDn']):
                                vlanpool_dn = str(child['infraRsVlanNs']['attributes']['tDn'])
                                if vlanpool_dn in vlanpool_dict.keys():
                                    domain_dict[domain_dn]['poolname'] = vlanpool_dict[vlanpool_dn]['name']
                                    domain_dict[domain_dn]['poolvlan'] = vlanpool_dict[vlanpool_dn]['poolvlan']
                                    domain_dict[domain_dn]['vlan'] = vlanpool_dict[vlanpool_dn]['vlan']
                        if 'infraRtDomP' in child:
                            if str(child['infraRtDomP']['attributes']['tDn']):
                                aep_dn = str(child['infraRtDomP']['attributes']['tDn'])
                                domain_dict[domain_dn]['aep'].append(aep_dn.split('uni/infra/attentp-')[1])
        return domain_dict

    def get_aep_name_dict(self):
        aep_name_dict = {}
        url = '/api/class/infraAttEntityP.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        aeps = json.loads(resp.text)['imdata']
        
        for aep in aeps:
            if "infraAttEntityP" in aep:
                aep_dn = str(aep['infraAttEntityP']['attributes']['dn'])
                aep_name_dict[aep_dn] = {}
                aep_name_dict[aep_dn]['name'] = str(aep['infraAttEntityP']['attributes']['name'])
                aep_name_dict[aep_dn]['descr'] = str(aep['infraAttEntityP']['attributes']['descr'])
        return aep_name_dict

    def get_aep_dict(self):
        aep_dict = {}
        domain_dict = self.get_domain_dict()
        url = '/api/class/infraAttEntityP.json?rsp-subtree=full&' \
              'rsp-subtree-class=infraRsDomP,infraRtAttEntP'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        aeps = json.loads(resp.text)['imdata']
        
        for aep in aeps:
            if "infraAttEntityP" in aep:
                aep_name = str(aep['infraAttEntityP']['attributes']['name'])
                aep_dict[aep_name] = {}
                aep_dict[aep_name]['name'] = str(aep['infraAttEntityP']['attributes']['name'])
                aep_dict[aep_name]['descr'] = str(aep['infraAttEntityP']['attributes']['descr'])
                aep_dict[aep_name]['domain'] = []
                aep_dict[aep_name]['domain_type'] = []
                aep_dict[aep_name]['ipg'] = []
                aep_dict[aep_name]['poolname'] = []
                aep_dict[aep_name]['poolvlan'] = []
                if 'children' in aep['infraAttEntityP']:
                    domain_children = aep['infraAttEntityP']['children']
                    for child in domain_children:
                        if 'infraRtAttEntP' in child:
                            if str(child['infraRtAttEntP']['attributes']['tDn']):
                                ipg_dn = str(child['infraRtAttEntP']['attributes']['tDn'])
                                ipg_name = ''
                                if 'uni/infra/funcprof/accbundle-' in ipg_dn: ipg_name = str(
                                    ipg_dn.split('uni/infra/funcprof/accbundle-')[1])
                                if 'uni/infra/funcprof/accportgrp-' in ipg_dn: ipg_name = str(
                                    ipg_dn.split('uni/infra/funcprof/accportgrp-')[1])
                                if aep_name in aep_dict.keys(): aep_dict[aep_name]['ipg'].append(ipg_name)
                        if 'infraRsDomP' in child:
                            if str(child['infraRsDomP']['attributes']['tDn']):
                                domain_dn = str(child['infraRsDomP']['attributes']['tDn'])
                                if domain_dn in domain_dict.keys():
                                    aep_dict[aep_name]['domain'].append(domain_dict[domain_dn]['name'])
                                    aep_dict[aep_name]['domain_type'].append(domain_dict[domain_dn]['type'])
                                    aep_dict[aep_name]['poolname'].append(domain_dict[domain_dn]['poolname'])
                                    aep_dict[aep_name]['poolvlan'].extend(domain_dict[domain_dn]['poolvlan'])
        return aep_dict

    def get_physif_dict(self):
        physif_dict = {}
        url = '/api/class/l1PhysIf.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        PhysIfs = json.loads(resp.text)['imdata']

        for PhysIf in PhysIfs:
            if 'l1PhysIf' in PhysIf:
                port_dn = str(PhysIf['l1PhysIf']['attributes']['dn'])
                port_node = str(port_dn.split('/node-')[1].split('/')[0])
                port_name = port_node + '-' + str(PhysIf['l1PhysIf']['attributes']['id'])
                physif_dict[port_name] = {}
                physif_dict[port_name]['name'] = port_name
                physif_dict[port_name]['node'] = port_node
                physif_dict[port_name]['id'] = str(PhysIf['l1PhysIf']['attributes']['id'])
                physif_dict[port_name]['descr'] = str(PhysIf['l1PhysIf']['attributes']['descr'])
                physif_dict[port_name]['usage'] = str(PhysIf['l1PhysIf']['attributes']['usage'])
                physif_dict[port_name]['speed'] = str(PhysIf['l1PhysIf']['attributes']['speed'])
                physif_dict[port_name]['adminst'] = str(PhysIf['l1PhysIf']['attributes']['adminSt'])
        return physif_dict

    def get_port_stat_dict(self):
        port_stat_dict = {}
        url = '/api/node/class/eqptIngrTotalHist5min.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        ingrs = json.loads(resp.text)['imdata']
        
        for ingr in ingrs:
            port = ''
            node = ''
            port_dn = ingr['eqptIngrTotalHist5min']['attributes']['dn']
            if '/node-' in port_dn: node = port_dn.split('/node-')[1].split('/')[0]
            if '/phys-[' in port_dn: port = port_dn.split('/phys-[')[1].split(']')[0]
            port_name = node + '-' + port
            if node != '' and port != '':
                if port_name not in port_stat_dict.keys():
                    port_stat_dict[port_name] = {}
                    port_stat_dict[port_name]['bytesratein'] = '0'
                    port_stat_dict[port_name]['bytesrateout'] = '0'
                    port_stat_dict[port_name]['packetin'] = '0'
                    port_stat_dict[port_name]['packetout'] = '0'
                    port_stat_dict[port_name]['portevent'] = []
                    port_stat_dict[port_name]['eventtime'] = []
                port_stat_dict[port_name]['bytesratein'] = \
                    str(int(float(ingr['eqptIngrTotalHist5min']['attributes']['bytesRateMin']) * 8))
                port_stat_dict[port_name]['packetin'] = \
                    ingr['eqptIngrTotalHist5min']['attributes']['pktsMin']

        url = '/api/node/class/eqptEgrTotalHist5min.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        egrs = json.loads(resp.text)['imdata']
        
        for egr in egrs:
            port = ''
            node = ''
            port_dn = egr['eqptEgrTotalHist5min']['attributes']['dn']
            if '/node-' in port_dn: node = port_dn.split('/node-')[1].split('/')[0]
            if '/phys-[' in port_dn: port = port_dn.split('/phys-[')[1].split(']')[0]
            port_name = node + '-' + port
            if node != '' and port != '':
                if port_name not in port_stat_dict.keys():
                    port_stat_dict[port_name] = {}
                    port_stat_dict[port_name]['bytesratein'] = '0'
                    port_stat_dict[port_name]['bytesrateout'] = '0'
                    port_stat_dict[port_name]['packetin'] = '0'
                    port_stat_dict[port_name]['packetout'] = '0'
                    port_stat_dict[port_name]['portevent'] = []
                    port_stat_dict[port_name]['eventtime'] = []
                port_stat_dict[port_name]['bytesrateout'] = \
                    str(int(float(egr['eqptEgrTotalHist5min']['attributes']['bytesRateMin']) * 8))
                port_stat_dict[port_name]['packetout'] = \
                    egr['eqptEgrTotalHist5min']['attributes']['pktsMin']
                    
        url = '/api/node/class/eventRecord.json?query-target-filter=or(' \
              'eq(eventRecord.cause,"port-up"),eq(eventRecord.cause,"port-down"))' \
              '&order-by=eventRecord.created|desc&page=0&page-size=5000'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        eventrecords = json.loads(resp.text)['imdata']
        
        if eventrecords:
            for eventrecord in eventrecords:
                port = ''
                node = ''
                port_dn = eventrecord['eventRecord']['attributes']['affected']
                if '/node-' in port_dn: node = port_dn.split('/node-')[1].split('/')[0]
                if '/phys-[' in port_dn: port = port_dn.split('/phys-[')[1].split(']')[0]
                port_name = node + '-' + port
                if node != '' and port != '':
                    if port_name not in port_stat_dict.keys():
                        port_stat_dict[port_name] = {}
                        port_stat_dict[port_name]['bytesratein'] = '0'
                        port_stat_dict[port_name]['bytesrateout'] = '0'
                        port_stat_dict[port_name]['packetin'] = '0'
                        port_stat_dict[port_name]['packetout'] = '0'
                        port_stat_dict[port_name]['portevent'] = []
                        port_stat_dict[port_name]['eventtime'] = []
                    port_stat_dict[port_name]['portevent'].append(
                        eventrecord['eventRecord']['attributes']['cause'])
                    port_stat_dict[port_name]['eventtime'].append(
                        eventrecord['eventRecord']['attributes']['created'].split('.')[0])
        return port_stat_dict

    def get_port_name_dict(self):
        port_name_dict = {}
        url = '/api/class/l1PhysIf.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        PhysIfs = json.loads(resp.text)['imdata']

        for PhysIf in PhysIfs:
            if 'l1PhysIf' in PhysIf:
                intf_dn = str(PhysIf['l1PhysIf']['attributes']['dn'])
                if '/node-' in intf_dn:
                    node = str(intf_dn.split('/node-')[1].split('/')[0])
                    intf_name = node + '-' + str(PhysIf['l1PhysIf']['attributes']['id'])
                    port_name_dict[intf_name] = {}
                    port_name_dict[intf_name]['name'] = intf_name
                    port_name_dict[intf_name]['node'] = node
                    port_name_dict[intf_name]['id'] = str(PhysIf['l1PhysIf']['attributes']['id'])
                    port_name_dict[intf_name]['descr'] = str(PhysIf['l1PhysIf']['attributes']['descr'])
                    port_name_dict[intf_name]['usage'] = str(PhysIf['l1PhysIf']['attributes']['usage'])
                    port_name_dict[intf_name]['speed'] = str(PhysIf['l1PhysIf']['attributes']['speed'])
                    port_name_dict[intf_name]['adminst'] = str(PhysIf['l1PhysIf']['attributes']['adminSt'])
        return port_name_dict

    def get_port_dict(self, limit=None):
        port_dict = {}
        if limit:
            intf_dict = self.get_interface_dict()
        else:
            intf_dict = self.get_intf_dict()
        switch_dict = self.get_switch_dict()
        url = '/api/class/l1PhysIf.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        PhysIfs = json.loads(resp.text)['imdata']

        for PhysIf in PhysIfs:
            if 'l1PhysIf' in PhysIf:
                intf_dn = str(PhysIf['l1PhysIf']['attributes']['dn'])
                if '/node-' in intf_dn:
                    node = str(intf_dn.split('/node-')[1].split('/')[0])
                    intf_name = node + '-' + str(PhysIf['l1PhysIf']['attributes']['id'])
                    if node in switch_dict.keys():
                        switch_name = switch_dict[node]['name']
                    else:
                        switch_name = ''
                    port_dict[intf_name] = {}
                    port_dict[intf_name]['id'] = str(PhysIf['l1PhysIf']['attributes']['id'])
                    port_dict[intf_name]['descr'] = str(PhysIf['l1PhysIf']['attributes']['descr'])
                    port_dict[intf_name]['usage'] = str(PhysIf['l1PhysIf']['attributes']['usage'])
                    port_dict[intf_name]['speed'] = str(PhysIf['l1PhysIf']['attributes']['speed'])
                    port_dict[intf_name]['adminst'] = str(PhysIf['l1PhysIf']['attributes']['adminSt'])
                    port_dict[intf_name]['dn'] = str(PhysIf['l1PhysIf']['attributes']['dn'])
                    port_dict[intf_name]['operst'] = ''
                    port_dict[intf_name]['bundleindex'] = ''
                    port_dict[intf_name]['opersterr'] = ''
                    port_dict[intf_name]['name'] = intf_name
                    port_dict[intf_name]['switch'] = switch_name
                    port_dict[intf_name]['node'] = node
                    port_dict[intf_name]['fexid'] = ''
                    port_dict[intf_name]['ipg'] = ''
                    port_dict[intf_name]['type'] = ''
                    port_dict[intf_name]['aep'] = ''
                    port_dict[intf_name]['domain'] = []
                    port_dict[intf_name]['poolname'] = []
                    port_dict[intf_name]['domain_type'] = []
                    port_dict[intf_name]['poolvlan'] = []
                    port_dict[intf_name]['mode'] = []
                    port_dict[intf_name]['encap'] = []
                    port_dict[intf_name]['epg'] = []
                    port_dict[intf_name]['bd'] = []
                    port_dict[intf_name]['leaf_profile'] = ''
                    port_dict[intf_name]['selector'] = ''
                    port_dict[intf_name]['blockname'] = ''
                    port_dict[intf_name]['blockport'] = ''
                    port_dict[intf_name]['bytesratein'] = '0'
                    port_dict[intf_name]['bytesrateout'] = '0'
                    port_dict[intf_name]['packetin'] = '0'
                    port_dict[intf_name]['packetout'] = '0'
                    port_dict[intf_name]['portevent'] = '0'
                    port_dict[intf_name]['lastevent'] = ''
                    port_dict[intf_name]['firstevent'] = ''
                    try:
                        if intf_name in intf_dict.keys():
                            port_dict[intf_name]['descr'] = intf_dict[intf_name]['descr']
                            port_dict[intf_name]['name'] = intf_dict[intf_name]['name']
                            port_dict[intf_name]['switch'] = intf_dict[intf_name]['switch']
                            port_dict[intf_name]['node'] = intf_dict[intf_name]['node']
                            port_dict[intf_name]['fexid'] = intf_dict[intf_name]['fexid']
                            port_dict[intf_name]['ipg'] = intf_dict[intf_name]['ipg']
                            port_dict[intf_name]['leaf_profile'] = intf_dict[intf_name]['leaf_profile']
                            port_dict[intf_name]['selector'] = intf_dict[intf_name]['selector']
                            port_dict[intf_name]['blockname'] = intf_dict[intf_name]['blockname']
                            port_dict[intf_name]['blockport'] = intf_dict[intf_name]['blockport']
                            port_dict[intf_name]['aep'] = intf_dict[intf_name]['aep']
                            port_dict[intf_name]['type'] = intf_dict[intf_name]['type']
                            port_dict[intf_name]['domain'] = intf_dict[intf_name]['domain']
                            port_dict[intf_name]['poolname'] = intf_dict[intf_name]['poolname']
                            port_dict[intf_name]['domain_type'] = intf_dict[intf_name]['domain_type']
                            port_dict[intf_name]['poolvlan'] = intf_dict[intf_name]['poolvlan']
                            port_dict[intf_name]['mode'] = intf_dict[intf_name]['mode']
                            port_dict[intf_name]['encap'] = intf_dict[intf_name]['encap']
                            port_dict[intf_name]['epg'] = intf_dict[intf_name]['epg']
                            port_dict[intf_name]['bd'] = intf_dict[intf_name]['bd']

                    except:
                        pass

        url = '/api/class/ethpmPhysIf.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        ethpmPhysIfs = json.loads(resp.text)['imdata']

        for ethpmPhysIf in ethpmPhysIfs:
            if 'ethpmPhysIf' in ethpmPhysIf:
                intf_dn = str(ethpmPhysIf['ethpmPhysIf']['attributes']['dn'])
                if '/node-' in intf_dn:
                    node = str(intf_dn.split('/node-')[1].split('/')[0])
                    intf_name = node + '-' + str(
                        ethpmPhysIf['ethpmPhysIf']['attributes']['dn'].split('/phys-[')[1].split(']')[0])
                    port_dict[intf_name]['bundleindex'] = str(ethpmPhysIf['ethpmPhysIf']['attributes']['bundleIndex'])
                    if str(ethpmPhysIf['ethpmPhysIf']['attributes']['operStQual']) != 'sfp-missing':
                        port_dict[intf_name]['speed'] = str(ethpmPhysIf['ethpmPhysIf']['attributes']['operSpeed'])
                    port_dict[intf_name]['operst'] = str(ethpmPhysIf['ethpmPhysIf']['attributes']['operSt'])
                    port_dict[intf_name]['opersterr'] = str(ethpmPhysIf['ethpmPhysIf']['attributes']['operStQual'])
                    if port_dict[intf_name]['bundleindex'] == 'unspecified': port_dict[intf_name]['bundleindex'] = ''

        if limit is 'full':
            port_stat_dict = self.get_port_stat_dict()
            for intf_name in port_stat_dict.keys():
                try:
                    port_dict[intf_name]['bytesratein'] = port_stat_dict[intf_name]['bytesratein']
                    port_dict[intf_name]['bytesrateout'] = port_stat_dict[intf_name]['bytesrateout']
                    port_dict[intf_name]['packetin'] = port_stat_dict[intf_name]['packetin']
                    port_dict[intf_name]['packetout'] = port_stat_dict[intf_name]['packetout']
                    port_dict[intf_name]['portevent'] = len(port_stat_dict[intf_name]['portevent'])
                    if port_stat_dict[intf_name]['eventtime']:
                        port_dict[intf_name]['lastevent'] = port_stat_dict[intf_name]['eventtime'][0]
                        port_dict[intf_name]['firstevent'] = port_stat_dict[intf_name]['eventtime'][-1]
                except:
                    pass

        return port_dict

    def get_endpoint_dict(self):
        endpoint_dict = {}
        ipg_dict = self.get_ipg_dict()
        url = '/api/class/fvCEp.json?rsp-subtree=children&rsp-subtree-class=fvIp'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        ceps = json.loads(resp.text)['imdata']

        endpoints = {}
        for cep in ceps:
            if "fvCEp" in cep:
                cep_dn = str(cep['fvCEp']['attributes']['dn'])
                endpoints[cep_dn] = {}
                endpoints[cep_dn]['mac'] = str(cep['fvCEp']['attributes']['mac'])
                endpoints[cep_dn]['ip'] = []
                endpoints[cep_dn]['encap'] = str(cep['fvCEp']['attributes']['encap'])
                endpoints[cep_dn]['epg'] = cep_dn.split('/cep-')[0]
                endpoints[cep_dn]['interfaces'] = []
                endpoints[cep_dn]['type'] = ''
                endpoints[cep_dn]['ipg'] = ''
                if 'children' in cep['fvCEp']:
                    cep_children = cep['fvCEp']['children']
                    for cep_child in cep_children:
                        endpoints[cep_dn]['ip'].append(str(cep_child['fvIp']['attributes']['addr']))
                else:
                    endpoints[cep_dn]['ip'].append(str(cep['fvCEp']['attributes']['ip']))

        url = '/api/class/fvRsCEpToPathEp.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        paths = json.loads(resp.text)['imdata']

        for path in paths:
            if "fvRsCEpToPathEp" in path:
                path_names = []
                path_type = ''
                path_dn = str(path['fvRsCEpToPathEp']['attributes']['dn'])
                cep_dn = str(path_dn.split('/rscEpToPathEp-')[0])
                if '/rscEpToPathEp-' in path_dn:
                    path_name = str(path_dn.split('/rscEpToPathEp-[')[1].split(']')[0])
                    if '/pathep-[eth' in path_name:
                        path_type = ''
                        path_ipg = ''
                        path_node = str(path_name.split('/paths-')[1].split('/')[0])
                        if '/extpaths-' in path_name:
                            path_fex = 'eth' + str(path_name.split('/extpaths-')[1].split('/')[0]) + '/'
                            path_names = [path_node + '-' + path_fex + path_name.split('eth')[1].split(']')[0]]
                        else:
                            path_names = [path_node + '-' + path_name.split('/pathep-[')[1].split(']')[0]]

                        for ipg_obj in ipg_dict:
                            if ipg_dict[ipg_obj]['type'] == 'accportgrp':
                                if path_names[0] in ipg_dict[ipg_obj]['interfaces']:
                                    path_type = ipg_dict[ipg_obj]['type']
                                    path_ipg = ipg_dict[ipg_obj]['name']
                    else:
                        path_name = path_name.split('/pathep-[')[1].split(']')[0]
                        if path_name in ipg_dict.keys():
                            path_names = ipg_dict[path_name]['interfaces']
                            path_type = ipg_dict[path_name]['type']
                            path_ipg = ipg_dict[path_name]['name']

                    if cep_dn in endpoints.keys():
                        endpoints[cep_dn]['interfaces'] = path_names
                        endpoints[cep_dn]['type'] = path_type
                        endpoints[cep_dn]['ipg'] = path_ipg

        for endpoint in endpoints.keys():
            endpoint_mac = endpoints[endpoint]['mac']
            if endpoint_mac not in endpoint_dict.keys():
                endpoint_dict[endpoint_mac] = {}
                endpoint_dict[endpoint_mac]['name'] = endpoint_mac
                endpoint_dict[endpoint_mac]['mac'] = [endpoints[endpoint]['mac']]
                endpoint_dict[endpoint_mac]['ip'] = [endpoints[endpoint]['ip']]
                endpoint_dict[endpoint_mac]['encap'] = [endpoints[endpoint]['encap']]
                endpoint_dict[endpoint_mac]['epg'] = [endpoints[endpoint]['epg']]
                endpoint_dict[endpoint_mac]['interfaces'] = [endpoints[endpoint]['interfaces']]
                endpoint_dict[endpoint_mac]['type'] = [endpoints[endpoint]['type']]
                endpoint_dict[endpoint_mac]['ipg'] = [endpoints[endpoint]['ipg']]
            else:
                endpoint_dict[endpoint_mac]['mac'].append(endpoints[endpoint]['mac'])
                endpoint_dict[endpoint_mac]['ip'].append(endpoints[endpoint]['ip'])
                endpoint_dict[endpoint_mac]['encap'].append(endpoints[endpoint]['encap'])
                endpoint_dict[endpoint_mac]['epg'].append(endpoints[endpoint]['epg'])
                endpoint_dict[endpoint_mac]['interfaces'].append(endpoints[endpoint]['interfaces'])
                endpoint_dict[endpoint_mac]['type'].append(endpoints[endpoint]['type'])
                endpoint_dict[endpoint_mac]['ipg'].append(endpoints[endpoint]['ipg'])

        return endpoint_dict

    def get_epg_endpoint_dict(self):
        epg_endpoint_dict = {}
        url = '/api/class/fvCEp.json?rsp-subtree=children&rsp-subtree-class=fvIp'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        ceps = json.loads(resp.text)['imdata']
        for cep in ceps:
            if "fvCEp" in cep:
                cep_dn = str(cep['fvCEp']['attributes']['dn'])
                epg_dn = cep_dn.split('/cep-')[0]
                if epg_dn not in epg_endpoint_dict.keys():
                    epg_endpoint_dict[epg_dn] = {}
                    epg_endpoint_dict[epg_dn]['mac'] = []
                    epg_endpoint_dict[epg_dn]['ip'] = []

                epg_endpoint_dict[epg_dn]['mac'].append(str(cep['fvCEp']['attributes']['mac']))
                epg_endpoint_dict[epg_dn]['encap'] = str(cep['fvCEp']['attributes']['encap'])
                epg_endpoint_dict[epg_dn]['name'] = cep_dn.split('/cep-')[0]
                if 'children' in cep['fvCEp']:
                    cep_children = cep['fvCEp']['children']
                    for cep_child in cep_children:
                        epg_endpoint_dict[epg_dn]['ip'].append(str(cep_child['fvIp']['attributes']['addr']))
                else:
                    epg_endpoint_dict[epg_dn]['ip'].append(str(cep['fvCEp']['attributes']['ip']))
        return epg_endpoint_dict


    def get_switch_profile_dict(self):
        node_id_dict = {}
        url = '/api/node/mo/uni/infra/.json?rsp-subtree=full&rsp-subtree-class=infraNodeP'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        infra = json.loads(resp.text)['imdata'][0]
        
        if 'children' in infra['infraInfra']:
            nodeps = infra['infraInfra']['children']
            for nodep in nodeps:
                if 'infraNodeP' in nodep:
                    node_name = str(nodep['infraNodeP']['attributes']['name'])
                    nodes = []
                    if 'children' in nodep['infraNodeP']:
                        nodep_children = nodep['infraNodeP']['children']
                        for leafs in nodep_children:
                            if 'infraLeafS' in leafs:
                                if 'children' in leafs['infraLeafS']:
                                    leafs_children = leafs['infraLeafS']['children']
                                    for nodeblk in leafs_children:
                                        if 'infraNodeBlk' in nodeblk:
                                            node1 = str(nodeblk['infraNodeBlk']['attributes']['from_'])
                                            node2 = str(nodeblk['infraNodeBlk']['attributes']['to_'])
                                            for node in range(int(node1), int(node2) + 1, 1):
                                                nodes.append(str(node))
                                                if str(node) not in node_id_dict.keys():
                                                    node_id_dict[str(node)] = {}
                                                    node_id_dict[str(node)]['int_profile'] = []
                                                    node_id_dict[str(node)]['sw_profile'] = []
                        for accportp in nodep_children:
                            if 'infraRsAccPortP' in accportp:

                                accportp_rn = str(
                                    accportp['infraRsAccPortP']['attributes']['tDn'].split('/accportprof-')[1])
                                if str(accportp['infraRsAccPortP']['attributes']['state']) == 'formed':
                                    for node in nodes:
                                        node_id_dict[node]['int_profile'].append(accportp_rn)
                                        node_id_dict[node]['sw_profile'].append(node_name)

        return node_id_dict

    def get_switch_maint_dict(self):
        node_id_dict = {}
        url = '/api/node/class/fabricNodeBlk.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        fnodeblks = json.loads(resp.text)['imdata']
        
        for fnodeblk in fnodeblks:
            fnodeblk_dn = str(fnodeblk['fabricNodeBlk']['attributes']['dn'])
            node1 = str(fnodeblk['fabricNodeBlk']['attributes']['from_'])
            node2 = str(fnodeblk['fabricNodeBlk']['attributes']['to_'])
            for node in range(int(node1), int(node2) + 1, 1):
                if str(node) not in node_id_dict.keys():
                    node_id_dict[str(node)] = {}
                    node_id_dict[str(node)]['fwgrp'] = ''
                    node_id_dict[str(node)]['maintgrp'] = ''
                if '/fwgrp-' in fnodeblk_dn:
                    node_id_dict[str(node)]['fwgrp'] = fnodeblk_dn.split('/fwgrp-')[1].split('/')[0]
                elif '/maintgrp-' in fnodeblk_dn:
                    node_id_dict[str(node)]['maintgrp'] = fnodeblk_dn.split('/maintgrp-')[1].split('/')[0]
        return node_id_dict

    def get_switch_health_dict(self):
        node_id_dict = {}
        url = '/api/node/class/healthInst.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        nodehealths = json.loads(resp.text)['imdata']
        
        for nodehealth in nodehealths:
            if '/sys/health' in str(nodehealth['healthInst']['attributes']['dn']):
                node = str(nodehealth['healthInst']['attributes']['dn'].split('/node-')[1].split('/')[0])
                node_id_dict[node] = {}
                node_id_dict[node]['healthscore'] = str(nodehealth['healthInst']['attributes']['cur'])

        return node_id_dict

    def get_switch_oob_dict(self):
        node_id_dict = {}
        url = '/api/class/mgmtRsOoBStNode.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        oobmgmts = json.loads(resp.text)['imdata']

        for oobmgmt in oobmgmts:
            node = str(oobmgmt['mgmtRsOoBStNode']['attributes']['dn'].split('/node-')[1].split(']')[0])
            node_id_dict[node] = {}
            node_id_dict[node]['addr'] = str(oobmgmt['mgmtRsOoBStNode']['attributes']['addr'])
            node_id_dict[node]['gw'] = str(oobmgmt['mgmtRsOoBStNode']['attributes']['gw'])

        return node_id_dict

    def get_switch_vpcpair_dict(self):
        node_id_dict = {}
        url = '/api/class/fabricExplicitGEp.json?rsp-subtree=full&rsp-subtree-class=fabricNodePEp'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        vpcpairs = json.loads(resp.text)['imdata']

        for vpcpair in vpcpairs:
            if 'children' in vpcpair['fabricExplicitGEp']:
                vpcpair_nodes = vpcpair['fabricExplicitGEp']['children']
                node_list = []
                for vpcpair_node in vpcpair_nodes:
                    node = str(vpcpair_node['fabricNodePEp']['attributes']['id'])
                    node_list.append(node)
                for vpcpair_node in vpcpair_nodes:
                    node = str(vpcpair_node['fabricNodePEp']['attributes']['id'])
                    node_id_dict[node] = {}
                    node_id_dict[node]['name'] = str(vpcpair['fabricExplicitGEp']['attributes']['name'])
                    node_id_dict[node]['id'] = str(vpcpair['fabricExplicitGEp']['attributes']['id'])
                    node_id_dict[node]['ip'] = str(vpcpair['fabricExplicitGEp']['attributes']['virtualIp'])
                    node_id_dict[node]['nodes'] = sorted(node_list)
        return node_id_dict

    def get_vpcpair_dict(self):
        vpcpair_dict = {}
        url = '/api/class/fabricExplicitGEp.json?rsp-subtree=full&rsp-subtree-class=fabricNodePEp'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        vpcpairs = json.loads(resp.text)['imdata']

        for vpcpair in vpcpairs:
            vpcid = str(vpcpair['fabricExplicitGEp']['attributes']['id'])
            vpcpair_dict[vpcid] = {}
            vpcpair_dict[vpcid]['name'] = str(vpcpair['fabricExplicitGEp']['attributes']['name'])
            vpcpair_dict[vpcid]['id'] = vpcid
            vpcpair_dict[vpcid]['ip'] = str(vpcpair['fabricExplicitGEp']['attributes']['virtualIp'])
            vpcpair_dict[vpcid]['nodes'] = []
            if 'children' in vpcpair['fabricExplicitGEp']:
                vpcpair_nodes = vpcpair['fabricExplicitGEp']['children']
                for vpcpair_node in vpcpair_nodes:
                    node = str(vpcpair_node['fabricNodePEp']['attributes']['id'])
                    vpcpair_dict[vpcid]['nodes'].append(node)
                    vpcpair_dict[vpcid]['nodes'].sort()

        return vpcpair_dict

    def get_lldp_dict(self):
        lldp_dict = {}
        url = '/api/class/lldpAdjEp.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        lldps = json.loads(resp.text)['imdata']

        for lldp in lldps:
            if "lldpAdjEp" in lldp:
                lldp_dn = str(lldp['lldpAdjEp']['attributes']['dn'])
                lldp_node = lldp_dn.split('/node-')[1].split('/')[0]
                lldp_port = lldp_dn.split('/if-[')[1].split(']')[0]
                lldp_name = lldp_node + '-' + lldp_port
                lldp_dict[lldp_name] = {}
                lldp_dict[lldp_name]['name'] = lldp_name
                lldp_dict[lldp_name]['local_name'] = lldp_node
                lldp_dict[lldp_name]['local_port'] = lldp_port
                lldp_dict[lldp_name]['remote_name'] = str(lldp['lldpAdjEp']['attributes']['sysName'])
                lldp_dict[lldp_name]['remote_port'] = str(lldp['lldpAdjEp']['attributes']['portIdV'])
                lldp_dict[lldp_name]['remote_portdesc'] = str(lldp['lldpAdjEp']['attributes']['portDesc'])
                lldp_dict[lldp_name]['remote_sysdesc'] = str(lldp['lldpAdjEp']['attributes']['sysDesc'])
                lldp_dict[lldp_name]['remote_mgmtip'] = str(lldp['lldpAdjEp']['attributes']['mgmtIp'])
                lldp_dict[lldp_name]['remote_mac'] = str(lldp['lldpAdjEp']['attributes']['chassisIdV'])

        return lldp_dict

    def get_l3out_name_dict(self):
        l3out_name_dict = {}
        url = '/api/class/l3extOut.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        l3outs = json.loads(resp.text)['imdata']
        
        for l3out in l3outs:
            if "l3extOut" in l3out:
                l3out_dn = str(l3out['l3extOut']['attributes']['dn'])
                l3out_name_dict[l3out_dn] = {}
                l3out_name_dict[l3out_dn]['name'] = str(l3out['l3extOut']['attributes']['name'])
                l3out_name_dict[l3out_dn]['descr'] = str(l3out['l3extOut']['attributes']['descr'])
                l3out_name_dict[l3out_dn]['tenant'] = str(l3out_dn.split('uni/tn-')[1].split('/')[0])
        return l3out_name_dict

    def get_l3ext_name_dict(self):
        l3ext_name_dict = {}
        url = '/api/class/l3extInstP.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        l3exts = json.loads(resp.text)['imdata']

        for l3ext in l3exts:
            if "l3extInstP" in l3ext:
                l3ext_dn = str(l3ext['l3extInstP']['attributes']['dn'])
                l3ext_name_dict[l3ext_dn] = {}
                l3ext_name_dict[l3ext_dn]['name'] = str(l3ext['l3extInstP']['attributes']['name'])
                l3ext_name_dict[l3ext_dn]['descr'] = str(l3ext['l3extInstP']['attributes']['descr'])
                l3ext_name_dict[l3ext_dn]['tenant'] = str(l3ext_dn.split('uni/tn-')[1].split('/')[0])
                l3ext_name_dict[l3ext_dn]['l3out'] = str(l3ext_dn.split('/out-')[1].split('/')[0])
        return l3ext_name_dict

    def get_dhcprelay_name_dict(self):
        dhcprelay_name_dict = {}
        url = '/api/class/dhcpRelayP.json'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)
        dhcprelays = json.loads(resp.text)['imdata']

        for dhcprelay in dhcprelays:
            if "dhcpRelayP" in dhcprelay:
                dhcprelay_name = str(dhcprelay['dhcpRelayP']['attributes']['name'])
                dhcprelay_name_dict[dhcprelay_name] = {}
                dhcprelay_name_dict[dhcprelay_name]['name'] = str(dhcprelay['dhcpRelayP']['attributes']['name'])
                dhcprelay_name_dict[dhcprelay_name]['descr'] = str(dhcprelay['dhcpRelayP']['attributes']['descr'])
        return dhcprelay_name_dict
        
    def get_snapshot_dict(self):
        snapshot_dict = {}
        url = '/api/class/configSnapshot.json?rsp-subtree=full'
        get_url = self.apic + url
        resp = self.mysession.get(get_url, verify=False)

        snapshots = json.loads(resp.text)['imdata']
        for snapshot in snapshots:
            filename = str(snapshot['configSnapshot']['attributes']['fileName'])
            if '_tn-' in filename:
                target = '-'.join(filename.split('_tn-')[1].split('-')[:-5])
            else:
                target = 'Fabric'
            snapshot_dict[filename] = {}
            snapshot_dict[filename]['name'] = str(snapshot['configSnapshot']['attributes']['name'])
            snapshot_dict[filename]['dn'] = str(snapshot['configSnapshot']['attributes']['dn'])
            snapshot_dict[filename]['filename'] = str(snapshot['configSnapshot']['attributes']['fileName'])
            snapshot_dict[filename]['descr'] = str(snapshot['configSnapshot']['attributes']['descr'])
            snapshot_dict[filename]['target'] = target

        return snapshot_dict       


    def get_tenant_table(self, tenant_name):
        result = []
        ret_dict = {}
        tenant_dict = self.get_tenant_dict()
        for tenant in tenant_dict.keys():
            if tenant_name == None:
                row = [tenant_dict[tenant]['name'], tenant_dict[tenant]['descr'], tenant_dict[tenant]['annotation'],
                       len(tenant_dict[tenant]['ctx']), len(tenant_dict[tenant]['bd']), len(tenant_dict[tenant]['app']),
                       len(tenant_dict[tenant]['epg']), len(tenant_dict[tenant]['contract']),
                       len(tenant_dict[tenant]['l3out'])]
                result.append(row)
            if tenant_name == tenant:
                row = [tenant_dict[tenant]['name'], tenant_dict[tenant]['descr'], tenant_dict[tenant]['annotation'],
                       len(tenant_dict[tenant]['ctx']), len(tenant_dict[tenant]['bd']), len(tenant_dict[tenant]['app']),
                       len(tenant_dict[tenant]['epg']), len(tenant_dict[tenant]['contract']),
                       len(tenant_dict[tenant]['l3out'])]
                result.append(row)

        result_headers = 'Tenant, Description, Annotation, Context, BD, APP, EPG, Contract, L3out'
        ret_dict[result_headers] = sorted(result)
        return ret_dict

    def get_epg_table(self, tenant_name, epg_name):
        result = []
        ret_dict = {}
        epg_dict = self.get_epg_dict()
        if epg_name == None:
            for epg_dn in sorted(epg_dict.keys()):
                if tenant_name == epg_dict[epg_dn]['tenant'] or tenant_name == None:
                    epg_domain_names = []
                    if epg_dict[epg_dn]['bd_tenant'] == 'common':
                        epg_dict[epg_dn]['bd'] = '*' + epg_dict[epg_dn]['bd']
                    if epg_dict[epg_dn]['ctx_tenant'] == 'common':
                        epg_dict[epg_dn]['ctx'] = '*' + epg_dict[epg_dn]['ctx']
                    for epg_domain in epg_dict[epg_dn]['domain']:
                        if 'uni/phys-' in epg_domain:
                            epg_domain_names.append(str(epg_domain.split('uni/phys-')[1]))
                        elif 'uni/l2dom-' in epg_domain:
                            epg_domain_names.append(str(epg_domain.split('uni/l2dom-')[1]))
                        elif 'uni/l3dom-' in epg_domain:
                            epg_domain_names.append(str(epg_domain.split('uni/l3dom-')[1]))
                        elif 'uni/vmmp-VMware/dom-' in epg_domain:
                            epg_domain_names.append(str(epg_domain.split('uni/vmmp-VMware/dom-')[1]))
                        else:
                            epg_domain_names.append(epg_domain)
                    row = [epg_dict[epg_dn]['tenant'], epg_dict[epg_dn]['app'], epg_dict[epg_dn]['name'],
                           epg_dict[epg_dn]['descr'],
                           epg_dict[epg_dn]['ctx'], epg_dict[epg_dn]['bd'], '\n'.join(epg_dict[epg_dn]['bd_subnet']),
                           '\n'.join(epg_dict[epg_dn]['vlan']),
                           '\n'.join(epg_dict[epg_dn]['encap']), '\n'.join(epg_domain_names)]
                    result.append(row)

            result_headers = 'Tenant, App Profile, EPG, Description, Context, Bridge Domain, Anycast GW, ' \
                             'Static, Learnt, Domain'
            ret_dict[result_headers] = sorted(result)

        else:
            for epg_dn in sorted(epg_dict.keys()):
                if tenant_name == epg_dict[epg_dn]['tenant'] or tenant_name == None:
                    if epg_dict[epg_dn]['bd_tenant'] == 'common':
                        epg_dict[epg_dn]['bd'] = '*' + epg_dict[epg_dn]['bd']
                    if epg_dict[epg_dn]['ctx_tenant'] == 'common':
                        epg_dict[epg_dn]['ctx'] = '*' + epg_dict[epg_dn]['ctx']
                    if epg_name == epg_dict[epg_dn]['name']:
                        if ret_dict == {}:
                            ret_dict = {
                                '02, Tenant, App Profile, EPG, Description': [],
                                '03, Context, Bridge Domain, Anycast GW, Static, Learnt, Domain': [],
                                '04, Node, Interface, Description, AEP, IPG, Speed, Status, '
                                'Aggr, Encap, Mode': []
                            }
                        ret_dict['02, Tenant, App Profile, EPG, Description'].append(
                            [epg_dict[epg_dn]['tenant'], epg_dict[epg_dn]['app'], epg_dict[epg_dn]['name'],
                             epg_dict[epg_dn]['descr']])
                        ret_dict['03, Context, Bridge Domain, Anycast GW, Static, Learnt, Domain'].extend(
                            [[epg_dict[epg_dn]['ctx'], epg_dict[epg_dn]['bd'],
                              '\n'.join(epg_dict[epg_dn]['bd_subnet']), '\n'.join(epg_dict[epg_dn]['vlan']),
                              '\n'.join(epg_dict[epg_dn]['encap']), '\n'.join(epg_dict[epg_dn]['domain'])]
                             for i in range(0, 1) if epg_dict[epg_dn]['bd'] != ''])
                        port_dict = self.get_port_dict()
                        for port_name in sorted(port_dict.keys()):
                            if epg_dn in port_dict[port_name]['epg']:
                                for i, port_encap in enumerate(port_dict[port_name]['encap']):
                                    if port_encap in epg_dict[epg_dn]['encap']:
                                        port_mode = port_dict[port_name]['mode'][i]
                                        break
                                    else:
                                        port_encap = ''
                                        port_mode = ''
                                ret_dict['04, Node, Interface, Description, AEP, IPG, Speed, Status, '
                                         'Aggr, Encap, Mode'].append(
                                    [port_dict[port_name]['node'], port_dict[port_name]['id'],
                                     port_dict[port_name]['descr'],
                                     port_dict[port_name]['aep'], port_dict[port_name]['ipg'],
                                     port_dict[port_name]['speed'], port_dict[port_name]['adminst'] + '/' +
                                     port_dict[port_name]['operst'], port_dict[port_name]['bundleindex'],
                                     port_encap, port_mode])
        return ret_dict

    def get_bd_table(self, tenant_name, bd_name):
        result = []
        ret_dict = {}
        bd_dict = self.get_bd_dict()
        if tenant_name == None:
            bd_list = bd_dict.keys()
        else:
            bd_list = []

        for bd_dn in sorted(bd_dict.keys()):
            bd_dict[bd_dn]['epg_list'] = bd_epg_list = []
            for epg_dn in bd_dict[bd_dn]['epg']:
                if tenant_name == None:
                    bd_epg_list.append(epg_dn.split('/epg-')[1])
                    bd_list = bd_dict.keys()
                if tenant_name == epg_dn.split('uni/tn-')[1].split('/')[0]:
                    bd_epg_list.append(epg_dn.split('/epg-')[1])
                    if bd_dn not in bd_list: bd_list.append(bd_dn)
        if bd_name == None:
            for bd_dn in bd_list:
                if bd_name == bd_dict[bd_dn]['name'] or bd_name == None:
                    bd_dict[bd_dn]['name'] = bd_dict[bd_dn]['name']
                    if bd_dict[bd_dn]['ctx_tenant'] == 'common': bd_dict[bd_dn]['ctx'] = '*' + bd_dict[bd_dn]['ctx']
                    row = [bd_dict[bd_dn]['name'], bd_dict[bd_dn]['descr'], bd_dict[bd_dn]['ctx'],
                           bd_dict[bd_dn]['unicastRoute'], bd_dict[bd_dn]['arpflood'], bd_dict[bd_dn]['unkunicast'],
                           '\n'.join(bd_dict[bd_dn]['subnet']), '\n'.join(bd_dict[bd_dn]['epg_list']),
                           '\n'.join(bd_dict[bd_dn]['dhcp'])]
                    result.append(row)
            result_headers = 'Bridge Domain, Description, Context, Route, ARP, Unicast, Subnet, EPG, DHCP Relay'
            ret_dict[result_headers] = sorted(result)

        else:
            for bd_dn in bd_list:
                if bd_name == bd_dict[bd_dn]['name']:
                    if ret_dict == {}:
                        ret_dict = {
                            '02, Tenant, Bridge Domain, Description, Context, Route, ARP, Unicast': [],
                            '03, Context, Subnet, EPG, DHCP Relay, L3out': []
                        }
                    ret_dict['02, Tenant, Bridge Domain, Description, Context, Route, ARP, Unicast'].append(
                        [bd_dict[bd_dn]['tenant'], bd_dict[bd_dn]['name'], bd_dict[bd_dn]['descr'],
                         bd_dict[bd_dn]['ctx'], bd_dict[bd_dn]['unicastRoute'], bd_dict[bd_dn]['arpflood'],
                         bd_dict[bd_dn]['unkunicast']])
                    ret_dict['03, Context, Subnet, EPG, DHCP Relay, L3out'].append(
                        [bd_dict[bd_dn]['ctx'], '\n'.join(bd_dict[bd_dn]['subnet']),
                         '\n'.join(bd_dict[bd_dn]['epg_list']),
                         '\n'.join(bd_dict[bd_dn]['dhcp']), '\n'.join(bd_dict[bd_dn]['l3out'])])

        return ret_dict

    def get_contract_table(self, tenant_name, contract_name):
        result = []
        ret_dict = {}
        contract_dict = self.get_contract_dict()
        filter_dict = self.get_filter_dict()
        contract_list = []
        filter_list = []

        for contract_dn in sorted(contract_dict.keys()):
            contract_dict[contract_dn]['cepg_list'] = contract_cepg_list = []
            contract_dict[contract_dn]['pepg_list'] = contract_pepg_list = []
            for epg_dn in contract_dict[contract_dn]['cepg']:
                if tenant_name == None:
                    if '/ctx-' in epg_dn: contract_cepg_list.append(
                        epg_dn.split('uni/tn-')[1].split('/')[0] + '/' + epg_dn.split('/ctx-')[1].replace('/any',
                                                                                                          '/vzAny'))
                    if '/epg-' in epg_dn: contract_cepg_list.append(
                        epg_dn.split('uni/tn-')[1].split('/')[0] + '/' + epg_dn.split('/epg-')[1])
                    if '/instP-' in epg_dn: contract_cepg_list.append(
                        epg_dn.split('uni/tn-')[1].split('/')[0] + '/' + epg_dn.split('/instP-')[1])
                    if contract_dn not in contract_list: contract_list.append(contract_dn)
                elif tenant_name == epg_dn.split('uni/tn-')[1].split('/')[0]:
                    if '/ctx-' in epg_dn: contract_cepg_list.append(epg_dn.split('/ctx-')[1].replace('/any', '/vzAny'))
                    if '/epg-' in epg_dn: contract_cepg_list.append(epg_dn.split('/epg-')[1])
                    if '/instP-' in epg_dn: contract_cepg_list.append(epg_dn.split('/instP-')[1])
                    if contract_dn not in contract_list: contract_list.append(contract_dn)
                elif 'common' == epg_dn.split('uni/tn-')[1].split('/')[0]:
                    if '/ctx-' in epg_dn: contract_cepg_list.append(
                        '*' + epg_dn.split('/ctx-')[1].replace('/any', '/vzAny'))
                    if '/epg-' in epg_dn: contract_cepg_list.append('*' + epg_dn.split('/epg-')[1])
                    if '/instP-' in epg_dn: contract_cepg_list.append('*' + epg_dn.split('/instP-')[1])
            for epg_dn in contract_dict[contract_dn]['pepg']:
                if tenant_name == None:
                    if '/ctx-' in epg_dn: contract_pepg_list.append(
                        epg_dn.split('uni/tn-')[1].split('/')[0] + '/' + epg_dn.split('/ctx-')[1].replace('/any',
                                                                                                          '/vzAny'))
                    if '/epg-' in epg_dn: contract_pepg_list.append(
                        epg_dn.split('uni/tn-')[1].split('/')[0] + '/' + epg_dn.split('/epg-')[1])
                    if '/instP-' in epg_dn: contract_pepg_list.append(
                        epg_dn.split('uni/tn-')[1].split('/')[0] + '/' + epg_dn.split('/instP-')[1])
                    if contract_dn not in contract_list: contract_list.append(contract_dn)
                elif tenant_name == epg_dn.split('uni/tn-')[1].split('/')[0]:
                    if '/ctx-' in epg_dn: contract_pepg_list.append(epg_dn.split('/ctx-')[1].replace('/any', '/vzAny'))
                    if '/epg-' in epg_dn: contract_pepg_list.append(epg_dn.split('/epg-')[1])
                    if '/instP-' in epg_dn: contract_pepg_list.append(epg_dn.split('/instP-')[1])
                    if contract_dn not in contract_list: contract_list.append(contract_dn)
                elif 'common' == epg_dn.split('uni/tn-')[1].split('/')[0]:
                    if '/ctx-' in epg_dn: contract_pepg_list.append(
                        '*' + epg_dn.split('/ctx-')[1].replace('/any', '/vzAny'))
                    if '/epg-' in epg_dn: contract_pepg_list.append('*' + epg_dn.split('/epg-')[1])
                    if '/instP-' in epg_dn: contract_pepg_list.append('*' + epg_dn.split('/instP-')[1])
        for contract_dn in contract_list:
            contract_filter_list = []
            entry_name_list = []
            entry_stateful_list = []
            entry_type_list = []
            entry_protocol_list = []
            entry_ports_list = []
            entry_dir_list = []
            if contract_name == contract_dict[contract_dn]['name'] or contract_name == None:
                for i, filter_dn in enumerate(contract_dict[contract_dn]['filter']):
                    if filter_dn:
                        filter_name = filter_dict[filter_dn]['name']
                        contract_filter_list.append(filter_name)
                        entries = filter_dict[filter_dn]['entries']
                        for entry in entries:
                            entry_name = str(entry['vzEntry']['attributes']['name'])
                            entry_dFromPort = str(entry['vzEntry']['attributes']['dFromPort'])
                            entry_dToPort = str(entry['vzEntry']['attributes']['dToPort'])
                            entry_prot = str(entry['vzEntry']['attributes']['prot'])
                            entry_etherT = str(entry['vzEntry']['attributes']['etherT'])
                            entry_stateful = str(entry['vzEntry']['attributes']['stateful'])
                            entry_dir = str(contract_dict[contract_dn]['dir'][i])
                            if entry_dFromPort == 'unspecified': entry_dFromPort = 'any'
                            if entry_dToPort == 'unspecified': entry_dToPort = 'any'
                            if entry_prot == 'unspecified': entry_prot = 'any'
                            if entry_etherT == 'unspecified': entry_etherT = 'any'
                            if 'uni/tn-common/' in filter_dn: entry_name = '*' + entry_name
                            if entry_name not in entry_name_list:
                                entry_name_list.append(entry_name)
                                entry_stateful_list.append(entry_stateful)
                                entry_type_list.append(entry_etherT)
                                entry_protocol_list.append(entry_prot)
                                entry_ports_list.append(entry_dFromPort + '-' + entry_dToPort)
                                entry_dir_list.append(entry_dir)
                        if filter_dn not in filter_list: filter_list.append(filter_dn)
                contract_dict[contract_dn]['filter'] = contract_filter_list
                if contract_dict[contract_dn]['tenant'] == 'common':
                    contract_dict[contract_dn]['name'] = '*' + contract_dict[contract_dn]['name']
                row = [contract_dict[contract_dn]['name'],
                       '\n'.join(contract_dict[contract_dn]['cepg_list']),
                       '\n'.join(contract_dict[contract_dn]['pepg_list']),
                       '\n'.join(entry_name_list), '\n'.join(entry_stateful_list), '\n'.join(entry_type_list),
                       '\n'.join(entry_protocol_list), '\n'.join(entry_ports_list), '\n'.join(entry_dir_list)]
                result.append(row)
        result_headers = 'Name, Source, Destination, Entries, FW, Type, Prot, Ports, Direction'
        ret_dict[result_headers] = sorted(result)
        return ret_dict

    def get_switch_table(self, role, node):
        result = []
        result2 = []
        ret_dict = {}
        switch_dict = self.get_switch_dict()
        switch_profile_dict = self.get_switch_profile_dict()
        switch_oob_dict = self.get_switch_oob_dict()
        switch_vpcpair_dict = self.get_switch_vpcpair_dict()
        switch_health_dict = self.get_switch_health_dict()
        switch_maint_dict = self.get_switch_maint_dict()

        for node_id in sorted(switch_dict.keys(), key=str.lower):
            if role == switch_dict[node_id]['role'] or role == None:
                if node_id == switch_dict[node_id]['id']:
                    row1 = [int(switch_dict[node_id]['id']), switch_dict[node_id]['name'], switch_dict[node_id]['pod'],
                            switch_dict[node_id]['serial'], switch_dict[node_id]['model'], switch_dict[node_id]['role'],
                            switch_dict[node_id]['fabricSt']]
                    row2 = [int(switch_dict[node_id]['id']), switch_dict[node_id]['name']]
                    if node_id in switch_oob_dict.keys():
                        row1.append(switch_oob_dict[node_id]['addr'])
                        row1.append(switch_oob_dict[node_id]['gw'])
                    else:
                        row1.extend(['', ''])
                    if node_id in switch_health_dict.keys():
                        row1.append(switch_health_dict[node_id]['healthscore'])
                    elif switch_dict[node_id]['role'] == 'controller':
                        row1.extend(['N/A'])
                    else:
                        row1.extend([''])
                    if node_id in switch_maint_dict.keys():
                        row1.append(switch_maint_dict[node_id]['fwgrp'])
                        row1.append(switch_maint_dict[node_id]['maintgrp'])
                    elif switch_dict[node_id]['role'] == 'controller':
                        row1.extend(['N/A', 'N/A'])
                    else:
                        row1.extend(['', ''])
                    if node_id in switch_profile_dict.keys():
                        row2.append('\n'.join(switch_profile_dict[node_id]['sw_profile']))
                        row2.append('\n'.join(switch_profile_dict[node_id]['int_profile']))
                    else:
                        row2.extend(['', ''])
                    if node_id in switch_vpcpair_dict.keys():
                        row2.append(switch_vpcpair_dict[node_id]['name'])
                        row2.append(switch_vpcpair_dict[node_id]['ip'])
                        row2.append(switch_vpcpair_dict[node_id]['id'])
                    else:
                        row2.extend(['', '', ''])
                    if node == None:
                        if row1 not in result:
                            result.append(row1)
                            if switch_dict[node_id]['role'] == 'leaf':
                                if row2 not in result2: result2.append(row2)
                    if node in switch_dict.keys():
                        if switch_dict[node]['id'] == node_id:
                            if row1 not in result:
                                result.append(row1)
                                if switch_dict[node_id]['role'] == 'leaf':
                                    if row2 not in result2: result2.append(row2)

        result_headers = '01, Node, Name, pod, serial, model, role, status, oob_mgmt_ip, oob_mgmt_gw, ' \
                         'health, fw grp, maint grp'
        result2_headers = '02, Node, Name, Switch profile, Interface profile, vpc pair name, vpc pair ip, vpc pair id'
        ret_dict[result_headers] = sorted(result)
        ret_dict[result2_headers] = sorted(result2)
        return ret_dict

    def get_pm_port_report(self, port_list, port_dict=None):
        result = []
        ret_dict = {}
        if not port_dict:
            port_dict = self.get_port_dict()
        for port_name in port_list:
            port_name = port_name.replace(',', '').strip()
            if port_name in port_dict.keys():
                result.append(
                    [port_dict[port_name]['switch'], port_dict[port_name]['id'],
                     port_dict[port_name]['descr'],
                     '\n'.join([epg.split('/epg-')[1] for epg in port_dict[port_name]['epg'] if '/epg-' in epg]),
                     port_dict[port_name]['ipg'],
                     port_dict[port_name]['speed'], port_dict[port_name]['adminst'] + '/' +
                     port_dict[port_name]['operst'], port_dict[port_name]['opersterr'],
                     '\n'.join(port_dict[port_name]['encap']), '\n'.join(port_dict[port_name]['mode'])])
        result_headers = 'Node, Interface, Description, EPG, IPG, Speed, Status, OperSt Error, Vlan, Mode'
        ret_dict[result_headers] = result
        return ret_dict

    def get_pm_epg_report(self, epg_list, epg_dict=None):
        result = []
        ret_dict = {}
        if not epg_dict:
            epg_dict = self.get_epg_dict()
        for epg_dn in epg_list:
            epg_dn = epg_dn.replace(',', '').strip()
            if epg_dn in epg_dict.keys():
                result.append([epg_dict[epg_dn]['tenant'], epg_dict[epg_dn]['app'], epg_dict[epg_dn]['name'],
                               epg_dict[epg_dn]['descr'],
                               epg_dict[epg_dn]['ctx'], epg_dict[epg_dn]['bd'],
                               '\n'.join(epg_dict[epg_dn]['bd_subnet']),
                               '\n'.join(epg_dict[epg_dn]['vlan'])])
        result_headers = 'Tenant, App Profile, EPG, Description, Context, Bridge Domain, Anycast GW, Vlan'
        ret_dict[result_headers] = result
        return ret_dict

    def get_port_table(self, match_node, match_port, switch_dict=None, port_dict=None):
        result = []
        ret_dict = {}
        if not switch_dict:
            switch_dict = self.get_switch_dict()
        if match_node is None and match_port is None:
            port_dict = self.get_port_dict('basic')
            for port_name in sorted(port_dict.keys()):
                portnum = []
                node = port_dict[port_name]['node']
                for pnum in port_dict[port_name]['id'].split('eth')[1].split('/'):
                    if len(pnum) < 2:
                        pnum = '0' + str(pnum)
                    portnum.append(pnum)
                if len(portnum) > 3:
                    portnum.insert(0, '000')
                nodenum = int(str(node) + '0000000')
                portnum = nodenum + int(''.join(portnum))
                portipg = port_dict[port_name]['ipg'].split('/')[0]
                result.append(
                    [portnum, port_dict[port_name]['name'],
                     port_dict[port_name]['descr'],
                     port_dict[port_name]['usage'], portipg,
                     port_dict[port_name]['speed'], port_dict[port_name]['adminst'] + '/' +
                     port_dict[port_name]['operst'], port_dict[port_name]['opersterr'],
                     port_dict[port_name]['bundleindex']])
            result_headers = 'Port Name, Description, Usage, IPG, Speed, Status, OperSt Error, Aggr'
            result = sorted(result)
            for line in result:
                del line[0]
            ret_dict[result_headers] = result
        elif match_node is not None and match_port is None:
            port_dict = self.get_port_dict('basic')
            node = str(switch_dict[match_node]['id'])
            for port_name in sorted(port_dict.keys()):
                if node == port_dict[port_name]['node']:
                    portnum = []
                    for pnum in port_dict[port_name]['id'].split('eth')[1].split('/'):
                        if len(pnum) < 2:
                            pnum = '0' + str(pnum)
                        portnum.append(pnum)
                    portnum = int(''.join(portnum))
                    portipg = port_dict[port_name]['ipg'].split('/')[0]
                    result.append(
                        [portnum, port_dict[port_name]['switch'], port_dict[port_name]['id'],
                         port_dict[port_name]['descr'],
                         port_dict[port_name]['usage'], portipg,
                         port_dict[port_name]['speed'], port_dict[port_name]['adminst'],
                         port_dict[port_name]['operst'], port_dict[port_name]['opersterr'],
                         port_dict[port_name]['bundleindex']])
            result_headers = 'Switch, Interface, Description, Usage, IPG, Speed, AdminSt, OperSt, OperSt Error, Aggr'
            result = sorted(result)
            for line in result:
                del line[0]
            ret_dict[result_headers] = result
        else:
            if not port_dict:
                port_dict = self.get_port_dict()
            node = str(switch_dict[match_node]['id'])
            if node + '-' + match_port in port_dict.keys():
                port_name = node + '-' + match_port
                port_dict[port_name]['epg_list'] = epg_list = []
                for epg_dn in port_dict[port_name]['epg']:
                    if '/epg-' in epg_dn:
                        epg_list.append(epg_dn.split('uni/tn-')[1].split('/')[0] + '/' + epg_dn.split('/epg-')[1])
                    if '/instP-' in epg_dn:
                        epg_list.append(epg_dn.split('uni/tn-')[1].split('/')[0] + '/' + epg_dn.split('/instP-')[1])
                    if '/lDevVip-' in epg_dn:
                        epg_list.append(
                            epg_dn.split('uni/tn-')[1].split('/')[0] + '/' + epg_dn.split('/lDevVip-')[1])
                ret_dict = {'03, Switch, Interface, Port Name, Description':
                                [[port_dict[port_name]['switch'], port_dict[port_name]['id'],
                                 port_dict[port_name]['name'], port_dict[port_name]['descr']]],
                            '04, Usage, Speed, AdminSt, OperSt, OperSt Error, Aggr':
                                [[port_dict[port_name]['usage'], port_dict[port_name]['speed'],
                                  port_dict[port_name]['adminst'], port_dict[port_name]['operst'],
                                  port_dict[port_name]['opersterr'], port_dict[port_name]['bundleindex']]],
                            '05, Profile, Selector, Blockname, Blockport, Type, IPG, AEP':
                                [[port_dict[port_name]['leaf_profile'], port_dict[port_name]['selector'],
                                  port_dict[port_name]['blockname'], ','.join(port_dict[port_name]['blockport']),
                                  port_dict[port_name]['type'], port_dict[port_name]['ipg'],
                                  port_dict[port_name]['aep']]
                                 for i in range(0, 1) if port_dict[port_name]['leaf_profile'] != ''],
                            '06, Bridgedomain, Tenant/EPG, Encap, Mode':
                                [[port_dict[port_name]['bd'][i], port_dict[port_name]['epg_list'][i],
                                  port_dict[port_name]['encap'][i], port_dict[port_name]['mode'][i]]
                                 for i in range(0, len(port_dict[port_name]['epg']), 1)],
                            '07, Domain, Domain Type, Pool':
                                [[port_dict[port_name]['domain'][i], port_dict[port_name]['domain_type'][i],
                                  port_dict[port_name]['poolname'][i]]
                                 for i in range(0, len(port_dict[port_name]['domain']), 1)]
                            }
        return ret_dict

    def get_port_stat_table(self, match_node, match_port):
        result = []
        ret_dict = {}
        port_dict = self.get_port_dict('full')
        switch_dict = self.get_switch_dict()
        if match_node is None and match_port is None:
            for port_name in sorted(port_dict.keys()):
                portnum = []
                node = port_dict[port_name]['node']
                for pnum in port_dict[port_name]['id'].split('eth')[1].split('/'):
                    if len(pnum) < 2:
                        pnum = '0' + str(pnum)
                    portnum.append(pnum)
                if len(portnum) > 3:
                    portnum.insert(0, '000')
                nodenum = int(str(node) + '0000000')
                portnum = nodenum + int(''.join(portnum))
                portipg = port_dict[port_name]['ipg'].split('/')[0]
                result.append(
                    [portnum, port_dict[port_name]['switch'], port_dict[port_name]['id'], port_dict[port_name]['name'],
                     port_dict[port_name]['descr'], port_dict[port_name]['speed'],
                     port_dict[port_name]['adminst'] + '/' + port_dict[port_name]['operst'],
                     round(float(port_dict[port_name]['bytesratein']) / 1000000, 3),
                     round(float(port_dict[port_name]['bytesrateout']) / 1000000, 3),
                     port_dict[port_name]['portevent'],
                     port_dict[port_name]['lastevent'], port_dict[port_name]['firstevent']])
                result_headers = 'Switch, Interface, Port Name, Description, Speed, Status, In Mbps, Out Mbps, ' \
                                 'Port Events, Last Event, First Event'
                result = sorted(result)
            for line in result:
                del line[0]
            ret_dict[result_headers] = result
        elif match_node is not None and match_port is None:
            node = str(switch_dict[match_node]['id'])
            for port_name in sorted(port_dict.keys()):
                if node == port_dict[port_name]['node']:
                    portnum = []
                    for pnum in port_dict[port_name]['id'].split('eth')[1].split('/'):
                        if len(pnum) < 2:
                            pnum = '0' + str(pnum)
                        portnum.append(pnum)
                    portnum = int(''.join(portnum))
                    result.append(
                        [portnum, port_dict[port_name]['switch'], port_dict[port_name]['id'],
                         port_dict[port_name]['name'],
                         port_dict[port_name]['descr'], port_dict[port_name]['speed'],
                         port_dict[port_name]['adminst'] + '/' + port_dict[port_name]['operst'],
                         round(float(port_dict[port_name]['bytesratein']) / 1000000, 3),
                         round(float(port_dict[port_name]['bytesrateout']) / 1000000, 3),
                         port_dict[port_name]['portevent'],
                         port_dict[port_name]['lastevent'], port_dict[port_name]['firstevent']])
            result_headers = 'Switch, Interface, Port Name, Description, Speed, Status, In Mbps, Out Mbps, ' \
                             'Port Events, Last Event, First Event'
            result = sorted(result)
            for line in result:
                del line[0]
            ret_dict[result_headers] = result
        else:
            node = str(switch_dict[match_node]['id'])
            if node + '-' + match_port in port_dict.keys():
                port_name = node + '-' + match_port
                ret_dict = {'01, Switch': port_dict[port_name]['switch'],
                            '02, Interface': port_dict[port_name]['id'],
                            '03, Description': port_dict[port_name]['descr'],
                            '04, Usage, Speed, AdminSt, OperSt, OperSt Error, Aggr':
                                [[port_dict[port_name]['usage'], port_dict[port_name]['speed'],
                                  port_dict[port_name]['adminst'], port_dict[port_name]['operst'],
                                  port_dict[port_name]['opersterr'], port_dict[port_name]['bundleindex']]],
                            '05, Rate In, Rate Out, Pkt In, Pkt Out, Port Events, Last Event, First Event':
                                [[str(round(float(port_dict[port_name]['bytesratein']) / 1000000, 3)) + ' Mbps',
                                  str(round(float(port_dict[port_name]['bytesrateout']) / 1000000, 3)) + ' Mbps',
                                  port_dict[port_name]['packetin'], port_dict[port_name]['packetout'],
                                  port_dict[port_name]['portevent'], port_dict[port_name]['lastevent'],
                                  port_dict[port_name]['firstevent']]]
                            }
        return ret_dict

    def get_ipg_table(self, match_node, type, ipg):
        result = []
        ret_dict = {}
        ipg_dict = self.get_ipg_dict()
        if ipg is None:
            for ipg_name in ipg_dict.keys():
                ipg_name = ipg_dict[ipg_name]['name']
                ipg_descr = ipg_dict[ipg_name]['descr']
                ipg_lacp = ipg_dict[ipg_name]['lacp']
                ipg_aep = ipg_dict[ipg_name]['aep']
                ipg_speed = ipg_dict[ipg_name]['speed']
                ipg_cdp = ipg_dict[ipg_name]['cdp']
                ipg_lldp = ipg_dict[ipg_name]['lldp']
                ipg_type = ipg_dict[ipg_name]['type']
                ipg_mcp = ipg_dict[ipg_name]['mcp']
                ipg_l2int = ipg_dict[ipg_name]['l2int']
                if type == ipg_type or type == None:
                    if ipg_type == 'accportgrp': ipg_type = 'direct'
                    if ipg_type == 'accbundle-link': ipg_type = 'dpc'
                    if ipg_type == 'accbundle-node': ipg_type = 'vpc'
                    if ipg == ipg_name or ipg == None:
                        row = [ipg_name, ipg_type, ipg_descr, ipg_lacp, ipg_aep, ipg_speed,
                               ipg_cdp, ipg_lldp, ipg_mcp, ipg_l2int]
                        if match_node in ipg_dict[ipg_name]['nodes'] or \
                                match_node in ipg_dict[ipg_name]['switches'] or match_node == None:
                            result.append(row)

            result_headers = 'IPG name, Type, Description, lacp, AEP, Speed, CDP, LLDP, MCP, L2_INT'
            result = sorted(result)
            ret_dict[result_headers] = result

        else:
            if ipg in ipg_dict.keys():
                ipg_name = ipg
                if ipg_dict[ipg_name]['type'] == 'accportgrp': ipg_type = 'direct'
                if ipg_dict[ipg_name]['type'] == 'accbundle-link': ipg_type = 'dpc'
                if ipg_dict[ipg_name]['type'] == 'accbundle-node': ipg_type = 'vpc'
                ret_dict = {'01, IPG name': ipg_dict[ipg_name]['name'],
                            '02, Type': ipg_type,
                            '03, Description': ipg_dict[ipg_name]['descr'],
                            '04, LACP, AEP, Speed, CDP, LLDP, MCP, L2_INT':
                                [[ipg_dict[ipg_name]['lacp'], ipg_dict[ipg_name]['aep'], ipg_dict[ipg_name]['speed'],
                                  ipg_dict[ipg_name]['cdp'], ipg_dict[ipg_name]['lldp'], ipg_dict[ipg_name]['mcp'],
                                  ipg_dict[ipg_name]['l2int']]],
                            '05, Interfaces, Interface Description, Switches, Node':
                                [[ipg_dict[ipg_name]['interfaces'][i], ipg_dict[ipg_name]['intf_descr'][i],
                                  ipg_dict[ipg_name]['switches'][i], ipg_dict[ipg_name]['nodes'][i]]
                                 for i in range(0, len(ipg_dict[ipg_name]['interfaces']), 1)],
                            '06, Domain, Domain Type, Pool':
                                [[ipg_dict[ipg_name]['domain'][i], ipg_dict[ipg_name]['domain_type'][i],
                                  ipg_dict[ipg_name]['poolname'][i]]
                                 for i in range(0, len(ipg_dict[ipg_name]['domain']), 1)]
                            }
        return ret_dict

    def get_fex_table(self, match_node, ipg):
        result = []
        ret_dict = {}
        fex_dict = self.get_fex_dict()
        for fex_name in fex_dict.keys():
            fex = fex_dict[fex_name]['name']
            fex_descr = fex_dict[fex_name]['descr']
            fex_type = fex_dict[fex_name]['type']
            fex_interfaces = '\n'.join(sorted(fex_dict[fex_name]['interfaces']))
            fex_intf_descr = '\n'.join(sorted(fex_dict[fex_name]['intf_descr']))
            fex_id = '\n'.join(sorted(fex_dict[fex_name]['fexid']))
            fex_nodes = '\n'.join(sorted(fex_dict[fex_name]['nodes']))
            fex_switches = '\n'.join(sorted(fex_dict[fex_name]['switches']))
            row = [fex, fex_type, fex_interfaces, fex_intf_descr, fex_switches, fex_nodes, fex_id]
            if ipg == fex or ipg == None:
                if match_node in fex_dict[fex_name]['nodes'] or match_node in fex_dict[fex_name]['switches'] or \
                        match_node == None: result.append(row)

        result_headers = 'Fex name, Type, Interfaces, Interface Description, Switches, Nodes, Fex id'
        result = sorted(result)
        ret_dict[result_headers] = result
        return ret_dict

    def get_vlan_per_domain_table(self, match_domain=None):
        result = []
        ret_dict = {}
        row1 = []
        row2 = []
        dom_vlan_dict = {}
        vlan_dict = self.get_vlan_dict()
        dom_dict = self.get_domain_dict()

        for domain in dom_dict.keys():
            if 'uni/phys-' in domain:
                dom_name = str(domain.split('uni/phys-')[1])
            elif 'uni/l2dom-' in domain:
                dom_name = str(domain.split('uni/l2dom-')[1])
            elif 'uni/l3dom-' in domain:
                dom_name = str(domain.split('uni/l3dom-')[1])
            elif 'uni/vmmp-VMware/dom-' in domain:
                dom_name = str(domain.split('uni/vmmp-VMware/dom-')[1])
            else:
                dom_name = domain
            dom_vlan_dict[dom_name] = {}
            dom_vlan_dict[dom_name]['name'] = dom_name + '\n' + dom_dict[domain]['poolname']
            dom_vlan_dict[dom_name]['poolname'] = dom_dict[domain]['poolname']
            dom_vlan_dict[dom_name]['opervlan'] = []
            dom_vlan_dict[dom_name]['poolvlan'] = dom_dict[domain]['poolvlan']
            dom_vlan_dict[dom_name]['vlan'] = dom_dict[domain]['vlan']
            dom_vlan_dict[dom_name]['type'] = dom_dict[domain]['type']
        if match_domain == None:
            for dom_name in sorted(dom_vlan_dict.keys())[0:10]:
                row1.append('\n'.join(dom_vlan_dict[dom_name]['poolvlan']))
            for dom_name in sorted(dom_vlan_dict.keys())[10:20]:
                row2.append('\n'.join(dom_vlan_dict[dom_name]['poolvlan']))
            ret_dict['01, ' + ', '.join([dom_vlan_dict[dom]['name']
                                         for dom in sorted(dom_vlan_dict.keys())[0:10]])] = [row1]
            ret_dict['02, ' + ', '.join([dom_vlan_dict[dom]['name']
                                         for dom in sorted(dom_vlan_dict.keys())[10:20]])] = [row2]
            return ret_dict
        else:
            for vlan_name in vlan_dict.keys():
                for dom_name in vlan_dict[vlan_name]['domain']:
                    if dom_vlan_dict[dom_name]['type'] == 'l3extDomP':
                        if '/instP-' in (',').join(vlan_dict[vlan_name]['epg']):
                            dom_vlan_dict[dom_name]['opervlan'].append(int(vlan_dict[vlan_name]['id']))
                    elif dom_vlan_dict[dom_name]['type'] == 'physDomP':
                        if '/epg-' in (',').join(vlan_dict[vlan_name]['epg']):
                            dom_vlan_dict[dom_name]['opervlan'].append(int(vlan_dict[vlan_name]['id']))
                        if '/lDevVip-' in (',').join(vlan_dict[vlan_name]['epg']):
                            dom_vlan_dict[dom_name]['opervlan'].append(int(vlan_dict[vlan_name]['id']))
                    elif dom_vlan_dict[dom_name]['type'] == 'vmmDomP':
                        if '/epg-' in (',').join(vlan_dict[vlan_name]['epg']):
                            dom_vlan_dict[dom_name]['opervlan'].append(int(vlan_dict[vlan_name]['id']))
                    elif dom_vlan_dict[dom_name]['type'] == 'l2extDomP':
                        if '/instP-' in (',').join(vlan_dict[vlan_name]['epg']):
                            dom_vlan_dict[dom_name]['opervlan'].append(int(vlan_dict[vlan_name]['id']))
            for dom_name in sorted(dom_vlan_dict.keys()):
                if match_domain == dom_name:
                    opervlan = []
                    missingvlan = []
                    for vlan in sorted(dom_vlan_dict[dom_name]['opervlan']):
                        if str(vlan) not in opervlan: opervlan.append(str(vlan))
                        if str(vlan) not in missingvlan and int(vlan) not in dom_vlan_dict[dom_name]['vlan']:
                            missingvlan.append(str(vlan))
                    row1.append(dom_name)
                    row1.append(dom_vlan_dict[dom_name]['poolname'])
                    row1.append('\n'.join(opervlan))
                    row1.append('\n'.join(dom_vlan_dict[dom_name]['poolvlan']))
                    row1.append('\n'.join(missingvlan))
        ret_dict['domain, vlanpool, operational vlan, pool vlan, operational vlans missing from pool'] = [row1]
        return ret_dict

    def get_vlan_table(self, vlan=None):
        result = []
        ret_dict = {}
        vlan_dict = self.get_vlan_dict()
        for vlan_name in vlan_dict.keys():
            vlan_dict[vlan_name]['epg_list'] = epg_list = []
            vlan_dict[vlan_name]['epg_tenant'] = epg_tenant_list = []
            for epg_dn in vlan_dict[vlan_name]['epg']:
                if '/epg-' in epg_dn:
                    epg_list.append(epg_dn.split('/epg-')[1])
                    epg_tenant_list.append(epg_dn.split('uni/tn-')[1].split('/')[0])
                elif '/instP-' in epg_dn:
                    epg_list.append(epg_dn.split('/instP-')[1])
                    epg_tenant_list.append(epg_dn.split('uni/tn-')[1].split('/')[0])
                elif '/lDevVip-' in epg_dn:
                    epg_list.append(epg_dn.split('/lDevVip-')[1])
                    epg_tenant_list.append(epg_dn.split('uni/tn-')[1].split('/')[0])
                else:
                    epg_list.append(epg_dn)
                    epg_tenant_list.append('')

            if vlan:
                result_headers = 'Vlan id, Vlan name, AEP, Interface, Description, BD, Tenant, EPG & External-EPG, Mode'
                if vlan == str(vlan_dict[vlan_name]['id']):
                    for i, epg in enumerate(vlan_dict[vlan_name]['interfaces']):
                        row = [int(vlan_dict[vlan_name]['id']), vlan_name, vlan_dict[vlan_name]['aep'][i],
                               vlan_dict[vlan_name]['interfaces'][i], vlan_dict[vlan_name]['intf_descr'][i],
                               vlan_dict[vlan_name]['bd'][i], vlan_dict[vlan_name]['epg_tenant'][i],
                               vlan_dict[vlan_name]['epg_list'][i], vlan_dict[vlan_name]['mode'][i]]
                        result.append(row)
                ret_dict[result_headers] = sorted(result)

            else:
                unique_epg_list = []
                result_headers = 'Vlan id, Vlan name, AEP, BD, Tenant, EPG & External-EPG, Description'
                for i, epg in enumerate(epg_list):
                    if epg not in unique_epg_list:
                        if len(vlan_dict[vlan_name]['aep']) <= i: vlan_dict[vlan_name]['aep'].append('N/A')
                        unique_epg_list.append(epg)
                        if i == 0:
                            row = [int(vlan_dict[vlan_name]['id']), vlan_name, vlan_dict[vlan_name]['aep'][i],
                                   vlan_dict[vlan_name]['bd'][i], vlan_dict[vlan_name]['epg_tenant'][i],
                                   vlan_dict[vlan_name]['epg_list'][i], vlan_dict[vlan_name]['epg_descr'][i]]
                        else:
                            row = [int(vlan_dict[vlan_name]['id']), vlan_name + '+', vlan_dict[vlan_name]['aep'][i],
                                   vlan_dict[vlan_name]['bd'][i], vlan_dict[vlan_name]['epg_tenant'][i],
                                   vlan_dict[vlan_name]['epg_list'][i], vlan_dict[vlan_name]['epg_descr'][i]]
                        result.append(row)
                ret_dict[result_headers] = sorted(result)

        return ret_dict

    def get_host_table(self):
        result = []
        ret_dict = {}

        intf_dict = self.get_intf_dict()
        for intf_name in intf_dict.keys():
            intf_dict[intf_name]['epg_list'] = epg_list = []
            for epg_dn in intf_dict[intf_name]['epg']:
                if '/epg-' in epg_dn:
                    epg_list.append(epg_dn.split('/epg-')[1])
                elif '/instP-' in epg_dn:
                    epg_list.append(epg_dn.split('/instP-')[1])
                elif '/lDevVip-' in epg_dn:
                    epg_list.append(epg_dn.split('/lDevVip-')[1])
                else:
                    epg_list.append(epg_dn)

            try:
                nodenum = int(intf_dict[intf_name]['name'].split('-')[0])
                portnum = []
                for pnum in intf_dict[intf_name]['name'].split('eth')[1].split('/'):
                    if len(pnum) < 2:
                        pnum = '0' + str(pnum)
                    portnum.append(pnum)
                portnum = int(('').join(portnum))
                portipg = intf_dict[intf_name]['ipg'].split('/')[0]
                if len(epg_list) > 1:
                    row = [nodenum, portnum, intf_dict[intf_name]['name'], intf_dict[intf_name]['descr'],
                           portipg, intf_dict[intf_name]['aep'], 'multiple', 'multiple', 'multiple', 'multiple',
                           '\n'.join(intf_dict[intf_name]['encap']), '\n'.join(intf_dict[intf_name]['bd']),
                           '\n'.join(intf_dict[intf_name]['epg_list']), '\n'.join(intf_dict[intf_name]['mode'])]
                else:
                    row = [nodenum, portnum, intf_dict[intf_name]['name'], intf_dict[intf_name]['descr'],
                           portipg, intf_dict[intf_name]['aep'],
                           '\n'.join(intf_dict[intf_name]['encap']), '\n'.join(intf_dict[intf_name]['bd']),
                           '\n'.join(intf_dict[intf_name]['epg_list']), '\n'.join(intf_dict[intf_name]['mode'])]
                result.append(row)
            except:
                pass
        result = sorted(result)
        for line in result:
            del line[1]
            del line[0]
        result_headers = 'Host port, Description, IPG, AEP, VLAN, BD, Tenant/EPG, Mode'
        ret_dict[result_headers] = result
        return ret_dict

    def get_endpoint_table(self, endpoint=None):
        result = []
        ret_dict = {}
        endpoint_dict = self.get_endpoint_dict()
        for endpoint_name in endpoint_dict.keys():
            endpoint_dict[endpoint_name]['epg_list'] = epg_list = []
            for epg_dn in endpoint_dict[endpoint_name]['epg']:
                if '/epg-' in epg_dn:
                    epg_list.append(
                        epg_dn.split('uni/tn-')[1].split('/')[0] + '/' + epg_dn.split('/epg-')[1])
                elif '/BD-' in epg_dn:
                    epg_list.append(
                        epg_dn.split('uni/tn-')[1].split('/')[0] + '/' + epg_dn.split('/BD-')[1].split(']')[0])
                elif '/ctx-' in epg_dn:
                    epg_list.append(
                        epg_dn.split('uni/tn-')[1].split('/')[0] + '/' + epg_dn.split('/ctx-')[1].split(']')[0])
                elif '/lDevVip-' in epg_dn:
                    epg_list.append(
                        epg_dn.split('uni/tn-')[1].split('/')[0] + '/' + epg_dn.split('/lDevVip-')[1].split(']')[0])
                else:
                    epg_list.append(epg_dn)

            if endpoint:
                if endpoint in str(endpoint_dict[endpoint_name]['ip']) or \
                        endpoint.lower() in str(endpoint_dict[endpoint_name]['mac']).lower():
                    for i, epg in enumerate(epg_list):
                        if endpoint_dict[endpoint_name]['type'][i] == 'accportgrp':
                            endpoint_dict[endpoint_name]['type'][i] = 'direct'
                        if endpoint_dict[endpoint_name]['type'][i] == 'accbundle-link':
                            endpoint_dict[endpoint_name]['type'][i] = 'dpc'
                        if endpoint_dict[endpoint_name]['type'][i] == 'accbundle-node':
                            endpoint_dict[endpoint_name]['type'][i] = 'vpc'
                        endpoint_ips = endpoint_dict[endpoint_name]['ip'][i]
                        for endpoint_ip in endpoint_ips:
                            if endpoint in endpoint_ip or endpoint.lower() in endpoint_name.lower():
                                row = [str(ipaddress.ip_address(endpoint_ip)),
                                       endpoint_dict[endpoint_name]['mac'][i],
                                       endpoint_dict[endpoint_name]['epg_list'][i],
                                       endpoint_dict[endpoint_name]['encap'][i],
                                       endpoint_dict[endpoint_name]['type'][i],
                                       endpoint_dict[endpoint_name]['ipg'][i],
                                       '\n'.join(endpoint_dict[endpoint_name]['interfaces'][i])]
                                result.append(row)
            else:
                if ':' in endpoint_name:
                    for i, epg in enumerate(epg_list):
                        if endpoint_dict[endpoint_name]['type'][i] == 'accportgrp':
                            endpoint_dict[endpoint_name]['type'][i] = 'direct'
                        if endpoint_dict[endpoint_name]['type'][i] == 'accbundle-link':
                            endpoint_dict[endpoint_name]['type'][i] = 'dpc'
                        if endpoint_dict[endpoint_name]['type'][i] == 'accbundle-node':
                            endpoint_dict[endpoint_name]['type'][i] = 'vpc'
                        endpoint_ips = endpoint_dict[endpoint_name]['ip'][i]
                        for endpoint_ip in endpoint_ips:
                            row = [str(ipaddress.ip_address(endpoint_ip)),
                                   endpoint_dict[endpoint_name]['mac'][i],
                                   endpoint_dict[endpoint_name]['epg_list'][i],
                                   endpoint_dict[endpoint_name]['encap'][i],
                                   endpoint_dict[endpoint_name]['type'][i],
                                   endpoint_dict[endpoint_name]['ipg'][i],
                                   '\n'.join(endpoint_dict[endpoint_name]['interfaces'][i])]
                            result.append(row)
        result_headers = 'ip, mac, epg & external-egp, encap, type, ipg, Interfaces'
        ret_dict[result_headers] = sorted(result)
        return ret_dict

    def get_lldp_table(self, node=None):
        result = []
        ret_dict = {}
        lldp_dict = self.get_lldp_dict()
        switch_dict = self.get_switch_dict()
        for lldp_name in lldp_dict.keys():
            if ':' in lldp_dict[lldp_name]['remote_port']:
                lldp_dict[lldp_name]['remote_port'] = lldp_dict[lldp_name]['remote_portdesc']
            if 'topology/pod-' in lldp_dict[lldp_name]['remote_sysdesc'] and \
                    '/node-' in lldp_dict[lldp_name]['remote_sysdesc']:
                lldp_dict[lldp_name]['remote_sysdesc'] = 'Cisco ACI'
            if node:
                if node in switch_dict.keys():
                    node_id = str(switch_dict[node]['id'])
                    if node_id == str(lldp_dict[lldp_name]['local_name']):
                        row = [str(switch_dict[lldp_dict[lldp_name]['local_name']]['name']),
                               lldp_dict[lldp_name]['name'], lldp_dict[lldp_name]['remote_name'],
                               ' '.join([sysdesc for i, sysdesc in enumerate(
                                   lldp_dict[lldp_name]['remote_sysdesc'].replace('"', '').split(' ')) if i < 2 and
                                         sysdesc != lldp_dict[lldp_name]['remote_name']]),
                               lldp_dict[lldp_name]['remote_port'],
                               lldp_dict[lldp_name]['remote_mgmtip'], lldp_dict[lldp_name]['remote_mac']]
                        result.append(row)
            else:
                row = [str(switch_dict[lldp_dict[lldp_name]['local_name']]['name']),
                       lldp_dict[lldp_name]['name'], lldp_dict[lldp_name]['remote_name'],
                       ' '.join([sysdesc for i, sysdesc in enumerate(
                           lldp_dict[lldp_name]['remote_sysdesc'].replace('"', '').split(' ')) if i < 2 and
                                 sysdesc != lldp_dict[lldp_name]['remote_name']]), lldp_dict[lldp_name]['remote_port'],
                       lldp_dict[lldp_name]['remote_mgmtip'], lldp_dict[lldp_name]['remote_mac']]
                result.append(row)
        result_headers = 'switch, local port, remote device , remote make , remote port, remote mgmt ip, remote mac'
        ret_dict[result_headers] = sorted(result)
        return ret_dict

    def get_snapshot_table(self):
        result = []
        ret_dict = {}
        snapshot_dict = self.get_snapshot_dict()
        for snapshot_name in snapshot_dict:
            row = [snapshot_dict[snapshot_name]['name'], snapshot_dict[snapshot_name]['filename'],
                   snapshot_dict[snapshot_name]['descr'], snapshot_dict[snapshot_name]['target']]
            result.append(row)
        result_headers = 'Name, Filename, Description, Target'
        ret_dict[result_headers] = sorted(result, reverse=True)
        return ret_dict

    def get_xml_from_json(self, result_json):

        child1 = None
        child2 = None
        child3 = None
        child4 = None
        children1 = []
        children2 = []
        children3 = []
        children4 = []
        children5 = []
        result = []

        for json_file in result_json:
            data = json.dumps(json_file, sort_keys=True)
            data = json.loads(data)
            for parent in data.keys():
                if 'attributes' in data[parent]:
                    result.append('  ' + '<' + str(parent))
                    for attribute in sorted(data[parent]['attributes'].keys()):
                        result.append(' ' + attribute + '="' + data[parent]['attributes'][attribute] + '"')
                if 'children' in data[parent]:
                    children1 = data[parent]['children']
                else:
                    children1 = []
                if children1 == []:
                    result.append('/>\n')
                else:
                    result.append('>\n')
                for data1 in children1:
                    for child1 in data1.keys():
                        if 'attributes' in data1[child1]:
                            result.append('    ' + '<' + str(child1))
                            for attribute in sorted(data1[child1]['attributes'].keys()):
                                result.append(' ' + attribute + '="' + data1[child1]['attributes'][attribute] + '"')
                        if 'children' in data1[child1]:
                            children2 = data1[child1]['children']
                        else:
                            children2 = []
                        if children2 == []:
                            result.append('/>\n')
                        else:
                            result.append('>\n')
                        for data2 in children2:
                            for child2 in data2.keys():
                                if 'attributes' in data2[child2]:
                                    result.append('      ' + '<' + str(child2))
                                    for attribute in sorted(data2[child2]['attributes'].keys()):
                                        result.append(
                                            ' ' + attribute + '="' + data2[child2]['attributes'][attribute] + '"')
                                if 'children' in data2[child2]:
                                    children3 = data2[child2]['children']
                                else:
                                    children3 = []
                                if children3 == []:
                                    result.append('/>\n')
                                else:
                                    result.append('>\n')
                                for data3 in children3:
                                    for child3 in data3.keys():
                                        if 'attributes' in data3[child3]:
                                            result.append('        ' + '<' + str(child3))
                                            for attribute in sorted(data3[child3]['attributes'].keys()):
                                                result.append(' ' + attribute + '="' + data3[child3]['attributes'][
                                                    attribute] + '"')
                                        if 'children' in data3[child3]:
                                            children4 = data3[child3]['children']
                                        else:
                                            children4 = []
                                        if children4 == []:
                                            result.append('/>\n')
                                        else:
                                            result.append('>\n')
                                        for data4 in children4:
                                            for child4 in data4.keys():
                                                if 'attributes' in data4[child4]:
                                                    result.append('          ' + '<' + str(child4))
                                                    for attribute in sorted(data4[child4]['attributes'].keys()):
                                                        result.append(
                                                            ' ' + attribute + '="' + data4[child4]['attributes'][
                                                                attribute] + '"')
                                                if 'children' in data4[child4]:
                                                    children5 = data4[child4]['children']
                                                else:
                                                    children5 = []
                                                if children5 == []:
                                                    result.append('/>\n')
                                                else:
                                                    result.append('>\n')
                                                print (children5, 'not converted')
                                            if children5 != []: result.append(
                                                '          ' + '</' + str(child4) + '>' + '\n')
                                    if children4 != []: result.append('        ' + '</' + str(child3) + '>' + '\n')
                            if children3 != []: result.append('      ' + '</' + str(child2) + '>' + '\n')
                    if children2 != []: result.append('    ' + '</' + str(child1) + '>' + '\n')
            if children1 != []: result.append('  ' + '</' + str(parent) + '>' + '\n')
            result.append('\n')

        result = ''.join(result)
        return result

    def mso_login(self, uid, pwd):
        data = {"username": uid, "password": pwd, "domainId": self.mso_domainid}
        login_url = self.mso_url + '/api/v1/auth/login'
        self.mso_mysession = requests.Session()
        try:
            post_resp = self.mso_mysession.post(login_url, json=data, verify=False)
            post_resp_data = json.loads(post_resp.text)
            if post_resp.ok:
                self.mso_token = post_resp_data['token']
                print ('mso token is ', self.mso_token)
                return self.mso_token
            else:
                print ('Could not login to MSO: ', self.mso_url, post_resp, post_resp.text)
                return None

        except:
            print ('Exception Could not connect to MSO: ', self.mso_url)
            return None


    def mso_logout(self):
        self.mso_mysession.close()
        self.mso_mysession = None

    def mso_get_schema(self, schema_id=None):
        get_url = self.mso_url + '/api/v1/schemas'
        if schema_id: get_url = self.mso_url + '/api/v1/schemas/'+ schema_id
        resp = self.mso_mysession.get(get_url, verify=False, headers = {'Authorization': 'Bearer ' + self.mso_token})

        result = json.loads(resp.text)
        return result

    

def get_data3(result, grep_list=None):
    data = {}
    data['header'] = []
    data['row'] = []
    data['rows'] = ''
    j = 0
    for key in sorted(result.keys()):
        if not isinstance(result[key], list):
            result[key] = [[result[key]]]
        if isinstance(result[key], list):
            if grep: result[key] = grep(result[key], grep_list)
            if result[key] != []:
                if len(result.keys()) == 1:
                    data['header'] = key.split(',')
                    data['row'] = [result[key]]
                else:
                    headers = ''
                    rows = ''
                    data['header'] = None
                    headers = headers + '<tr bgcolor="#ceceff">'
                    for header in key.split(',')[1:]:
                        headers = headers + '<td style="white-space: pre-line; background: #ceceff;"><b>' + \
                                  str(header) + '</b></td>'
                    headers = headers + '</tr>'
                    data['rows'] = data['rows'] + headers

                    rows = rows + '<tr>'
                    for rowkeys in result[key]:
                        for row in rowkeys:
                            rows = rows + '<td style="white-space: pre; color: #333355ba;">' + str(row) + '</td>'
                        rows = rows + '</tr>'
                    data['rows'] = data['rows'] + rows

    return data


def get_data4(result, grep_list=None):
    data = {}
    data['header'] = []
    data['row'] = []
    data['rows'] = ''
    for key in sorted(result.keys()):
        if not isinstance(result[key], list):
            print (key.split(', ')[1] + ': ' + result[key])
    for key in sorted(result.keys()):
        if not isinstance(result[key], list):
            data['row'].append([[key.split(', ')[1] + ': ' + result[key]]])
        if isinstance(result[key], list):
            if grep: result[key] = grep(result[key], grep_list)
            if result[key] != []:
                if len(result.keys()) == 1:
                    data['header'] = key.split(',')
                    data['row'] = result[key]
                else:
                    headers = ''
                    rows = ''
                    data['header'] = None
                    headers = headers + '<tr bgcolor="#ceceff">'
                    for header in key.split(',')[1:]:
                        headers = headers + '<td style="white-space: pre-line"><b>' + str(header) + '</b></td>'
                    headers = headers + '</tr>'
                    data['rows'] = data['rows'] + headers

                    rows = rows + '<tr>'
                    for rowkeys in result[key]:
                        for row in rowkeys:
                            rows = rows + '<td style="white-space: pre-line; color: #333355ba;">' + str(row) + '</td>'
                        rows = rows + '</tr>'
                    data['rows'] = data['rows'] + rows

    return data

def get_data5(result):
    data = {}
    data['header'] = []
    data['row'] = []
    for key in sorted(result.keys()):
        if result[key] != []:
            data['header'] = key.split(',')
            data['row'] = result[key]
        else:
            data['header'] = key.split(',')
    return data

def grep(resultin, grep_list):
    resultout = resultin
    if grep_list:
        resultout = [line for line in resultin if str(grep_list).lower().strip() in str(line).lower()]
    return resultout


def generate_auth_token(login, password, url, apic):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return s.dumps({'login': login, 'password': password, 'url': url, 'apic': apic})


def verify_auth_token(token):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(str(token), max_age=12600)
        if data is None:
            data = {}
    except SignatureExpired:
        return {}
    except BadSignature:
        return {}
    return data


app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = binascii.hexlify(os.urandom(24))
app.config['CSRF_ENABLED'] = True
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
CSRFProtect(app)
userlog = []

#'site', 'apic_display_name', 'apic_ip', 'apic_dnsname', "siteid", 'schema', 'template_name', 'mso_url', 'login_domain'

apic_dict = {
            'sandboxapic': ['SBX', 'sandboxapicdc', 'sandboxapicdc.cisco.com', 'sandboxapicdc.cisco.com',
                            "5e21cfbbf90000f300c7345a", '5e21d0da2100005d01915aa8', 'sm-one-Template',
                            'https://192.168.230.135', '0000ffff0000000000000090'],
            }
apic_list = sorted(apic_dict.keys())
apic_list.insert(0, 'Choose APIC')

class aciapp(BaseView):
    @expose('/')
    def index(self):
        variable = request.args.get('variable')
        token = request.args.get('token')
        if variable:
            return redirect(url_for('aciapp.show_table', token=token, grep='', dest='tenant'))
        if token:
            token_data = verify_auth_token(token)
            if token_data:
                login = token_data.get('login')
                password = token_data.get('password')
                url = token_data.get('url')
                apic = token_data.get('apic')
                if login == None: login = ''
                if password == None: password = ''
            else:
                login = ''
                password = ''
                url = ''
                apic = None
                token = ''
            formaction = "/aciapp/credential"
            formname = 'token'
            return render_template('index.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                   apic_list=apic_list, username=login, password=password, url=url)
        else:

            login = ''
            password = ''
            url = ''
            apic = None
            token = ''
            if login == None: login = ''
            if password == None: password = ''
            formaction = "/aciapp/credential"
            formname = ''
            return render_template('index.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                   apic_list=apic_list, username=login, password=password, url=url)

    @expose('/credential', methods=['GET', 'POST'])
    def credentials(self):
        login = str(request.form['username'])
        password = str(request.form['password'])
        selectapic = str(request.form['selectapic'])
        apic = apic_dict[selectapic][2]
        url = "https://" + apic
        aci = aciDB(url)
        login_apic = aci.login(login, password, url)
        if login_apic:     
            token = generate_auth_token(login, password, url, selectapic)
        else:
            token = ''
        aci.logout()
        return redirect(url_for('aciapp.index', variable=login_apic, token=token))
  
    @expose('/table')
    def show_table(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            return render_template('app.html', apic=apic, username=login, url=url, token=token)
        except:
            token = request.args.get('token')
            return redirect(url_for('aciapp.index', token=token))

    @expose('/table.json')
    @expose('/tabletenant.json')
    def tenanttable_json(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB(url)
            login_apic = aci.login(login, password, url)
            tenant_name = request.args.get('tenant_name')
            grep_list = request.args.get('grep')
            result = aci.get_tenant_table(tenant_name)
            data = get_data3(result, grep_list)
            row_url = ['href=table?token=' + token + '&dest=tenant&grep=''&tenant_name=', '', '', '',
                       'href=table?token=' + token + '&dest=bd&grep=''&tenant_name=', '',
                       'href=table?token=' + token + '&dest=epg&grep=''&tenant_name=',
                       'href=table?token=' + token + '&dest=contract&grep=''&tenant_name=', '']
            data['row_url'] = row_url
            data['title'] = 'Display Tenant list'
            aci.logout()
            return jsonify(data)
        except:
            return {}

    @expose('/tablebd.json')
    def bdtable_json(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB(url)
            login_apic = aci.login(login, password, url)
            tenant_name = request.args.get('tenant_name')
            bd_name = request.args.get('bd_name')
            if bd_name:
                bd_name = bd_name.split('/')[-1]
                if bd_name.startswith('*'):
                    bd_name = bd_name.replace('*', '', 1)
            grep_list = request.args.get('grep')
            result = aci.get_bd_table(tenant_name, bd_name)
            data = get_data3(result, grep_list)
            row_url = ['href=table?token=' + token + '&dest=bd&grep=''&bd_name=', '', '', '', '', '', '',
                           'href=table?token=' +
                           token + '&dest=epg&grep=''&epg_bd=', '', '']
            data['row_url'] = row_url
            data['title'] = 'Display BridgeDomain list'
            aci.logout()
            return jsonify(data)
        except:
            return {}

    @expose('/tableepg.json')
    def epgtable_json(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB(url)
            login_apic = aci.login(login, password, url)
            tenant_name = request.args.get('tenant_name')
            epg_name = request.args.get('epg_name')
            epg_bd = request.args.get('epg_bd')
            grep_list = request.args.get('grep')
            if epg_bd:
                grep_list = epg_bd.split('/')[-1]
            result = aci.get_epg_table(tenant_name, epg_name)
            data = get_data3(result, grep_list)
            row_url = ['href=table?token=' + token + '&dest=tenant&grep=''&tenant_name=', '',
                       'href=table?token=' + token + '&dest=epg&grep=''&epg_name=', '', '',
                       'href=table?token=' + token + '&dest=bd&grep=', '',
                       'href=table?token=' + token + '&dest=vlan&grep=', '', '', '']
            data['row_url'] = row_url
            data['title'] = 'Display EPG list'
            aci.logout()
            return jsonify(data)
        except:
            return {}

    @expose('/tableendpoint.json')
    def endpointtable_json(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB(url)
            login_apic = aci.login(login, password, url)
            grep_list = request.args.get('grep')
            result = aci.get_endpoint_table(None)
            data = get_data3(result, grep_list)
            row_url = ['', '', '', '', '', '', '', '', '' ]
            data['row_url'] = row_url
            data['title'] = 'Display Endpoint list'
            aci.logout()
            return jsonify(data)
        except:
            return {}

    @expose('/tablecontract.json')
    def contracttable_json(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB(url)
            login_apic = aci.login(login, password, url)
            grep_list = request.args.get('grep')
            result = aci.get_contract_table(None, None)
            data = get_data3(result, grep_list)
            row_url = ['', '', '', '', '', '', '', '', '' ]
            data['row_url'] = row_url
            data['title'] = 'Display Contract list'
            aci.logout()
            return jsonify(data)
        except:
            return {}

    @expose('/tablehost.json')
    def hosttable_json(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB(url)
            login_apic = aci.login(login, password, url)
            grep_list = request.args.get('grep')
            result = aci.get_host_table()
            result_list = result[list(result.keys())[0]]
            if grep_list: result_list = grep(result_list, grep_list)
            result[list(result.keys())[0]] = [line[0:8] for line in result_list]
            data = get_data3(result)
            row_url = ['href=table?token=' + token + '&dest=port&grep=''&port_name=', '',
                       'href=table?token=' + token + '&dest=ipg&grep=''', '', '', '', '', '', '', '']
            data['row_url'] = row_url
            data['title'] = 'Display Host list'
            aci.logout()
            return jsonify(data)
        except:
            return {}

    @expose('/tableport.json')
    def porttable_json(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB(url)
            login_apic = aci.login(login, password, url)
            node = request.args.get('node')
            port = request.args.get('port')
            port_name = request.args.get('port_name')
            if port_name:
                if '-' in port_name:
                    node = port_name.split('-')[0]
                    port = port_name.split('-')[1]
            grep_list = request.args.get('grep')
            result = aci.get_port_table(node, port)
            data = get_data3(result, grep_list)
            row_url = ['href=table?token=' + token + '&dest=port&grep=''&port_name=', '', '',
                       'href=table?token=' + token + '&dest=ipg&grep=''', '', '', '', '', '', '', '']
            data['row_url'] = row_url
            data['title'] = 'Display Port list'
            aci.logout()
            return jsonify(data)
        except:
            return {}

    @expose('/tableportstat.json')
    def portstattable_json(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB(url)
            login_apic = aci.login(login, password, url)
            grep_list = request.args.get('grep')
            result = aci.get_port_stat_table(None, None)
            data = get_data3(result, grep_list)
            row_url = ['', '', '', '', '', '', '', '', '' ]
            data['row_url'] = row_url
            data['title'] = 'Display Port Statistics list'
            aci.logout()
            return jsonify(data)
        except:
            return {}

    @expose('/tableipg.json')
    def ipgtable_json(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB(url)
            login_apic = aci.login(login, password, url)
            grep_list = request.args.get('grep')
            result = aci.get_ipg_table(None, None, None)
            data = get_data3(result, grep_list)
            row_url = ['', '', '', '', '', '', '', '', '' ]
            data['row_url'] = row_url
            data['title'] = 'Display IPG list'
            aci.logout()
            return jsonify(data)
        except:
            return {}

    @expose('/tablefex.json')
    def fextable_json(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB(url)
            login_apic = aci.login(login, password, url)
            grep_list = request.args.get('grep')
            result = aci.get_fex_table(None, None)
            data = get_data3(result, grep_list)
            row_url = ['', '', '', '', '', '', '', '', '' ]
            data['row_url'] = row_url
            data['title'] = 'Display Fex list'
            aci.logout()
            return jsonify(data)
        except:
            return {}

    @expose('/tablevlan.json')
    def vlantable_json(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB(url)
            login_apic = aci.login(login, password, url)
            vlan = request.args.get('vlan')
            grep_list = request.args.get('grep')
            result = aci.get_vlan_table(vlan)
            data = get_data3(result, grep_list)
            if vlan:
                row_url = ['href=table?token=' + token + '&dest=vlan&grep=''&vlan=',
                           'href=table?token=' + token + '&dest=vlan&grep=',
                           '', 'href=table?token=' + token + '&dest=port&port_name=', '',
                           'href=table?token=' + token + '&dest=bd&bd_name=',
                           'href=table?token=' + token + '&dest=tenant&tenant_name=',
                           'href=table?token=' + token + '&dest=epg&epg_name=', '']
            else:
                row_url = ['href=table?token=' + token + '&dest=vlan&grep=''&vlan=',
                           'href=table?token=' + token + '&dest=vlan&grep=',
                           '', 'href=table?token=' + token + '&dest=bd&bd_name=',
                           'href=table?token=' + token + '&dest=tenant&tenant_name=',
                           'href=table?token=' + token + '&dest=epg&epg_name=', '', '', '']
            data['row_url'] = row_url
            data['title'] = 'Display Vlan list'
            aci.logout()
            return jsonify(data)
        except:
            return {}

    @expose('/tablevlandomain.json')
    def vlandomaintable_json(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB(url)
            login_apic = aci.login(login, password, url)
            grep_list = request.args.get('grep')
            result = aci.get_vlan_per_domain_table(None)
            data = get_data3(result, grep_list)
            row_url = ['', '', '', '', '', '', '', '', '' ]
            data['row_url'] = row_url
            data['title'] = 'Display Vlan Per Domain list'
            aci.logout()
            return jsonify(data)
        except:
            return {}

    @expose('/tablelldp.json')
    def lldptable_json(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB(url)
            login_apic = aci.login(login, password, url)
            grep_list = request.args.get('grep')
            result = aci.get_lldp_table(None)
            data = get_data3(result, grep_list)
            row_url = ['', '', '', '', '', '', '', '', '' ]
            data['row_url'] = row_url
            data['title'] = 'Display LLDP list'
            aci.logout()
            return jsonify(data)
        except:
            return {}

    @expose('/tablenode.json')
    def nodetable_json(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB(url)
            login_apic = aci.login(login, password, url)
            grep_list = request.args.get('grep')
            result = aci.get_switch_table(None, None)
            data = get_data3(result, grep_list)
            row_url = ['', '', '', '', '', '', '', '', '' ]
            data['row_url'] = row_url
            data['title'] = 'Display Node list'
            aci.logout()
            return jsonify(data)
        except:
            return {}

    @expose('/tablesnapshot.json')
    def snapshottable_json(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB(url)
            login_apic = aci.login(login, password, url)
            grep_list = request.args.get('grep')
            result = aci.get_snapshot_table()
            data = get_data3(result, grep_list)
            row_url = ['', '', '', '', '', '', '', '', '' ]
            data['row_url'] = row_url
            data['title'] = 'Display Snapshot list'
            aci.logout()
            return jsonify(data)
        except:
            return {}
    

admin = Admin(app, url='/', base_template='index-static.html', )

admin.add_view(aciapp(name='aciapp'))

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port='8888', url_scheme='http')

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import time
import argparse
import requests
import json


def get_release(build):
    rel = build.split('.')[0]
    if len(rel) == 2:
        release = '%s.%s' % (rel[0], rel[1])
    elif len(rel) == 4:
        release = '%s.%s.%s' % (rel[0], rel[1], rel[2:])
    else:
        raise RuntimeError('get base release failed')
    return release


parser = argparse.ArgumentParser()
parser.add_argument('-b', '--build', required=True)
parser.add_argument('-g', '--group', required=True)
args = parser.parse_args()

#group_list = ['weekly', 'TIREPORT_P2P', 'PORTPROT']
#group_list = ['6101_StandAlone_Sanity_CX']
group_list = args.group.split(',')
pending_list = []

for group in group_list:
    rep_url = 'https://smartservice.int.nokia-sbell.com/TIAReport?&release=%s&build=%s\
&coverage=Weekly&reporttype=Group&domainType=%s' % (get_release(args.build), args.build, group)
    print('report url is: %s' % rep_url)

    url = 'https://smartservice.int.nokia-sbell.com/getSummery?release=%s&build=%s&coverage=Weekly\
&reporttype=Group&domainType=%s&includePlatform=yes' % (get_release(args.build), args.build, group)
    print('get pending TI for group ' + group)
    ret = requests.get(url, timeout=900, verify=False)
    assert(ret.status_code == 200)
    result = json.loads(ret.text)
    if result[args.build]['summary']['PENDINGCLASSIFICATIONS'] > 0:
        pending_list.extend(result[args.build]['summary']['PENDINGCLASSIFICATIONSList'])
    else:
        print('group %s all TI done' % group)


if len(pending_list) == 0:
    print('all TI done')


platform_list = set([x['jobName'] for x in pending_list])
for platform in platform_list:
    result_url = 'https://smartservice.int.nokia-sbell.com/Result/?jobNameFilter=%s&\
buidIDFilter=%s' % (platform, args.build)
    print(result_url)
    pending_list_platform = [x for x in pending_list if x['jobName'] == platform]
    for TI in pending_list_platform:
        if TI['Domain'] == '' and 'P2P' in TI['jobName']:
            TI['Domain'] = 'P2P'
        if TI['Domain'] == '' and 'A2A' in TI['jobName']:
            TI['Domain'] = 'A2A'
        if TI['Domain'] == '' and 'PORTPROT' in TI['jobName']:
            TI['Domain'] = 'A2A'
        if TI['Domain'] == '' and 'REDUN' in TI['jobName'] and 'PORTPROT' not in TI['jobName']:
            TI['Domain'] = 'REDUN'
        print('\t%10s\t\t%40s\t\t%50s' % (TI['Domain'], TI['ATCName'][:40], TI['jobName']))



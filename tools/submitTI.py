#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import xlrd
import argparse
import pdb
import getpass
import requests
from contextlib import contextmanager

parser = argparse.ArgumentParser()
parser.add_argument('-f', '--exfile', default='dwerferferf', required=True,
    help='excel file: \\135.251.206.152\\pt\\Automation\\TI_analysis\\A2A\\57.069_NFXSE_FANTF_REDUND_PORTPROT_weekly.xls')
parser.add_argument('-A', '--all', action="store_true", default=False, help='fill for all TI')
args = parser.parse_args()


def get_TI_result_excel(exfile):

    TI_result = {}

    try:
        data = xlrd.open_workbook(exfile)
    except Exception as e:
        print ('===> open excel file %s failed: %s' % (exfile, str(e)))
        exit(-1)

    table = data.sheets()[0]

    for case in range(1, table.nrows):
        if table.row_values(case)[2]=='TI':
            case_name = table.row_values(case)[0]
            TI_type = table.row_values(case)[6]
            NTI = table.row_values(case)[8].upper()
            fr_id = table.row_values(case)[5]
            commnt= table.row_values(case)[9]

            #assert(TI_type in ['ATC', 'SW', 'ENV', 'NonReproducible', 'Inconsistent'])
            #assert(NTI in ['YES', 'NO'])
            if TI_type not in ['ATC', 'SW', 'ENV', 'NonReproducible', 'Inconsistent']:
                print('===> wrong TI type, must be ATC/SW/ENV/NonReproducible/Inconsistent')
                exit(-1)
            if NTI not in ['YES', 'NO']:
                print('===> new TI must be YES or NO')
                exit(-1)

            TI_result[case_name] = dict(TI_type=TI_type, NTI=NTI, fr_id=fr_id, commnt=commnt)

    data.release_resources()
    return TI_result


def TI_fill_result(s, TI_case, username='no one'):
    TI_id, version, batch = TI_case[1], TI_case[3], TI_case[4]
    print('fill TI result: ', ' '.join(TI_case[1:5]))
    TI_type = TI_result[TI_case[5]]['TI_type']
    NTI     = TI_result[TI_case[5]]['NTI']
    fr_id   = TI_result[TI_case[5]]['fr_id']
    commnt  = TI_result[TI_case[5]]['commnt']

    print(TI_type, NTI, fr_id, commnt)
    url = "http://135.249.31.173/webtia/modalpopup.php?id=%s" % batch
    payload = {
        'form_margin_remove_length': '10',
        'id': batch,
        'Sno_it[]': TI_id,
        'Select_box[]': TI_id,
        'TI[%s]'%TI_id : TI_type,
        'NTI[%s]'%TI_id : NTI,
        'fr_id[%s]'%TI_id : fr_id,
        'commnt[%s]'%TI_id : commnt,
        'User_name[%s]'%TI_id : username,
        'auto_suggest[%s]'%TI_id : '',
        'formSubmit' : 'Save',
    }
    #print(payload)
    r = s.post(url, payload)
    if '#alert-pass' in r.text:
        print('\t\tsuccess')


def get_pending_TI(product='FTTU', batch='FTTU_SETUP_weekly', version='', all_TI=False):

    pending = []
    url = 'http://135.249.31.114/cgi-bin/test/ti_info.cgi?sRelease=&sBuild=%s&sPlatform=%s&sAtc=&sBoard=&sTiType=&sPt=%s'
    print('===> get pending TI from webtia: %s, %s' % (product, batch))
    uu = url % (version, batch, product)
    #print(uu)
    try:
        import requests
        r = requests.get(uu)
        data = r.content.decode('utf-8')
    except:
        print('===> get TI data from TIAWeb failed')
        exit(-1)

    result = re.findall('<tr><td>.*?</td></tr>', data)
    for case in result:
        case_info = [x.replace('</td>', '').replace('<td>', '') for x in case.split('<td align=left>')]
        if all_TI:
            print(case_info[1:7])
            pending.append(case_info[:10])
        else:
            if case_info[10]=='':
                print(case_info[1:7])
                pending.append(case_info[:10])

    return pending


@contextmanager
def webtia_session(username, password):
    print('login')
    s = requests.Session()
    payload = {'redi': 'index.php', 'pid': username, 'password':password, 'btnsubmit': 'login'}
    r = s.post("http://135.249.31.173/webtia/login.php", data=payload)

    if r.status_code== 200 and b'Authenticate successful' in r.content:
        print('===> login successful')
    else:
        print('===> login failed with %s %s' % (username, '*********'))
        exit()
    yield s
    print('logout')




if __name__ == '__main__':

    exfile = os.path.basename(args.exfile)
    version = exfile.split('_')[0]
    batch = '_'.join(exfile.split('_')[1:])
    batch = batch.split('.')[0]
    product = 'FTTU' if 'PORTPROT' not in batch else 'PORTPROT'
    print('===> product: %s;  version: %s;  batch: %s' % (product, version, batch))


    print('\n\n' + '#'*80)
    print('===> pending case list:')
    pending_case = get_pending_TI(product, batch, version, all_TI=args.all)
    if not pending_case:
        print('===> no pending TI')
        exit()


    print('\n\n' + '#'*80)
    print('===> search TI result from excel file:')
    TI_result = get_TI_result_excel(args.exfile)
    for case in pending_case:
        case_name = case[5]
        if case_name not in TI_result:
            print('===> not found TI result from excel file for case: %s' % case_name)
            continue
        print('===> TI_result: %s' % str(TI_result[case_name]))


    print('\n\n' + '#'*80)
    username = raw_input('please input your username:')
    password = getpass.getpass('password:')

    print('\n\n' + '#'*80)
    print('===> fill TI result to website:')

    with webtia_session(username, password) as s:
        for case in pending_case:
            if case[5] in TI_result:
                TI_fill_result(s, case, username=username)


    print('\n\n' + '#'*80)
    print('===> pending case list after auto fill:')
    pending_case = get_pending_TI(product, batch, version)


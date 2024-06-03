from seatable_api import Base, context
import argparse
import yaml
import os
import json
import requests
import re
import sys
import tqdm
HOME_DIR = os.getenv('HOME')
REPO_DIR = HOME_DIR + '/awesome-tool-content'
sys.path.append(os.path.join(os.path.dirname(__file__), '..')) 

from EDR import edr_connection
from EDR import edr_rule
from SIEM import siem_connection
from SIEM import siem_rule
from Model import RuleContent

http_proxy  = 'http://192.168.5.8:3128'
https_proxy = 'https://192.168.5.8:3128'
ftp_proxy   = 'ftp://192.168.5.8:3128'


proxies = { 
              'http'  : http_proxy, 
              'https' : https_proxy, 
              'ftp'   : ftp_proxy
            }
def get_tech_name(tech_id):
    x = requests.get('http://attack.mitre.org/techniques/'+tech_id.replace('.','/'), proxies = proxies)
    al = x.text
    al = al[al.find('<title>') + 7 : al.find('</title>')].split(',')[0]
    return al




server_url = 'https://seatable.viettelcyber.com'
base = ''

''' format json for red docs
{
    'case x': {
        blue: {

        },
        red: {
            'test_name' : ,
            'platform' : ,
            'setup' : ,
            'script_attack' : ,
            'events' : {
                'edr' : '<path-to-json-edr>',
                'siem' : '<path-to-json-siem>',
                'nsm' : '<path-to-pcap-file>'
            },
        }

    },
    'case x+1':  [
        ...
    ]
}
'''

red_form = '''
later :/

'''


blue_from = '''# {}

**Description**: {}

## Rule link
[{}](../../rules/{}/{}.zip)

## Rule Detail
{}

## Testcase
{}


## Mitre ATT&CK

{}

## Reference
{}
'''

def auth_seatable(key):
    with open(REPO_DIR + '/config/config.json', 'r') as f:
        api_token = json.load(f)[key]['access_token']
    base = Base(api_token, server_url)
    try:
        base.auth()
        print ('[ + ] Auth successed for token ' + api_token[::-1][10:][::-1] + 'x'*10)
    except:
        print ('[ - ] Auth failed')
    return base

def auth_edr():
    with open(REPO_DIR + '/config/config.json', 'r') as f:
        user_info = json.load(f)
        username = user_info['vcs_ajiant']['username']
        password = user_info['vcs_ajiant']['password']
    cookie, access_token = edr_connection.login(username, password)

    return cookie #, access_token

def auth_siem():
    with open(REPO_DIR + '/config/config.json', 'r') as f:
        user_info = json.load(f)
        username = user_info['vcs_cym']['username']
        password = user_info['vcs_cym']['password']
    cookie, access_token = siem_connection.login(username, password)

    return cookie #, access_token


def check_dir(path):
    if not os.path.exists(path):   
        # print('[ - ] Folder ' + path + ' not exist')
        os.mkdir(path)
        # print('[ + ] Created folder') 

def parser_(base):
    tables = [x['name'] for x in base.get_metadata()['tables']][:-1]
    idx = 0
    check_dir(REPO_DIR + '/output/testcase')
    check_dir(REPO_DIR + '/output/testcase/EDR/')
    check_dir(REPO_DIR + '/output/testcase/SIEM/')  
    check_dir(REPO_DIR + '/output/parser_for_all/')
    check_dir(REPO_DIR + '/output/rules')
    for table_name in tqdm.notebook.tqdm_notebook(tables, desc='[ O ] Parsing technique '):
        json_output = {}
        rows = base.list_rows(table_name)
        check_dir(REPO_DIR + '/output/testcase/EDR/'+table_name)
        check_dir(REPO_DIR + '/output/testcase/SIEM/'+table_name)

        for row in tqdm.notebook.tqdm_notebook(rows, desc='[ O ] Parsing testcase'):
            test_name, description, platform, config, script, json_edr, json_siem, ref = ['N/A']*8
            events = {}
            rule = {}
            # check if rule exist -> get test name, description, platform, config, script, json, ref
            if 'RULE NAME EDR' in row or 'RULE NAME SIEM' in row or 'RULE NAME KIAN' in row or 'PCAP FILE' in row :
                idx += 1
                case_name = 'Content-red-team-attack-case-'+str(idx)
                if 'TEST NAME' in row:
                    test_name = row['TEST NAME']
                if 'DESCRIPTION' in row:
                    description = row['DESCRIPTION']
                if 'PLATFORM' in row:
                    platform = row['PLATFORM']
                if 'SETUP/CONFIG' in row:
                    config = row['SETUP/CONFIG']     
                if 'SCRIPT ATTACK' in row:
                    script = row['SCRIPT ATTACK']     
                if 'JSON EDR' in row:
                    jedr_out = []
                    json_edr = row['JSON EDR'].splitlines()          
                    with open(REPO_DIR + '/output/testcase/EDR/'+ table_name + '/' + case_name + '.json', 'w') as ff:
                        for line in json_edr:
                            try:
                                jedr_out.append(json.loads(line))
                            except:
                                pass
                        json.dump(jedr_out, ff)
                if 'JSON SIEM' in row:
                    jsiem_out = []
                    json_siem = row['JSON SIEM'].splitlines()
                    with open(REPO_DIR + '/output/testcase/SIEM/'+ table_name + '/' + case_name + '.json', 'w') as ff:
                        for line in json_siem:
                            try:
                                jsiem_out.append(json.loads(line))
                            except:
                                pass
                        json.dump(jsiem_out, ff)
                if os.path.exists(REPO_DIR + '/output/testcase/EDR/'+ table_name + '/' + case_name + '.json'):
                    rule['edr'] = REPO_DIR + '/output/testcase/EDR/'+ table_name + '/' + case_name + '.json'
                if os.path.exists(REPO_DIR + '/output/testcase/SIEM/'+ table_name + '/' + case_name + '.json'):
                    rule['siem'] = REPO_DIR + '/output/testcase/SIEM/ '+ table_name + '/' + case_name + '.json'
                if 'REF' in row:
                    ref = row['REF']
                case_info = {}
                red_info = {}
                blue_info = {}
                rule_info = {}
                red_info['test_name'] = test_name
                red_info['platform'] = platform
                red_info['setup'] = config
                red_info['script_attack'] = script
                red_info['rule'] = rule
                red_info['ref'] = ref
                if 'RULE NAME EDR' in row:
                    rule_info['name'] = re.sub('\s+', '',row['RULE NAME EDR'])
                    
                    rule_edr_json = edr_rule.search_rule(rule_info['name'], edr_cookie)
                    if (len(rule_edr_json) == 0):
                        print ('[ - ] Err when search rule ', rule_info['name'])
                    else:
                        
                        rulecontent = RuleContent.RuleContent(rule_edr_json)
                        rule_info['tag'] = 'https://attack.mitre.org/techniques/' + table_name.replace('.', '/')
                        rule_info['des'] = rulecontent.get_rule_desc()
                        rule_info['detail'] = rulecontent.get_rule_blocks()
                        rule_info['ref'] = str(rulecontent.get_rule_references())
                        blue_info['edr'] = rule_info
                        edr_rule.export_rule(rule_info['name'], edr_cookie, REPO_DIR + '/output/rules/')

                if 'RULE NAME SIEM' in row:
                    rule_info = {}
                    rule_info['name'] = re.sub('\s+', '',row['RULE NAME SIEM'])

                    rule_siem_json = siem_rule.search_rule(rule_info['name'], siem_cookie)
                    if (len(rule_siem_json) == 0):
                        print ('[ - ] Err when search rule ', rule_info['name'])
                    else:
                        rulecontent = RuleContent.RuleContent(rule_siem_json)
                        rule_info['tag'] = 'https://attack.mitre.org/techniques/' + table_name.replace('.', '/')
                        rule_info['des'] = rulecontent.get_rule_desc()
                        rule_info['detail'] = rulecontent.get_rule_blocks()
                        rule_info['ref'] = str(rulecontent.get_rule_references())
                        blue_info['siem'] = rule_info
                        siem_rule.export_rule(rule_info['name'], siem_cookie, REPO_DIR + '/output/rules/')
                        
                case_info['blue'] = blue_info
                case_info['red'] = red_info
                json_output[case_name] = case_info
                file_name = REPO_DIR + '/output/parser_for_all/' + table_name +'.yml'
                #
                if os.path.exists(file_name):
                    with open(file_name, 'r') as ff:
                        cur_ = yaml.safe_load(ff)
                        if cur_ != None:
                            json_output.update(cur_)

                with open(file_name, 'w') as ff:
                    yaml.safe_dump(json_output, ff)
        idx = 0
    print('[ + ] Parser done...')
    return json_output

def gen_red_docs():    
    check_dir(REPO_DIR + '/output/redteam')
    techs = os.listdir(REPO_DIR + '/output/parser_for_all')
    for tech in tqdm.notebook.tqdm_notebook(techs, desc="[ O ] Parsing red documents "):
        tech = tech.replace('.yml', '')
        check_dir(REPO_DIR + '/output/redteam/'+tech)
        list_cases = ''
        content = ''
        with open(REPO_DIR + '/output/parser_for_all/'+tech+'.yml', 'r') as ff:
            yml_in = yaml.safe_load(ff)
            for cc in yml_in:
                tmp = cc + '-' + yml_in[cc]['red']['test_name']
                list_cases += '- ['+ tmp  +'](#' + tmp.replace(' ', '-').replace(',', '').replace('.', '').lower() + ')\n\n'
                content += '# ' + tmp + '\n\n'
                content += '**Platform:** ' + yml_in[cc]['red']['platform'] + '\n\n'
                content += '## Setup/config \n'
                content += '```\n' + yml_in[cc]['red']['setup'].replace('```', '').strip() + '\n```\n\n'
                content += '## Script attack \n'
                content += '```\n'+ yml_in[cc]['red']['script_attack'].replace('```', '').strip() +'\n```\n\n'
                content += '## Json test case \n'
                content += '### EDR \n'
                if 'edr' in yml_in[cc]['red']['rule']:
                    content += '- [' + cc + '](../testcase/EDR/'+tech+'/'+cc+'.json)\n\n'
                content += '### SIEM \n'
                if 'siem' in yml_in[cc]['red']['rule']:
                    content += '- [' + cc + '](../testcase/SIEM/'+tech+'/'+cc+'.json)\n\n'
                content += '### NSM \n'
                # update pcap later
                content += '**Reference link:** ' + yml_in[cc]['red']['ref'].replace('```', '') + '\n<br/>\n\n'

        output  = '# ' + tech + ' - ' + get_tech_name(tech)  + '\n\n'
        output += '# VCS content red-team test\n'
        output += list_cases
        output += content
        with open(REPO_DIR + '/output/redteam/'+tech+'/'+tech+'.md', 'w') as ff:
            ff.write(output)


def gen_blue_docs():
    techs = os.listdir(REPO_DIR + '/output/parser_for_all')
    check_dir(REPO_DIR + '/output/guides')
    check_dir(REPO_DIR + '/output/guides/SIEM')
    check_dir(REPO_DIR + '/output/guides/EDR')
    print ("[ + ] Start generate blue document")
    for tech in tqdm.notebook.tqdm_notebook(techs, desc="[ O ] Parsing blue documents"):
        tech = tech.replace('.yml', '')
        with open(REPO_DIR + '/output/parser_for_all/'+tech+'.yml', 'r') as ff:
            yml_in = yaml.safe_load(ff)
            for cc in yml_in:
                if 'edr' in yml_in[cc]['blue']:
                    name = yml_in[cc]['blue']['edr']['name']
                    ref = yml_in[cc]['blue']['edr']['ref']
                    ref = '['+ref+']('+ref+')'
                    tag = '['+tech+']('+yml_in[cc]['blue']['edr']['tag']+')'
                    detail = yml_in[cc]['blue']['edr']['detail']
                    ehh = ''
                    for i in detail:
                        ehh += i + '\n'
                    detail = ehh
                    des = yml_in[cc]['blue']['edr']['des']
                    test = '['+cc+'](../../testcase/' +tech + '/' + cc + '.json)'  
                    edr_blue_output  = blue_from.format(
                        tech + ' - ' + get_tech_name(tech),
                        des,
                        name, 'EDR', name,
                        detail,
                        test,
                        tag,
                        ref
                    )
                    with open(REPO_DIR + '/output/guides/EDR/'+ name + '.md', 'w') as ff:
                        ff.write(edr_blue_output)

                if 'siem' in yml_in[cc]['blue']:
                    name = yml_in[cc]['blue']['siem']['name']
                    ref = yml_in[cc]['blue']['siem']['ref']
                    ref = '['+ref+']('+ref+')'
                    tag =  '['+tech+']('+yml_in[cc]['blue']['siem']['tag']+')'
                    detail = yml_in[cc]['blue']['siem']['detail']
                    ehh = ''
                    for i in detail:
                        ehh += i + '\n'
                    detail = ehh
                    des = yml_in[cc]['blue']['siem']['des']
                    test = '['+cc+'](../../testcase/' +tech + '/' + cc + '.json)' 
                    siem_blue_output  = blue_from.format(
                        tech + ' - ' + get_tech_name(tech),
                        des,
                        name, 'SIEM', name,
                        detail,
                        test,
                        tag,
                        ref
                    )
                    with open(REPO_DIR + '/output/guides/SIEM/'+ name + '.md', 'w') as ff:
                        ff.write(siem_blue_output)

def gen_guides_docs():
    pass

edr_cookie = auth_edr()
siem_cookie = auth_siem()


def get_args():
    parser = argparse.ArgumentParser(description='Tool Generate document for VCS content team')
    parser.add_argument('-r', '--red', dest='red', action='store_true', help='Generate document for red team')
    parser.add_argument('-b', '--blue', dest='blue', action='store_true',help='Generate document for blue team')
    parser.add_argument('-k', '--key', dest='key', help="seatble key")
    parser.add_argument('-p', '--parsers', dest='parsers', action='store_true',help='Parser document')
    #parser.add_argument('-m', '--mapping', dest='mapping',help='Generate mapping document (not done)')
    #parser.add_argument('-a', '--all', dest='all',help='Generate all documents')
    # parser.add_argument('-c', '--commit', dest='commit', help = 'Commit and push to git content')
    return parser.parse_args()


def main():
    args = get_args()
    check_dir(REPO_DIR + '/output')
    if args.parsers:
        base = auth_seatable(args.key)
        parser_(base)
    if args.red:
        gen_red_docs()
    if args.blue:
        gen_blue_docs()

main()


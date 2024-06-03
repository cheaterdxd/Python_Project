from seatable_api import Base
import yaml
import json
from tqdm import tqdm
import time
import re
from pathlib import Path
import os
import sys
from datetime import datetime

HOME_DIR = os.getenv('HOME')
if HOME_DIR == None:
    HOME_DIR = os.path.join(os.path.dirname(__file__), '..')
REPO_DIR = HOME_DIR + '/awesome-tool-content'
ROOT_PATH = os.path.join(os.path.dirname(__file__), '..')
sys.path.append(ROOT_PATH)
from EDR import edr_connection
from EDR import edr_rule
from SIEM import siem_connection
from SIEM import siem_rule
import argparse
# from colorama import init, Fore, Style
# init(convert=True)
STATUS_LEVEL = {
    '0': 'deprecated',
    '1': 'test',
    '2': 'experimental',
    '3': 'stable'
}
SEVERITY = {
    '0': 'info',
    '2': 'low',
    '3': 'low',
    '4': 'low',
    '5': 'low',
    '6': 'low',
    '7': 'low',
    '8': 'low',
    '9': 'medium',
    '11': 'high',
    '12': 'high',
    '13': 'high',
    '14': 'high',
    '15': 'high',
    '16': 'critical',
    '-1': 'info',
    '1': 'low',
    '8': 'medium',
    '10': 'high',
    '15': 'critical'
}

OPERATOR_MAPPING = {
    'eq': '==',
    'ne': '!=',
    'gt': '>',
    'gte': '>=',
    'lt': '<',
    'lte': '<='
}

WRAPPER_MAPPING = {
    'AlertEvent':'alert',
    'Accumulate':'accumulate',
    'Event':'event',
    'Function':'function'
}

def block_parser(block, rule_name, first = True):
    ret = []
    for item in block:
        if item['type'] == 'item':
            left = item['left']
            right = item['right']
            operator = item['operator']
            if left == 'filtered_ids':
                continue
            if right == '$tags':
                continue
            if 'endswith' in left.lower() or 'startswith' in left.lower():
                left = left.lower()
                args = left.split('.')
                left_ = args[0]
                operator_ = left.replace(left_, '')
                right_ = operator_[operator_.find('(')+2:operator_.find(')')-1]
                operator_ = operator_[1:operator_.find('(')]
                if right == 'false':
                    operator_ = 'not ' + operator_
                left = left_
                operator = operator_
                right = right_
            else:    
                if operator in OPERATOR_MAPPING:
                    operator = OPERATOR_MAPPING[operator]
                if '$' in right:
                    operator+='|raw'
                else:
                    try:
                        right = json.loads(right)
                    except json.JSONDecodeError as e:
                        operator+='|raw'
                        print("[e] JSON decoding failed:", e, right, rule_name, file=sys.stderr)
            ret.append({left+'|'+operator:right})
        else:
            if item['type'] == 'container':
                container_cond_exps = block_parser(item['cond_exps'][0], rule_name, first=False)
                ret.append({item["operator"]: container_cond_exps})   
            if item['type'] == 'wrapper':
                key = ''
                value = {}
                check = 0
                if item['cond_notprefix'] == True:
                    key = 'not_'
                wrapper_block = block_parser(item['cond_exps'][0], rule_name, first = False)
                value['query'] = wrapper_block
                if 'cond_windowtime_value' in item and item['cond_windowtime_value'] != None:
                    check += 1
                    time_ = {'time_window':str(item['cond_windowtime_value'])+item['cond_windowtime_unit']}
                if 'cond_count_operator' in item and item['cond_count_operator'] != None:
                    check += 2
                    count = {'count|'+item['cond_count_operator']:int(item['cond_count'])}
                if check == 1:
                    value.update(time_)
                if check == 2:
                    value.update(count)
                if check == 3:
                    value.update(time_)
                    value.update(count)
                ret.append({key+WRAPPER_MAPPING[item['operator']]:value})
    return ret

def parse_rule(platform, rule_json, sprint):
    output = {}
    id = rule_json['_id']
    description = str(rule_json['description']).replace('\n', '')
    author = rule_json['creator']
    tags = rule_json['tags']
    check = False
    for i in tags:
        if 'vcs_content' in i.lower():
            tags.pop(tags.index(i))
            check = True
    if check:
        tags.append('VCS_Content_Offline')
    tags.append(sprint.replace('#', '_'))
    tags = list(dict.fromkeys(tags))


    indices_to_remove = [i for i, s in enumerate(tags) if s.startswith('T')]
    technique = [tags.pop(i) for i in reversed(indices_to_remove)]
    mitre_attack = {}
    # parse filter

    filter_ = {}

    condition_filter = block_parser(rule_json['engines_filter']['condition_trees'], rule_json['rule_name'])
    for wrapper in condition_filter:
        # check new format: keep normal if old rule
        if 'AND' in wrapper:
            wrapper = wrapper['AND'][0]
        try:
            log_source = wrapper['event']['query'].pop(0)
        except:
            print (f'[w] More than 1 Event in filter of {rule_json["rule_name"]}', file=sys.stderr)
            return 
        if 'AND' in log_source:
            log_source = log_source['AND']
        else:
            print(f'[w] Log source not in block {rule_json["rule_name"]}', file=sys.stderr)
        log_source_ = {}
        try:
            for i in log_source:
                if 'log_name|==' in i or 'log_provider_name|==' in i:
                    for j in log_source:
                        for key, value in j.items():
                            key = key.replace('|==', '')
                            if key == 'signature_id':
                                value = int(value)
                            log_source_[key] = value
                            log_source = {'logsource':log_source_}
                if 'OR' in i:
                    log_source = {'logsource':{'category|feature':'process_creation'}}
            filter_.update(log_source)
            filter_.update(wrapper['event'])
        except:
            filter_.update(wrapper['event'])
            print (f'[w] Missing log_name or log_provider_name {rule_json["rule_name"]}', file=sys.stderr)
    # parse indicator
    indicator = {}
    not_alert = {}
    accumulate = {}
    ## parser indicator condition
    condition_indicator = block_parser(rule_json['engines_indicator']['condition_trees'], rule_json['rule_name'])
    if 'AND' in condition_indicator[0]:
        condition_indicator = condition_indicator[0]['AND']
    for wrapper in condition_indicator:
        if 'not_alert' in wrapper:
            not_alert.update(wrapper)
        if 'accumulate' in wrapper:
            accumulate.update(wrapper)
    ### alert
    action = {}
    alert_fields = {}
    reference = []
    tactic = []
    event_fields = []
    content = rule_json['engines_indicator']['action_alert']['content']
    auto_pass = ['link', 'events', 'object_type', 'timestamp', 'category', 'sub_category', 'source_log', 'rule_id', 'filtered_ids']

    for i in content:
        if i['right'].replace(i['left'].capitalize(), '') == '$event.get()':
            event_fields.append(i['left'])
    # remove event fields
    content = [item for item in content if item.get('left') not in event_fields]
    content = [item for item in content if '$tags' not in item.values()]
    for i in content:
        if i['left'] == 'description':
            rr = str(i['right'][1:][:-1]).encode().decode('utf-8')
            if rr == description:
                auto_pass.append(i['left'])
        if i['left'] == 'description_en':
            rr = str(i['right'][1:][:-1]).encode().decode('utf-8')
            if rr == description:
                auto_pass.append(i['left'])
        if i['left'] == 'message':
            rr = str(i['right'][1:][:-1]).encode().decode('utf-8')
            if rr == description:
                auto_pass.append(i['left'])
        if i['left'] == 'message_en':
            rr = str(i['right'][1:][:-1]).encode().decode('utf-8')
            if rr == description:
                auto_pass.append(i['left'])                
        if i['left'] == 'attack_technique':
            auto_pass.append(i['left'])
            tech = i['right'][1:][:-1].split(',')
            for j in tech:
                if j not in technique:
                    technique.append(j)
        if i['left'] == 'attack_tactic':
            auto_pass.append(i['left']) 
            tactic = [item.strip() for item in i['right'][1:][:-1].split(',')]
            mitre_attack['tactic'] = tactic                   
        if i['left'] == 'reference':
            auto_pass.append(i['left']) 
            reference = i['right'][1:][:-1].split('\n')
        if i['left'] == 'severity':
            auto_pass.append(i['left']) 
            severity = SEVERITY[i['right']]
        if i['left'] == 'release_level':
            auto_pass.append(i['left'])  
            status = STATUS_LEVEL[i['right']]   
    if 'technique' not in mitre_attack:
        mitre_attack['technique'] = technique     
    if 'tactic' not in mitre_attack:
        mitre_attack['tactic'] = tactic                  
    content = [item for item in content if item.get('left') not in auto_pass]
    for i in content:
        key = i['left']
        value = i['right']
        if '$' in value:
            key += '|raw'
        if value[0] == '"':
            value = value.replace('"', '')
        alert_fields.update({key:value})

    alert_fields = {'alert_fields': alert_fields}
    event_fields = {'event_fields':event_fields}
    action['alert'] = alert_fields
    action['alert'].update(event_fields)

    indicator.update(not_alert)
    indicator.update(accumulate)
    indicator['action'] = action

    # gen output
    mitre_attack['datasource'] = None
    rule_name = re.sub('Ver.+', '', rule_json['rule_name'])
    output['rule_name'] = rule_name.replace('_', ' ').strip()
    output['id'] = id
    output['description'] = description
    output['author'] = author
    
    output['tags'] = tags

    output['date'] = datetime.fromtimestamp(rule_json['create_time']/1000).strftime("%Y/%m/%d")
    output['modified'] = datetime.fromtimestamp(rule_json['modified_time']/1000).strftime("%Y/%m/%d")
    output['product'] = platform
    output['status'] = status
    
    output['mitre-attack'] = mitre_attack
    output['reference'] = reference
    output['filter'] = {'event' :filter_}
    output['indicator'] = indicator
    output['severity'] = severity
    output['version'] = int(rule_json['rule_name'].split('_')[-1].lower().replace('ver', ''))
    with open('./output/'+rule_json['rule_name']+'_pulled.yml', 'w') as ff:
        yaml.safe_dump(output, ff, allow_unicode=True, sort_keys=False)
    return output

def check_dir(path):
    if not os.path.exists(path):   
        os.mkdir(path)


def auth_seatable(key):
    with open(REPO_DIR + '/config/config.json', 'r') as f:
        api_token = json.load(f)[key]['access_token']
    base = Base(api_token, 'https://seatable.viettelcyber.com')
    try:
        base.auth()
        print ('[+] Auth successed for token ' + api_token[::-1][10:][::-1] + 'x'*10)
    except:
        print ('[-] Auth failed')
    return base

def get_rule_output(base, sprint):
    rules_output = []
    # print (base.get_metadata())
    rows = base.list_rows(sprint)
    for row in rows:
        # print (row)
        if 'Results of Verify' in row and row['Results of Verify'] != 'NOK':
            rules_output.append(row['rule_name'])
    # print(rules_output)
    return rules_output

def get_args():
    parser = argparse.ArgumentParser(description='Testing rule EDR/SIEM by check list')
    parser.add_argument('-c', '--config', dest='config', help='config filepath for EDR/SIEM server, default value is ./config/config.json')
    parser.add_argument('-p', '--platform', dest='platform', help = 'product platform')
    parser.add_argument('-k', '--key', dest='key', help = 'seatable access token key')
    parser.add_argument('-t', '--table', dest='table', help = 'seatable table')

    return parser.parse_args()

def main():
    args = get_args()
    config_file = f"{REPO_DIR}/config/config.json"
    if args.config != None:
        config_file = args.config
    config = json.load(open(config_file,"r"))
    cookie, access_token = None, None
    server = None
    server_address = None
    if args.platform.lower() == "vcs_cym":
        try:
            server_address =  config["vcs_cym"]["server"]
            cookie, access_token = siem_connection.login(config["vcs_cym"]["username"], config["vcs_cym"]["password"], server=server_address)
            server = siem_rule
            if access_token == None:
                raise Exception("Access token none")
            print(f"[+] Logon success on VCS_CyM")
        except:
            print(f"[-] Logon failed on VCS_CyM", file=sys.stderr)
            return 
    if args.platform.lower() == "vcs_ajiant":
        try:
            server_address =  config["vcs_ajiant"]["server"]
            cookie, access_token = edr_connection.login(config["vcs_ajiant"]["username"], config["vcs_ajiant"]["password"], server=server_address)
            server = edr_rule
            if access_token == None:
                raise Exception("Access token none")
            print(f"[+] Logon success on VCS_Ajiant")
        except:
            print(f"[-] Logon failed on VCS_Ajiant", file=sys.stderr)
            return
    base = auth_seatable(args.key)
    rules_output = get_rule_output(base, args.table)
    # exit(0)
    check_dir('./output')
    for rule in rules_output:
        if args.platform.lower() == "vcs_ajiant":
            try:
                rule_json  = edr_rule.search_rule(rule_name=rule, cookie=cookie, server=server_address)
                if rule_json == {}:
                    print('[-] Search failed, rule may not exist', rule, file=sys.stderr)
                    continue
                parse_rule(args.platform, rule_json, args.table)
            except Exception as e:
                print ('[-] Rule ERR', rule, e.with_traceback(), file=sys.stderr)
        if args.platform.lower() == "vcs_cym":
            try:
                rule_json  = siem_rule.search_rule(rule_name=rule, cookie=cookie, server=server_address)
                if rule_json == {}:
                    print('[-] Search failed, rule may not exist', rule, file=sys.stderr)
                    continue
                parse_rule(args.platform, rule_json, args.table)
            except Exception as e:
                print ('[-] Rule ERR',rule,e.with_traceback(), file=sys.stderr)
        # parse_rule(args.platform, rule_json)
main()


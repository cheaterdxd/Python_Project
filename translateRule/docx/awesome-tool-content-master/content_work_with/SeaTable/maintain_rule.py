from seatable_api import Base, context
import argparse
import time
import os
import json
import pandas as pd
import sys
from tqdm import tqdm
sys.path.append(os.path.join(sys.path[0], '..')) 
from EDR import edr_connection
from EDR import edr_debug
from EDR import edr_alert
from SIEM import siem_connection
from SIEM import siem_debug
from SIEM import siem_alert

REPO_DIR = sys.path[0]+'/../..'
PLATFORM = {
    'EDR': 'VCS_Ajiant',
    'SIEM': 'VCS_CyM',
    'SIEM1': 'VCS_CyM'

}
http_proxy  = 'http://192.168.5.8:3128'
https_proxy = 'https://192.168.5.8:3128'
ftp_proxy   = 'ftp://192.168.5.8:3128'
base = None
proxies = { 
              'http'  : http_proxy, 
              'https' : https_proxy, 
              'ftp'   : ftp_proxy
            }


def auth_seatable(key, server_url='https://seatable.viettelcyber.com'):
    with open(REPO_DIR + '/config/config.json', 'r') as f:
        api_token = json.load(f)[key]['access_token']
        # print (api_token)
    base = Base(api_token, server_url)
    try:
        base.auth()
        print ('[+] Auth successed for token ' + api_token[::-1][10:][::-1] + 'x'*10)
    except:
        print ('[-] Auth failed')
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

def get_args():
    parser = argparse.ArgumentParser(description='Tool Generate document for VCS content team')
    parser.add_argument('-p', '--platform', dest='platform', help='EDR/SIEM')
    parser.add_argument("-c", "--config", dest="config", help="config filepath for EDR/SIEM server, default value is ./config/config.json")
    parser.add_argument('-k', '--key', dest='key', help="seatable key")
    parser.add_argument('-s', '--server', type=str,dest='server', help="server address")
    parser.add_argument('-t', '--table', dest='table', help="seatable key")

    return parser.parse_args()

def main():
    args = get_args()
    # args.platform = 'EDR'
    # args.key = 'maintain27'
    # args.config = None
    config_file = f"{REPO_DIR}/config/config.json"
    if args.config != None:
        config_file = args.config
    config = json.load(open(config_file,"r"))

    base = auth_seatable(args.key)
    try:
        rows = base.list_rows(args.table)
    except:
        print (f"[-] List row failed", file=sys.stderr)
    # get list json by rule_name and copy table
    rulename_map = {}
    sfile_name = []
    srule_name = []
    sjson_test = []
    stest = []
    sduplicated_rule = []
    snote = []

    list_json = []

    for row in tqdm(rows, desc="[o] Coping seatable content"):
        key = 'ruleTest_' + str(int(time.time()*10000))
        time.sleep(0.02)    
        # copy table
        try:
            sfile_name.append(row['file_name'])
        except:
            sfile_name.append(None)
        try:
            srule_name.append(row['rule_name'])
        except:
            srule_name.append(None)
        try:
            sjson_test.append(row['json_test'])
        except:
            sjson_test.append(None)

        sduplicated_rule.append(None)
        snote.append("")
        stest.append(False)
        # get rule lists
        try:
            rule_name = row['rule_name']
            rulename_map[key] = rule_name
            try:
                json_tests = row['json_test'].split('\n')
                for json_test_raw in json_tests:
                    try:
                        json_test = json.loads(json_test_raw)
                        try:
                            json_test['client_id'] = key
                        except:
                            pass
                        try:
                            json_test['server_id'] = key
                        except:
                            pass
                        try:
                            json_test['filtered_ids'] = []
                        except:
                            pass
                        list_json.append(json_test)
                    except Exception as e:
                        pass
            except Exception as e:
                print (f"[-] Missing json test {rule_name}", file=sys.stderr)
        except Exception as e:
            pass

    cookie, access_token = '', ''
    server = None
    server_address = None
    search_alert = None
    try:
        if args.platform == 'EDR':
            server_address = edr_connection.login.__defaults__[2]
            if args.server != None:
                server_address = args.server
            cookie, access_token = edr_connection.login(config["vcs_ajiant"]["username"], config["vcs_ajiant"]["password"], server=server_address)
            server = edr_debug
            search_alert = edr_alert
        else:
            server_address = siem_connection.login.__defaults__[2]
            if args.server != None:
                server_address = args.server
            # print (server_address)
            
            cookie, access_token = siem_connection.login(config["vcs_cym"]["username"], config["vcs_cym"]["password"], server=server_address)
            server = siem_debug
            search_alert = siem_alert
        if access_token == None:
            raise Exception("Access token none")
        print(f"[+] Logon success on {PLATFORM[args.platform]}")
    except:
        print(f"[-] Logon failed on {PLATFORM[args.platform]}", file=sys.stderr)
        return 
    for json_test in tqdm(list_json, desc="[o] Debugging"):
        try:
            debug = server.debug(event=json_test, access_token=access_token, cookie=cookie, server=server_address)
        except Exception as e:
            print (f"[-] Err {e}")
    for i in tqdm(range(300), desc="[o] Waiting for engine"):
        time.sleep(1)

    # search alert
    for i in tqdm(rulename_map, desc="[o] Seaching"):
        pass_rule = ''
        dup_rule = []
        try:
            output = search_alert.search_alert(query=f"client_id = \"{i}\"", cookie=cookie, access_token=access_token, server=server_address)
        except Exception as e:
            print (f'[Err] {rulename_map[i]} {output} {e}', file=sys.stderr)
        output = output['data']
        # print (rulename_map[i])
        idx = srule_name.index(rulename_map[i])
        stest[idx] = True

        for o in output:
            if rulename_map[i] in o['rule_id']:
                pass_rule = rulename_map[i]
            else:
                dup_rule.append(o['rule_id'])
        if pass_rule != '':
            if len(dup_rule) > 0:
                # print (dup_rule)
                snote[idx] += 'LR,'
                sduplicated_rule[idx] = ''
                for i in dup_rule:
                    sduplicated_rule[idx] += i + '\n'
        else:
            snote[idx] += 'NP,'
    output = { 'file_name': sfile_name,
            'rule_name' : srule_name,
            'json_test' : sjson_test,
            'test' : stest,
            'duplicated_rule' : sduplicated_rule,
            'note' : snote,
    }
    df = pd.DataFrame(output)
    df.to_csv('output.csv', index=False)

main()
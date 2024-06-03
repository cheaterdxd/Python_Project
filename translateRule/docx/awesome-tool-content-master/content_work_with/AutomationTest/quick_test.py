import os
import sys
import argparse
import yaml
import json
from tqdm import tqdm
import time
from colorama import init, Fore, Style
import hashlib
import re
ROOT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(ROOT_PATH)
FORMAT_EDR_PATH = os.path.abspath(os.path.join(ROOT_PATH, "Rule Offline/format_rule/edr"))
FORMAT_SIEM_PATH = os.path.abspath(os.path.join(ROOT_PATH, "Rule Offline/format_rule/siem"))
LOG = {}
start = time.time()
init(convert=True)
from SeaTable import get_full_json

def beauty_print_log():
    for rule in LOG:
        if len(LOG[rule]) == 0:
            print(f"{Fore.GREEN}[Info] {rule}: Clean{Style.RESET_ALL}\n")
        else:
            label = f"{Fore.YELLOW}[Warning]"
            message = f"This rule must be reviewed before submit!{Style.RESET_ALL}"
            full_dump = ""
            for item in LOG[rule]:
                if item.startswith(f"{Fore.RED}[Error]"):
                    label = f"{Fore.RED}[Error]"
                    message = f"Error rule occured!{Style.RESET_ALL}"
                full_dump += f"{item}\n"
            full_dump = full_dump
            print(f"{label} {rule}: {message}")
            print(full_dump)
        
def get_rule_name(rule):
    # Generate rule name
    rule_name = rule["rule_name"].replace(" ", "_")+"_Ver"+str(rule["version"])
    if rule["product"].lower() == "vcs_cym" and not rule_name.startswith("ATTCK") and not rule_name.startswith("CVE"):
        rule_name = "ATTCK_"+rule_name
    return rule_name

def get_rule_id(rule):
    # Generate rule id
    rule_id = str(get_rule_name(rule))
    if len(rule["subcategory"])>0:
        rule_id = rule["subcategory"].replace(" ", "_") + "_" + rule_id
    if len(rule["category"])>0:
        rule_id = rule["category"].replace(" ", "_") + "_" + rule_id
    return rule_id

def get_args():
    parser = argparse.ArgumentParser(description="Testing rule EDR/SIEM by check list")
    parser.add_argument("-c", "--config", dest="config", help="config filepath for EDR/SIEM server, default value is ./AutomationTest/test_config.json")
    parser.add_argument("-f", "--file", dest="file", help = "folder or rule file")
    parser.add_argument("-t", "--testcase", dest="testcase", help = "json test file")
    parser.add_argument("-o", "--output", dest="output", help = "output file default value is #{platform}_output.txt")
    return parser.parse_args()

def read_config(path = ""):
    try:
        return json.loads(open(path).read())
    except:
        return json.loads(open(os.path.abspath(os.path.join(ROOT_PATH,"AutomationTest/config.json"))).read())

def read_rule(path = ""):
    rules = []
    platform = set()
    # Read rule if path is single file
    try:
        if os.path.isfile(path):
            rule = yaml.safe_load(open(path, "r", encoding="utf-8"))
            rules.append(rule)
            platform.add(rule["product"].upper())
            LOG.update({get_rule_name(rule):[]})
            return rules, platform
        # Read rule if path is dir of rule
        for file in os.listdir(path):
            rule = yaml.safe_load(open(os.path.join(path, file), "r", encoding="utf-8"))
            rules.append(rule)
            platform.add(rule["product"].upper())
            LOG.update({get_rule_name(rule):[]})
    except Exception as ex:
        print(ex.with_traceback(), file=sys.stderr)
    return rules, platform

def read_testcase(path = "", config={}, platform=""):
    testcase = []
    # Split test case json line by line
    try:
        for line in open(path, "r", encoding="utf-8").read().splitlines():
            try:
                # Check legimate json
                json_load = json.loads(line.strip())
                if "filtered_ids" in json_load:
                    json_load.pop("filtered_ids")
                testcase.append(json_load)
            except Exception as ex:
                # Not legimate json
                testcase.append("{}")
                print(f"{Fore.RED}[-] Invalid json in line {len(testcase)}{Style.RESET_ALL}", file=sys.stderr)
        if len(testcase) == 0:
            raise Exception("Test case not found")
    except:
        try:
            testcase = get_full_json.get_full_json(config["Seatable"]["access_token"], platform.lower()) 
            json_file = open(path, "a")
            for item in testcase:
                json_file.write(json.dumps(item)+"\n")
            print(f"{Fore.GREEN}[+] Try Pull testcase from SeaTable: Done{Style.RESET_ALL}")
        except Exception as ex:
            print(ex)
            print(f"{Fore.RED}[+] Test case not found{Style.RESET_ALL}", file=sys.stderr)
    return testcase    

def load_format(path = ""):
    # Loading format
    formats = []
    for format_path in os.listdir(path):
        try:
            format = yaml.safe_load(open(os.path.join(path,format_path), "r", encoding="utf-8"))
            formats.append(format)
        except Exception as ex:
            print(ex, f"at file {format_path}", file=sys.stderr)
    return formats

def check_event_field(rule = [], formats = set()):
    for format in formats:
        # print(format["rule_name"])
        # print(format["filter"]["event"]["logsource"])
        if rule["filter"]["event"]["logsource"] == format["filter"]["event"]["logsource"]:
            missing_field = set()
            for field in format["indicator"]["action"]["alert"]["event_fields"]:
                if field not in rule["indicator"]["action"]["alert"]["event_fields"]:
                    missing_field.add(field)
            for field in format["indicator"]["action"]["alert"]["alert_fields"]:
                if field not in rule["indicator"]["action"]["alert"]["alert_fields"]:
                    if not "|" in field:
                        missing_field.add(field)
                    missing_field.add(field.split("|")[0])
            return {
                "format_rule": format["rule_name"],
                "missing_field": missing_field
            }
    return {
            "format_rule": None,
            "missing_field": None
        }
        
def checking_format(rules, platform):
    edr_formats = []
    siem_formats = []
    if "VCS_AJIANT" in platform:
        edr_formats = load_format(FORMAT_EDR_PATH)
    if "VCS_CYM" in platform:
        siem_formats = load_format(FORMAT_SIEM_PATH)
    for rule in tqdm(rules, desc= "[o] Checking valid format rule"):
        if rule["product"].upper() == "VCS_AJIANT":
            check = check_event_field(rule, edr_formats)
            continue
        if rule["product"].upper() == "VCS_CYM":
            check = check_event_field(rule, siem_formats)
        if check["format_rule"] == None:
            LOG[get_rule_name(rule)].append(f"{Fore.YELLOW}[Warning] Unknown format rule or missing logsource{Style.RESET_ALL}")
        elif len(check["missing_field"]) > 0:
            format =  check["format_rule"]
            missing_field = str(check["missing_field"])
            LOG[get_rule_name(rule)].append(f"{Fore.RED}[Error] Missing field for {format}: {missing_field}{Style.RESET_ALL}")
        time.sleep(0.05)
    print(f"{Fore.GREEN}[+] Checking valid format rule{Style.RESET_ALL}")

def checking_mitre_metadata(rules = []):
    for rule in tqdm(rules, desc= "[o] Checking Mitre ATT&CK metadata"):
        missing_field = []
        try:
            if len(rule["mitre-attack"]["technique"]) == 0:
                missing_field.append("technique")
        except:
            missing_field.append("technique")
        try:
            if len(rule["mitre-attack"]["tactic"]) == 0:
                missing_field.append("tactic")
        except:
            missing_field.append("tactic")  
        try:
            if len(rule["mitre-attack"]["datasource"]) == 0:
                missing_field.append("datasource")
        except:
            missing_field.append("datasource") 
        if(len(missing_field)):
            LOG[get_rule_name(rule)].append(f"{Fore.RED}[Error] Missing Mitre ATT&CK metadata: {missing_field}{Style.RESET_ALL}")
        time.sleep(0.05)
    print(f"{Fore.GREEN}[+] Checking Mitre ATT&CK metadata{Style.RESET_ALL}")
    
def checking_regular_metadata(rules = []):
    for rule in tqdm(rules, desc= "[o] Checking regular metadata"):
        missing_field = []
        try:
            if rule["status"] != "development" or rule["status"] != "test":
                status = rule["status"]
                LOG[get_rule_name(rule)].append(f"{Fore.YELLOW}[Warning] Rule not in developer phase status: [{status}]{Style.RESET_ALL}")
        except:
            missing_field.append("status")
        try:
            if rule["severity"] != "medium":
                severity = rule["severity"]
                LOG[get_rule_name(rule)].append(f"{Fore.YELLOW}[Warning] Rule severity need to be reviewed before submit: [{severity.upper()}]{Style.RESET_ALL}")
        except:
            missing_field.append("severity")
        try:
            if not "Sprint" in str(rule["tags"]):
                LOG[get_rule_name(rule)].append(f"{Fore.RED}[Error] Unknown Sprint of rule{Style.RESET_ALL}")
            if not "VCS_Content" in str(rule["tags"]):
                LOG[get_rule_name(rule)].append(f"{Fore.RED}[Error] Missing VCS_Content* tags{Style.RESET_ALL}")
        except:
            missing_field.append("tags")
        if len(missing_field) > 0:
            LOG[get_rule_name(rule)].append(f"{Fore.RED}[Error] Missing metadata: {missing_field}{Style.RESET_ALL}")
        time.sleep(0.05)
    print(f"{Fore.GREEN}[+] Checking regular metadata{Style.RESET_ALL}")
    
def checking_alert_duplicate(rules = [], platform = "", testcase = [], config = {}):
    rules_test = {}
    for rule in rules:
        rules_test.update({get_rule_name(rule):{"isAlert" : False, "duplicate_ti":[], "duplicate_soc":[]}})
    try:
        # Init platform
        if platform == "VCS_CYM":
            from SIEM import siem_connection as connection
            from SIEM import siem_debug as debug  
            from SIEM import siem_alert as alert
        if platform == "VCS_AJIANT":
            from EDR import edr_connection as connection
            from EDR import edr_debug as debug
            from EDR import edr_alert as alert
        # Login with config
        platform = platform.lower()
        username = config[platform]["username"]
        password = config[platform]["password"]
        server =  config[platform]["server"]
        cookie, access_token = connection.login(username, password, server)
        # push json
        searches = []
        for i in tqdm(range(len(testcase)), desc="[o] Push JSON to portal"):
            nonce = str(int(time.time()*1000))
            search = hashlib.md5(f"{username}_{i}_{nonce}".encode('utf-8')).hexdigest().upper()
            try:
                testcase[i]["client_id"] = search
            except:
                pass
            try:
                testcase[i]["server_id"] = search
            except:
                pass
            searches.append(search)
            debug.debug(event=testcase[i], access_token=access_token, cookie=cookie, server=server)
        for i in tqdm(range(60), desc="[o] Waiting server"):
            time.sleep(1)
        for index in tqdm(range(len(searches)), desc="[o] Searching alert"):
            search = searches[index]
            if platform == "VCS_CYM":
                alerts_json = alert.search_alert(query = f"client_id = \"{search}\" OR server_id = \"{search}\"", cookie=cookie, access_token=access_token, server=server)
            else:
                alerts_json = alert.search_alert(query = f"client_id = \"{search}\"", cookie=cookie, access_token=access_token, server=server)
            checks = {
                "rules_id":[],
                "severity":[],
                "is_ti":[]
            }
            for alert_json in alerts_json["data"]:
                checks["rules_id"].append(alert_json["rule_id"])
                checks["severity"].append(alert_json["severity"])
                is_ti = False
                if re.match(r"(?i).*Ver\d+$", alert_json["rule_id"]):
                    is_ti= True
                checks["is_ti"].append(is_ti)
            for rule in rules_test:
                if rule in str(checks["rules_id"]):
                    rules_test[rule]["isAlert"] = True
                    duplicate_ti = []
                    duplicate_soc = []
                    for i in range(len(checks["rules_id"])):
                        if not checks["severity"][i].upper() in ["MEDIUM", "HIGH", "CRITICAL"]:
                            continue
                        # if rule in checks["rules_id"][i]:
                        #    continue
                        if checks["is_ti"][i]:
                            duplicate_ti.append(checks["rules_id"][i])
                            continue
                        duplicate_soc.append(checks["rules_id"][i])
                    rules_test[rule]["duplicate_ti"] = duplicate_ti
                    rules_test[rule]["duplicate_soc"] = duplicate_soc
    except Exception as ex:
        print(ex.with_traceback(), file=sys.stderr)
    for rule in rules_test:
        if not rules_test[rule]["isAlert"]:
            LOG[rule].append(f"{Fore.RED}[Error] Alert not found on portal!{Style.RESET_ALL}")
            continue
        if len(rules_test[rule]["duplicate_ti"]) > 1:
            LOG[rule].append(f"{Fore.RED}[Error] Duplicate multiple rule Content TI{Style.RESET_ALL}")
            for item in rules_test[rule]["duplicate_ti"]:
                if rule in item:
                    continue
                LOG[rule].append(f"{Fore.RED}\t{item}{Style.RESET_ALL}")
        if len(rules_test[rule]["duplicate_soc"]) > 0:
            LOG[rule].append(f"{Fore.YELLOW}[Warning] Duplicate multiple rule Content SOC{Style.RESET_ALL}")
            for item in rules_test[rule]["duplicate_soc"]:
                LOG[rule].append(f"{Fore.YELLOW}\t{item}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Check alert and duplicate rule{Style.RESET_ALL}")
    
def main():
    agrs = get_args()
    rules, platform = read_rule(path=agrs.file)
    if len(platform) != 1:
        print(f"{Fore.RED}[Error] Only Support one product rule per test{Style.RESET_ALL}")
        exit()
    platform = platform.pop()
    config = read_config(path=agrs.config)
    testcase = read_testcase(path=agrs.testcase, config=config, platform=platform)
    checking_format(rules, platform)
    checking_mitre_metadata(rules)
    checking_regular_metadata(rules)
    checking_alert_duplicate(rules, platform, testcase, config)
    end = time.time()
    total_time = time.strftime("%H:%M:%S", time.gmtime(end-start))
    print(f"{Fore.GREEN}[+] Running in {total_time}{Style.RESET_ALL}")
    beauty_print_log()
main()
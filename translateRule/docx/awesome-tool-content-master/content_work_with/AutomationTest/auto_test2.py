import os
import sys
import json
# import pandas as pd
from colorama import init, Fore, Style
from tqdm import tqdm
import subprocess
# import copy
# import requests
import re
import argparse
ROOT_PATH = os.path.join(os.path.dirname(__file__), '..')
sys.path.append(ROOT_PATH)
from EDR import edr_connection
from EDR import edr_rule
from EDR import edr_alert
from SIEM import siem_connection
from SIEM import siem_rule
from SIEM import siem_alert
from Model.RuleContent import RuleContent
from Model.RuleContent import side_parser
import time

start_time = time.time()
# Default Value
SOC_IMPORTANT_FIELDS = open(os.getenv("HOME")+"/awesome-tool-content/content_work_with/AutomationTest/SOC_Important_alert_fields.txt").read().splitlines()
SIEM_IMPORTANT_FIELDS = open(os.getenv("HOME")+"/awesome-tool-content/content_work_with/AutomationTest/SIEM_Important_alert_fields.txt").read().splitlines()
CONFIG_PATH = os.getenv("HOME")+"/awesome-tool-content/config/config.json"
init(convert=True)

# TODO Check alert information SOC 
def check_SOC_indicator(indicator=str()):
    fields = []
    for item in SOC_IMPORTANT_FIELDS:
        if (item.startswith("#")):
            continue
        if not ("alert.set"+item.capitalize()) in indicator:
            fields.append(item)
    return fields

# TODO Check list Data Source, Data Component
def __check_list_datasource_SIEM(filter=list()):
    for content in filter:
        if not ("log_parser ==" in content or
            "log_parser in" in content or
            "log_parser contains" in content or
            "device_product ==" in content or
            "device_product in" in content):
            return "datasource"
        if ("log_parser == \"windows_event\"" in content or 
            "log_parser in \"windows_event\"" in content or
            "device_product == \"sysmon\"" in content or
            "device_product in \"sysmon\"" in content):
            if not ("signature_id ==" in content or
                "signature_id in" in content):
                return "signature_id"
    return "OK"

def __check_list_datasource_EDR(filter=list()):
    for content in filter:
        # Check source_log in (source_log == * is bugged)
        if not "source_log in" in content:
            return "source_log"
        # Check signature_id (all EDR log have signature_id)
        if not ("signature_id in" in content or
                "signature_id ==" in content):
            return "signature_id"
    return "OK"

# TODO Check list Action Alert
def __check_list_action_alert(indicator=str(), platform=str()):
    action_alert = []
    severity = "OK"
    if platform == "SIEM":
        for field in SIEM_IMPORTANT_FIELDS:
            if not ("alert.set"+field.capitalize()) in indicator:
                action_alert.append(field)
        if not "alert.setSource_log(\"mixed\")" in indicator:
            action_alert.append("source_log")
    if not "alert.setSeverity" in indicator:
        action_alert.append("severity")
        severity = "NOK"
    if not "alert.addEventIdFromEvent($events_id)" in indicator:
        action_alert.append("events")
    if not "alert.setSource_log" in indicator:
        action_alert.append("source_log")
    if re.search(r"alert.setSeverity\([0-7]\)", indicator):
        severity = "LOW"
    if not re.search(r"alert.setRelease_level\([1-2]\)", indicator):
        action_alert.append("release_level")
    return severity, action_alert

# TODO Check list not AlertEvent
def __check_list_not_alert(indicator=str()):
    # search not AlertEvent block
    search = re.search(r"not AlertEvent\((.*)\) over window:time", indicator)
    
    # get all field from action alert
    fields = re.findall(r"alert.set([^\(\)]*)\(", indicator)
    
    # check if not AlertEvent block using field not in action alert 
    try:
        not_alert = search.group(1)
        parser = side_parser(not_alert)
        for item in parser["left"]:
            field = re.search(r"[a-z0-9_]{1,}", item).group()
            if not field.capitalize() in fields:
                return "NOK"
    except Exception as ex:
        print("Error occur:", ex)
        return "NOK"
    
    return "OK"

def __check_list_accumulate(indicator=str()):
    check_list = []
    try:
        accumulate = re.search(r"accumulate \((.*)\)", indicator).group()
    except:
        check_list.append("accumulate")
        return check_list
    window_times = re.findall(r"(not AlertEvent|accumulate).*(over window:time\(\d{1,}[shm])\)", indicator)
    before = None
    for window_time in window_times:
        if before != None and before != window_time[1]:
            check_list.append("window_time")
            break
        before = window_time[1]
    try:
        if not "$count >= 1" in accumulate:
            check_list.append("count")
    except:
        check_list.append("accumulate")
    return check_list

# Check list verify test case
def __check_list_test_case(filter=str(), test_case=[], correlation=str()):
    open("filter.drl", "w", encoding="utf-8").write(filter)
    if len(test_case) == 0:
        return 0
    # return 1
    open("test_case.json", "w", encoding="utf-8").write("")
    for test in test_case:
        try:
            open("test_case.json", "w").write(test)
            proc = subprocess.Popen(["java", "-cp", correlation, "com.viettel.Main", "-f", "./filter.drl", "-r", "./test_case.json", "--fuzzing","false"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = int(proc.stdout.read())
            proc.kill()
            if result != 0:
                return result
        except:
            return -1
    return 0

# TODO check null
def __check_list_null(filter=str(), test_case=[], correlation=str()): 
    open("filter.drl", "w", encoding="utf-8").write(filter)
    if len(test_case) == 0:
        return 0
    # return 1
    open("test_case.json", "w", encoding="utf-8").write("")
    for test in test_case:
        opt_test = {}
        try:
            test_json = json.loads(test)
        except:
            print(test)
        for key in test_json:
            if key in filter:
                opt_test[key] = test_json[key]
        open("test_case.json", "w", encoding="utf-8").write(json.dumps(opt_test))
        proc = subprocess.Popen(["java", "-cp", correlation, "com.viettel.Main", "-f", "./filter.drl", "-r", "./test_case.json","--fuzzing","true"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = int(proc.stdout.read())
        proc.kill()
        if result == -1:
            return result
    return 1

# TODO Check debug
def _check_list_debug(rule = RuleContent):
    if "Functions.debug" in rule.get_rule_indicator():
        return False
    if "Functions.debug" in rule.get_rule_filter():
        return False
    return True

# TODO Check list rule
def check_list_rule(rule=RuleContent, platform=str(), correlation=str()):
    filter = rule.get_rule_blocks()
    indicator = rule.get_rule_indicator()
    datasource = None
    if platform == "SIEM":
        datasource = __check_list_datasource_SIEM(filter=filter)
    if platform == "EDR":
        datasource = __check_list_datasource_EDR(filter=filter)
    severity, action_alert = __check_list_action_alert(indicator=indicator)
    not_alert = __check_list_not_alert(indicator=indicator)
    accumulate = __check_list_accumulate(indicator=indicator)
    verify_json_test = __check_list_test_case(filter=rule.get_rule_filter(), test_case=rule.get_test_case(), correlation=correlation)
    verify_null = -1
    if verify_json_test > 0:
        verify_null = __check_list_null(filter=rule.get_rule_filter(), test_case=rule.get_test_case(), correlation=correlation) 
    return datasource, severity, action_alert, not_alert, accumulate, verify_json_test, verify_null

def check_all_rule(config=dict(), input=pd.DataFrame(), platform=str(), correlation = str()):
    # Get list RuleContent
    rules = {}
    rule_search = None
    connection = None
    test_list = {
        "rule_name": [],
        "author": [],
        "technique": [],
        "isExist": [],
        "isAlert": [],
        "datasource": [],
        "severity": [],
        "action_alert": [],
        "not_alert": [],
        "accumulate": [],
        "verify_json_test": [],
        "verify_null": [],
        "verify_debug": [],
        "testing": [],
        "note":[],
        "verify_fp": [],
        "coverage_rule_ver1": [],	
        "point_base_bm11": [],
        "high_confidence" : []
    }
    if platform == "EDR":
        connection = edr_connection
        rule_search = edr_rule
    if platform == "SIEM":
        connection = siem_connection
        rule_search = siem_rule
    try:
        cookie, access_token = connection.login(username=config["username"],password=config["password"],server=config["server"])
        print(Fore.GREEN+"[+] Login to", platform, "successful",Style.RESET_ALL)
    except:
        print(Fore.RED+"[-] Login to", platform, "failed",Style.RESET_ALL)
        return test_list
    # Initial rule
    for index in tqdm(range(len(input)), desc="[o] Rule loading"):
        rule_name = input["rule_name"][index]
        if type(rule_name) != str:
            continue
        try:
            search = rule_search.search_rule(rule_name=rule_name, cookie=cookie, server=config["server"])
        except Exception as ex:
            print(Fore.RED+"[-] Failed to loaded",rule_name,Style.RESET_ALL)
            return test_list
        try:    
            rule = RuleContent(search)
            rule.set_test_case(input["test_case"][index])
            rules[rule_name] = rule
            test_list["isExist"].append("OK")
        except Exception as ex:
            test_list["isExist"].append("NOK")
        test_list["rule_name"].append(rule_name)
        test_list["author"].append(input["author"][index])
        test_list["verify_fp"].append(input["verify_fp"][index])
        test_list["coverage_rule_ver1"].append(input["coverage_rule_ver1"][index])
        test_list["point_base_bm11"].append(input["point_base_bm11"][index])
        test_list["high_confidence"].append(input["high_confidence"][index])
        test_list["note"].append(input["note"][index])
    print(Fore.GREEN+"[+] Rule loading successful",Style.RESET_ALL)
    for index in tqdm(range(len(test_list["rule_name"])), desc="[o] Rule test"):
        if test_list["isExist"][index] == "OK":   
            rule = rules[test_list["rule_name"][index]]
            test_list["technique"].append(", ".join(rule.get_rule_technique()))
            isAlert = "NOK"
            search = None
            if platform == "EDR":
                search = edr_alert.search_alert(rule_id=rule.get_rule_id(), cookie=cookie, access_token=access_token, server=config["server"])
            if platform == "SIEM":
                search = siem_alert.search_alert(rule_id=rule.get_rule_id(), cookie=cookie, server=config["server"])
            if len(search.json()["data"]) > 0:
                isAlert = "OK"
            test_list["isAlert"].append(isAlert)
            datasource, severity, action_alert, not_alert, accumulate, verify_json_test, verify_null = check_list_rule(rule=rule, platform=platform, correlation=correlation)
            if verify_json_test == -1:
                print(index)
            if len(action_alert) == 0:
                action_alert = ["OK"]
            if len(accumulate) == 0:
                accumulate = ["OK"]
            test_list["datasource"].append(datasource)
            test_list["severity"].append(severity)
            test_list["action_alert"].append(", ".join(action_alert))
            test_list["not_alert"].append(not_alert)
            test_list["accumulate"].append(", ".join(accumulate))
            test_list["testing"].append(None)
            verify_json = "NOK"
            verify_null_p = "NOK"
            if verify_json_test > 0:
                verify_json = "OK"
            if verify_null > 0:
                verify_null_p = "OK"
            test_list["verify_json_test"].append(verify_json)
            test_list["verify_null"].append(verify_null_p)
            verify_debug = "OK"
            if not _check_list_debug(rule=rule):
                verify_debug = "NOK"
            test_list["verify_debug"].append(verify_debug)
        else:
            test_list["technique"].append(None)
            test_list["isAlert"].append(None)
            test_list["datasource"].append(None)
            test_list["severity"].append(None)
            test_list["action_alert"].append(None)
            test_list["not_alert"].append(None)
            test_list["accumulate"].append(None)
            test_list["testing"].append(None)
            test_list["verify_json_test"].append(None)
            test_list["verify_null"].append(None)
            test_list["verify_debug"].append(None)
    print(Fore.GREEN+"[+] Rule testing successful",Style.RESET_ALL)
        
    return pd.DataFrame(test_list)
    

# def fix_missing_field(rule,cookie,fields):
#     indicator = {
#         "engine":"indicator",
#         "engine_rule":rule["engines_indicator"],
#         "priority":rule["priority"],
#         "rule_id":rule["rule_id"],
#         "category":rule["category"],
#         "subcategory":rule["subcategory"]
#         }
#     for field in fields:
#         indicator["engine_rule"]["action_alert"]["content"].append({"left":field,"right":"$event.get"+field.capitalize()+"()"})
#     content = requests.post(url="https://10.255.251.153/api/rule/gen_content", headers={"Cookie":cookie}, json=indicator, verify=False).json()
#     content["engine"]="indicator"
#     verify = requests.post(url="https://10.255.251.153/api/rule/verify_syntax", headers={"Cookie":cookie}, json=content, verify=False).json()
#     if (verify["code"]==200):
#         rule["engines_indicator"]["content"]=content["content"]
#         rule["engines_indicator"]["content_old"]=""
#         update = requests.post(url="https://10.255.251.153/api/rule/update_rule", headers={"Cookie":cookie}, json=rule, verify=False).json()
#         deploy = requests.post(url="https://10.255.251.153/api/rule/deploy_rule", headers={"Cookie":cookie}, json={"list_id":[rule["_id"]]}, verify=False).json()
#         print(update)
#         print(deploy)
#     else:
#         print(verify)
        
#     open("rule.json", "w").write(json.dumps(content))
#     return

def get_args():
    parser = argparse.ArgumentParser(description="Testing rule EDR/SIEM by check list")
    parser.add_argument("-c", "--config", dest="config", help="config filepath for EDR/SIEM server, default value is ./AutomationTest/test_config.json")
    parser.add_argument("-p", "--platform", dest="platform",help="platform choosing EDR or SIEM")
    parser.add_argument("-i", "--input", dest="input", help = "json file of rule_name|technique|author etc")
    parser.add_argument("-o", "--output", dest="output", help = "excel file of output output, default value is #{platform}_output.xlsx")
    return parser.parse_args()

def main():
    args = get_args()
    file_config = CONFIG_PATH
    if args.config != None:
        file_config = args.config
    CONFIG = json.loads(open(file_config).read())
    PLT = ""
    PLATFORM = args.platform
    if  PLATFORM == "EDR":
        PLT = "vcs_ajiant" 
    if PLATFORM == "vcs_cym":
        PLT = "SIEM" 
    print (args.input)
    INPUT = pd.read_json(args.input)

    testfile = args.output
    if testfile == None:
        testfile = PLATFORM+"_testfile.csv"
    check = check_all_rule(config=CONFIG[PLT], input=INPUT, platform=PLATFORM, correlation = CONFIG["correlation"])
    testing = check
    # testing = check[[
    #     "rule_name",
    #     "technique",
    #     "isAlert",
    #     "coverage_rule_ver1",
    #     "point_base_bm11",
    #     "high_confidence",
    #     "verify_fp",
    #     "note"
    # ]]
    print(check)
    try:
        testing.to_csv(testfile)
        print(Fore.GREEN+"[+] Rule testing output to",testfile,"succesful",Style.RESET_ALL)
    except Exception as ex:
        print(Fore.RED+"[-] Rule testing output to",testfile,"failed", ex ,Style.RESET_ALL)
    print(Fore.GREEN+"[+] Running in",time.strftime('%H:%M:%S', time.gmtime(time.time()-start_time)),Style.RESET_ALL)
main()
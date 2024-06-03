from seatable_api import Base, context
import json
import os
import sys
import pandas as pd
import json
import argparse
from tqdm import tqdm
import time

ROOT_PATH = os.path.join(os.path.dirname(__file__), '..')
PLATFORM_PATH = {
    "EDR": {
        "rule_name" : "RULE NAME EDR",
        "test_case" : "JSON EDR",
        "verify_fp" : "VERIFY FP EDR",
        "coverage_rule_ver1": "COVERAGE RULE VER1 EDR",
        "note": "NOTE OUTPUT EDR"
    },
    "SIEM": {
        "rule_name" : "RULE NAME SIEM",
        "test_case" : "JSON SIEM",
        "verify_fp" : "VERIFY FP SIEM",
        "coverage_rule_ver1": "COVERAGE RULE VER1 SIEM",
        "note": "NOTE OUTPUT SIEM"
    }
}
CONFIG_PATH = ROOT_PATH + "\\SeaTable\\config.json"
sys.path.append(ROOT_PATH)
server_url = "https://seatable.viettelcyber.com"

def dict2pd(key_dict={}):
    arr = []
    for key in key_dict:
        key_dict[key]["test_case"] = "\n".join(key_dict[key]["test_case"])
        arr.append(key_dict[key])
    return pd.DataFrame(arr)

def check_work(file_path=str()):
    tech_author = {}
    work = pd.read_excel(file_path)
    for index in range(len(work)):
        tech_author.update({work["Sub-Techniques ID"][index]:work["Blue-Team"][index]})
    return tech_author

def get_testing_data(platform=str(), sprint_path=str(), key=str(), config = str()):
    api_token = json.loads(open(config).read())[key]["access_token"]
    base = Base(api_token, server_url)
    base.auth()
    tech_author = check_work(file_path=sprint_path)
    key_dict = {}
    meta_data = base.get_metadata()["tables"]
    for table in meta_data:
        for attemp in range(3):
            try:
                rows = None
                rows = base.list_rows(table_name=table["name"])
                if rows != None:
                    break
            except Exception as ex:
                print(table["name"])
                if ex.errno == 429:
                    print ('[ O ] Too much apis call ')
                    for i in tqdm(range(60), desc=f'[ * ] Re-try get {table["name"]} data after'):
                        time.sleep(1)
                else:
                    print(ex)
                continue

        for row in rows:
            if not PLATFORM_PATH[platform]["rule_name"] in row:
                continue
            rule_name = row[PLATFORM_PATH[platform]["rule_name"]]
            if not rule_name in key_dict:
                author = ""
                try:
                    author = tech_author[table["name"]]
                except:
                    pass
                key_dict.update({
                    rule_name : {
                        "rule_name":rule_name.strip(),
                        "author":author,
                        "test_case":[],
                        "verify_fp":None,
                        "coverage_rule_ver1":None,
                        "point_base_bm11":None,
                        "high_confidence":None,
                        "note":None
                    }
                })
            # if rule_name == "ATTCK_Proc_Creation_Win_Wmic_Uninstall_Security_Products_Ver1":
            #     print(row["JSON SIEM"])
            try:
                log_json = row[PLATFORM_PATH[platform]["test_case"]].splitlines()
                test_case = []
                for test in log_json:
                    try:
                        test_json = json.loads(test)
                        if "filtered_ids" in test_json:
                            test_json["filtered_ids"] = []
                        test_case.append(json.dumps(test_json))
                    except Exception as ex:
                        if "{" in test or "}" in test:
                            print(table["name"], rule_name.strip())
                            # print(ex)
                key_dict[rule_name]["test_case"] += test_case
            except:
                pass
            try: 
                key_dict[rule_name]["verify_fp"] = (row[PLATFORM_PATH[platform]["verify_fp"]])
            except:
                pass
            try:
                key_dict[rule_name]["coverage_rule_ver1"] = (row[PLATFORM_PATH[platform]["coverage_rule_ver1"]])
            except:
                pass
            try:
                key_dict[rule_name]["point_base_bm11"] = (row["POINT BASE ON BM11"])
            except:
                pass
            try:
                key_dict[rule_name]["high_confidence"] = (row["CONFIDENCE LEVEL HIGH"])
            except:
                pass
            try:
                key_dict[rule_name]["note"] = (row[PLATFORM_PATH[platform]["note"]])
            except:
                pass
    # print(key_dict)
    return dict2pd(key_dict)

     
def get_args():
    parser = argparse.ArgumentParser(description="Get total file on s")
    parser.add_argument("-c", "--config", dest="config", help="config filepath for EDR/SIEM server, default value is ./SeaTable/test_config.json")
    parser.add_argument("-p", "--platform", dest="platform",help="platform choosing EDR or SIEM")
    parser.add_argument("-k", "--key", dest="key", help = "key of access token")
    parser.add_argument("-o", "--output", dest="output", help = "json file of output")
    parser.add_argument("-i", "--input", dest="input", help = "sprint task excel")
    return parser.parse_args()

def main():
    args = get_args()
    platform = args.platform
    config = CONFIG_PATH
    if args.config != None:
        config = args.config
    key = args.key
    output = args.output
    input = args.input
    get_testing_data(platform=platform, sprint_path=input, key = key, config=config).to_json(output)

main()
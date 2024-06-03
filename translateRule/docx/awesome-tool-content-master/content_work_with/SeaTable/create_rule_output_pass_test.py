from seatable_api import Base, context
import json
import os
import sys
import pandas as pd
import json
import argparse
from tqdm import tqdm
import time
import re

ROOT_PATH = os.path.join(os.path.dirname(__file__), '..')
CONFIG_PATH = ROOT_PATH + "\\SeaTable\\config.json"
sys.path.append(ROOT_PATH)
server_url = "https://seatable.viettelcyber.com"

def get_testing_data(sprint=str(), sprint_path=str(), key=str(), config = str()):
    api_token = json.loads(open(config).read())[key]["access_token"]
    base = Base(api_token, server_url)
    base.auth()
    meta_data = base.get_metadata()["tables"]
    rows = None
    for attemp in range(3):
        try:
            rows = base.list_rows(table_name=f"Sprint#{sprint}")
            if rows != None:
                break
        except Exception as ex:
            print(f"Sprint#{sprint}")
            if ex.errno == 429:
                print ('[ O ] Too much apis call ')
                for i in tqdm(range(60), desc=f'[ * ] Re-try get {table["name"]} data after'):
                    time.sleep(1)
            else:
                print(ex)
            continue
    # print(rows)
    sprint_df = pd.DataFrame(json.loads(open(sprint_path).read()))
    pass_rule = []
    maintain_scope = []
    for item in rows:
        if item["Results of Verify"] != "NOK":
            pass_rule.append(item["rule_name"])
    for i in range(len(sprint_df)):
        rule_name = sprint_df["rule_name"][i]
        json_test = sprint_df["test_case"][i]
        if rule_name in pass_rule and len(json_test) > 0:
            file_name =  re.sub("(^attck_|_ver\d+$)", "", rule_name.lower())
            # print(file_name)
            maintain_scope.append({"file_name":file_name, "rule_name": rule_name, "json_test": json_test})
    return pd.DataFrame(maintain_scope)

def get_args():
    parser = argparse.ArgumentParser(description="Get total file on s")
    parser.add_argument("-c", "--config", dest="config", help="config filepath for EDR/SIEM server, default value is ./SeaTable/test_config.json")
    parser.add_argument("-k", "--key", dest="key", help = "key of access token")
    parser.add_argument("-o", "--output", dest="output", help = "csv rule output")
    parser.add_argument("-i", "--input", dest="input", help = "json sprint")
    parser.add_argument("-s", "--sprint", dest="sprint", help = "sprint number")
    return parser.parse_args()

def main():
    args = get_args()
    config = CONFIG_PATH
    if args.config != None:
        config = args.config
    key = args.key
    output = args.output
    input = args.input
    sprint = args.sprint
    csv = get_testing_data(sprint=sprint, sprint_path=input, key = key, config=config).to_csv(output)

main()
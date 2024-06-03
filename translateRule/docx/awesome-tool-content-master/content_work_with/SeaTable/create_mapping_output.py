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

def get_testing_data(platform=str(), key=str(), config = str()):
    api_token = json.loads(open(config).read())[key]["access_token"]
    base = Base(api_token, server_url)
    base.auth()
    meta_data = base.get_metadata()["tables"]
    rows = None
    for attemp in range(3):
        try:
            rows = base.list_rows(table_name=platform)
            if rows != None:
                break
        except Exception as ex:
            print(platform)
            if ex.errno == 429:
                print ('[ O ] Too much apis call ')
                for i in tqdm(range(60), desc=f'[ * ] Re-try get {platform} data after'):
                    time.sleep(1)
            else:
                print(ex)
            continue
    json_file = set()
    mapping = []
    for item in rows:
        try:
            if not item["pass"]:
                continue
            events_id = set()
            for line in item["json_test"].splitlines():
                try:
                    json_test = json.loads(line)
                    if "filtered_ids" in json_test:
                        json_test["filtered_ids"] = []
                        # print(item["file_name"])
                    json_file.add(json.dumps(json_test))
                    events_id.add(json_test["event_id"])
                except:
                    if "}{" in line:
                        for i in line.split("}{"):
                            if not i.startswith("{"):
                                i = "{" + i
                            if not i.endswith("}"):
                                i = i + "}"
                            json_test = json.loads(i)
                            if "filtered_ids" in json_test:
                                json_test["filtered_ids"] = []
                            json_file.add(json.dumps(json_test))
                            events_id.add(json_test["event_id"])
            mapping.append({"file_name":item["file_name"],"event_id":list(events_id)})
        except Exception as ex:
            pass
    out_file = ""
    for item in json_file:
        out_file += item+"\n"
    return out_file, mapping
def get_args():
    parser = argparse.ArgumentParser(description="Get total file on s")
    parser.add_argument("-c", "--config", dest="config", help="config filepath for EDR/SIEM server, default value is ./SeaTable/test_config.json")
    parser.add_argument("-k", "--key", dest="key", help = "key of access token")
    parser.add_argument("-o", "--output", dest="output", help = "csv rule output")
    parser.add_argument("-t", "--testcase", dest="testcase", help = "testcase rule output")
    parser.add_argument("-p", "--platform", dest="platform", help = "platform")
    return parser.parse_args()

def main():
    args = get_args()
    config = CONFIG_PATH
    if args.config != None:
        config = args.config
    key = args.key
    platform = args.platform
    json_file, mapping = get_testing_data(platform=platform, key = key, config=config)
    print(len(mapping))
    open(args.output, "w").write(json.dumps(mapping))
    open(args.testcase, "w").write(json_file)
main()
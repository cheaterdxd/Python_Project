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
    "vcs_ajiant": {
        "rule_name" : "RULE NAME EDR",
        "test_case" : "JSON EDR",
        "verify_fp" : "VERIFY FP EDR",
        "coverage_rule_ver1": "COVERAGE RULE VER1 EDR",
        "note": "NOTE OUTPUT EDR"
    },
    "vcs_cym": {
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

def get_full_json(api_token, platform):
    base = Base(api_token, server_url)
    base.auth()
    meta_data = base.get_metadata()["tables"]
    test_case = []
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
            try:
                log_json = row[PLATFORM_PATH[platform]["test_case"]].splitlines()
                for test in log_json:
                    try:
                        test_json = json.loads(test)
                        if "filtered_ids" in test_json:
                            test_json["filtered_ids"] = []
                        test_case.append(test_json)
                    except Exception as ex:
                        pass
                        # print(ex)
            except Exception as ex:
                pass
                # print(ex)
    return test_case
#!/usr/bin/env python3
import requests
import warnings
import sys
warnings.filterwarnings('ignore')

# Defalt value data
RAW_SEARCH = {
    "_size":50,
    "_counting":True,
    "_from":0,"_sort":"-modified_time",
    "_query":{
        "category":[],
        "subcategory":[],
        "engines":[],
        "by_actor":False,
        "text_search":"",
        "name":"",
        "time_from":0,
        "time_to":9999999999999,
        "creator":"",
        "rule_type":"",
        "optional_type":""
        }
    }

# TODO search rule by rule_name
def search_rule(rule_name = str, cookie = str,  server = "https://10.255.251.153"):
    # Update query
    RAW_SEARCH["_query"].update({"name": rule_name.strip()})
    
    # Request to server
    searches = requests.post(
        server + "/api/rule/search", 
        json = RAW_SEARCH,
        verify = False,
        headers = {"Cookie":cookie},
    )
    
    # Find rule and return data
    try: 
        for rule in searches.json()["data"]:
            if (rule["rule_name"].lower() == rule_name.lower()):
                return rule
    except Exception as ex:
        print("An exception occur for \"{input}\": {exception}".format(input=rule_name, exception=ex), file=sys.stderr)
    return dict()

# TODO export rule by rule name
def export_rule(rule_name=None, cookie=None, rule_dir = "./", server = "https://10.255.251.153"):
    # Get list_rule to export (just only one but the api rule export need a list rule input)
    list_rule = search_rule(rule_name, cookie, server)
    
    # Request to take path of zip file to download 
    path = requests.post(
        server + "/api/rule/export",
        json = {
            "mode_export":"selected",
            "list_rule":[list_rule]
        },
        verify = False,
        headers = {"Cookie":cookie}
    ).json()["path"]
    # Download the export rule as zip file and return rule name
    rule_file = requests.post(
        server + "/api/rule/download",
        json = {
            "file_name":path
        },
        verify = False,
        headers = {"Cookie":cookie}
    ).content
    
    open(rule_dir + rule_name+".zip", "wb").write(rule_file)
    return rule_name

def gen_content(engine_json=None, cookie=None, server = "https://10.255.251.153"):
    content =  requests.post(
        server + "/api/rule/gen_content", 
        json = engine_json,
        verify = False,
        headers = {"Cookie":cookie}
    )
    try:
        return content.json()["content"]
    except:
        return content.json()

def create_rule(rule_json=None, cookie=None, server = "https://10.255.251.153"):
    create = requests.post(
        server + "/api/rule/save_rule", 
        json = rule_json,
        verify = False,
        headers = {"Cookie":cookie}
    )
    return create.json()

def verify_syntax_rule(content=None, engine=None, cookie=None, server = "https://10.255.251.153"):
    verify_syntax = requests.post(
        server + "/api/rule/verify_syntax", 
        json = {
            "engine":engine,
            "content":content
        },
        verify = False,
        headers = {"Cookie":cookie}
    )
    return verify_syntax.json()

def update_rule(rule_json=None, cookie=None, server = "https://10.255.251.153"):
    update_rule = requests.post(
        server + "/api/rule/update_rule", 
        json = rule_json, 
        verify = False,
        headers = {"Cookie":cookie}
    )
    return update_rule.json()
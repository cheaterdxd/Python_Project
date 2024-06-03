#!/usr/bin/env python3
import requests
import json
import warnings
import sys
warnings.filterwarnings('ignore')

RAW_SEARCH = {
    "_size":50,
    "_counting":True,
    "_from":0,
    "_sort":"-modified_time",
    "_query":{
        "category":[],
        "subcategory":[],
        "engines":[],
        "by_actor":False,
        "text_search":"",
        "name":"",
        "time_from":0,
        "time_to":0,
        "creator":""
    }
}

def get_access_token(cookie='', server = "https://siem.staging.vcs.vn", scope="read%3Arule"):
    rule_session = requests.get(
        server + f"/oauth/authorize?scope={scope}&client_id=cym_portal&audience=cym_api&response_type=code&redirect_uri=https%3A%2F%2Fsiem.staging.vcs.vn&include_granted_scope=false",
        verify = False,
        headers = {"Cookie":cookie}
    )
    referer = rule_session.history[0].headers["Location"]
    code = referer.replace("https://siem.staging.vcs.vn?code=", "")
    rule_session = requests.post(
        server+"/oauth/token",
        verify = False,
        headers = {"Cookie":cookie},
        data = {"code":code, "client_id":"cym_portal", "grant_type":"authorization_code", "redirect_uri":"https%3A%2F%2Fsiem.staging.vcs.vn", "audience":"cym_api"}
    )
    # print(rule_session.json())
    return rule_session.json()["access_token"]

def search_rule(rule_name='', cookie='', server = "https://siem.staging.vcs.vn"):
    # Update query
    RAW_SEARCH["_query"].update({"name": rule_name.strip()})
    
    # Request to server
    searches = requests.post(
        server + "/cymapi/v1/rule/list", 
        json = RAW_SEARCH,
        verify = False,
        headers = {"Authorization":"Bearer "+get_access_token(cookie, server, "read%3Arule")}
    )
    
    # Find rule and return data
    try:
        for rule in searches.json()["data"]:
            if (rule["rule_name"].lower() == rule_name.lower()):
                return rule
    except Exception as ex:
        print("An exception occur for \"{input}\": {exception}".format(input=rule_name, exception=ex), file=sys.stderr)
    return dict()

def export_rule(rule_id='', cookie='', rule_dir = './', server = "https://siem.staging.vcs.vn"):
    rule = search_rule(rule_id, cookie, server)["_id"]
    access_token = get_access_token(cookie, server, "read%3Arule")
    path = requests.post(
        server + "/cymapi/v1/rule/export",
        verify = False,
        headers = {"Authorization":"Bearer " + access_token},
        json = {"mode":"select","rule_ids":[rule]}
    ).json()["path"]
    rule_file = requests.get(
        server + "/cymapi/v1/rule/download?file_name="+path,
        verify = False,
        headers = {"Authorization":"Bearer " + access_token}
        ).content
    open(rule_dir + rule_id+".zip", "wb").write(rule_file)
    return rule_id

def gen_content(engine_json='', cookie='', server = "https://siem.staging.vcs.vn"):
    content =  requests.post(
        server + "/cymapi/v1/rule/gen-content", 
        json = engine_json,
        verify = False,
        headers = {"Authorization":"Bearer "+get_access_token(cookie, server, "read%3Arule")}
    )
    try:
        return content.json()["content"]
    except:
        return content.json()
    
def create_rule(rule_json='', cookie='', server = "https://siem.staging.vcs.vn"):
    create = requests.post(
        server + "/cymapi/v1/rule", 
        json = rule_json,
        verify = False,
        headers = {"Authorization":"Bearer "+get_access_token(cookie, server, "create%3Arule")}
    )
    return create.json()

def verify_syntax_rule(content="", engine="", cookie="", server = "https://siem.staging.vcs.vn"):
    verify_syntax = requests.post(
        server + "/cymapi/v1/rule/verify-syntax", 
        json = {
            "engine":engine,
            "content":content
        },
        verify = False,
        headers = {"Authorization":"Bearer "+get_access_token(cookie, server, "read%3Arule")}
    )
    return verify_syntax.json()

def update_rule(rule_json="", cookie="", server = "https://siem.staging.vcs.vn"):
    access_token = get_access_token(cookie, server, "edit%3Arule")
    # print(access_token)
    update = requests.put(
        server + "/cymapi/v1/rule", 
        json = rule_json,
        verify = False,
        headers = {"Authorization":"Bearer "+access_token}
    )
    return update.json()
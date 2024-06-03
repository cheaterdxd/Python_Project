import yaml
import json
import time
import re
from pathlib import Path
import os
import sys
ROOT_PATH = os.path.join(os.path.dirname(__file__), '..')
sys.path.append(ROOT_PATH)
from EDR import edr_connection
from EDR import edr_rule
from SIEM import siem_connection
from SIEM import siem_rule
import argparse
from colorama import init, Fore, Style
init(convert=True)
OPERATOR_MAPPING = {
    "==" : "eq",
    "!=" : "ne",
    ">" : "gt",
    ">=" : "gte",
    "<" : "lt",
    ">=" : "lte"
}
STATUS_LEVEL = {
    "deprecated":"0",
    "test":"1",
    "experimental":"2",
    "stable":"3"
}
SEVERITY = {
    "info":"-1",
    "low":"1",
    "medium":"9",
    "high":"11",
    "critical":"16"
}
def get_rule_name(rule):
    # Generate rule name
    rule_name = rule["rule_name"].replace(" ", "_")+"_Ver"+str(rule["version"])
    if rule["product"].lower() == "vcs_cym" and not rule_name.startswith("ATTCK"):
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

def add_missing_field(rule):
    # Adding missing field and value for rule
    
    # Default Category and Subcategory
    if rule["product"].lower() == "vcs_cym": 
        if not "category" in rule:
            rule.update({"category":"Anomaly Detection"})
        if not "subcategory" in rule:
            rule.update({"subcategory":""})
    if rule["product"].lower() == "vcs_ajiant":
        if not "category" in rule:
            rule.update({"category":"Windows"})
        if not "subcategory" in rule:
            rule.update({"subcategory":"APT"})
    
    # Missing indicator field
    try:
        alert = rule["indicator"]["action"]["alert"]
        if "source_log" not in alert["alert_fields"] and "source_log" not in alert["event_fields"]:
            alert["alert_fields"].update({"source_log":"mixed"})
        if "description" not in alert["alert_fields"] and "description" not in alert["event_fields"]:
            alert["alert_fields"].update({"description":rule["description"]})
        if "description_en" not in alert["alert_fields"] and "description_en" not in alert["event_fields"]:
            alert["alert_fields"].update({"description_en":rule["description"]})
        if rule["product"].lower() == "vcs_cym":
            if "message" not in alert["alert_fields"] and "message" not in alert["event_fields"]:
                alert["alert_fields"].update({"message":rule["description"]})
            if "message_en" not in alert and "message_en" not in alert["event_fields"]:
                alert["alert_fields"].update({"message_en":rule["description"]})
    except:
        return False
    try:
        if "reference" not in alert["alert_fields"] and "reference" not in alert["event_fields"]:  
            reference = ""
            for item in rule["reference"]:
                reference += item+"\n"
            reference=reference[:-1]
            alert["alert_fields"].update({"reference":reference})
    except:      
        print("W: Don't have reference in rule")
    
    # Add tags Mitre technique and link
    try: 
        rule["tags"]=rule["tags"]+(rule["mitre-attack"]["technique"])
        if "link" not in alert["alert_fields"] and "reference" not in alert["event_fields"]:
            link = ""
            for item in rule["mitre-attack"]["technique"]:
                link += "https://attack.mitre.org/techniques/"+item.upper().replace(".","/")+"/\n"
            alert["alert_fields"].update({"link":link[:-1]})
    except:
        pass
    
    # Add event including filtered_ids
    if not "event" in rule["indicator"]:
        rule["indicator"].update({"event":{}})
    if not "query" in rule["indicator"]:
        rule["indicator"]["event"].update({"query":[]})
    is_filter = False
    for item in rule["indicator"]["event"]["query"]:
        if "filtered_ids|contains" in item or "filtered_ids|contains|raw":
            is_filter = True
            break
    if not is_filter:
        rule["indicator"]["event"]["query"].append({"filtered_ids|contains":f"Filter_{get_rule_id(rule)}"})
        
    # Add accumulate including filtered_ids
    try:
        is_filter = False
        for item in rule["indicator"]["accumulate"]["query"]:
            if "filtered_ids|contains" in item or "filtered_ids|contains|raw" in item:
                is_filter = True
                break
        if not is_filter:
            rule["indicator"]["accumulate"]["query"] = [{"filtered_ids|contains":f"Filter_{get_rule_id(rule)}"}] + rule["indicator"]["accumulate"]["query"]
    except:
        pass

    # Add severity for alert
    if not "severity|raw" in rule["indicator"]["action"]["alert"]["alert_fields"]:
        rule["indicator"]["action"]["alert"]["alert_fields"].update({"severity|raw":"9"})
    if "severity" in rule:
        rule["indicator"]["action"]["alert"]["alert_fields"]["severity|raw"] = SEVERITY[rule["severity"]]
        
    # Add release level for alert
    if not "release_level|raw" in rule["indicator"]["action"]["alert"]["alert_fields"]:
        rule["indicator"]["action"]["alert"]["alert_fields"].update({"release_level|raw":1})
    if "status" in rule:
        rule["indicator"]["action"]["alert"]["alert_fields"]["release_level|raw"] = STATUS_LEVEL[rule["status"]]
    
    # Add object_type "device" for alert
    if not "object_type" in rule["indicator"]["action"]["alert"]["alert_fields"]:
        rule["indicator"]["action"]["alert"]["alert_fields"].update({"object_type":"device"})
    if not ("events" or "events|raw") in rule["indicator"]["action"]["alert"]["alert_fields"] and not ("events" or "events|raw") in rule["indicator"]["action"]["alert"]["event_fields"]:
        rule["indicator"]["action"]["alert"]["alert_fields"].update({"events|raw":"$events_id"})
    return True

def action_activelist_parser(action):
    action_activelist = {
            "content": [],
            "enable": False
        }
    if "action" in action:
        action = action["action"]
    if "activelist" in action:
        # TODO: Parser activelist
        action_activelist["enable"] = True
    return action_activelist

def action_alert_parser(action):
    action_alert = {
            "content": [
                {
                    "left": "severity",
                    "right": "1"
                },
                {
                    "left": "object",
                    "right": "\"\""
                },
                {
                    "left": "object_type",
                    "right": "\"\""
                },
                {
                    "left": "organization_group",
                    "right": "\"\""
                }    
            ],
            "enable": False
        }
    if "action" in action:
        action = action["action"]
    if "alert" in action:
        # TODO: Parser alert
        content = []
        for item in action["alert"]["alert_fields"]:
            value = str(action["alert"]["alert_fields"][item])
            try:
                field, option = item.split("|",1)
            except:
                field = item
                option = None
            if option != "raw":
                value = f"\"{value}\""
            content.append({"left":field,"right":value})
        for item in action["alert"]["event_fields"]:
            value = item.capitalize()
            content.append({"left":item,"right":f"$event.get{value}()"})
        action_alert["enable"] = True
        action_alert["content"] = content
    return action_alert

def action_enrichment_parser(action):
    action_enrichment = {
            "content": [],
            "enable": False
        }
    if "action" in action:
        action = action["action"]
    if "enrichment" in action:
        # TODO: Parser enrichment
        action_enrichment["enable"] = True
    return action_enrichment
    
def query_parser(query):
    block = []
    for item in query:
        for key in item:
            if (key == "AND") or (key == "OR"):
                block.append({"cond_exps":[],"operator":key,"type":"container"})
                block[len(block)-1]["cond_exps"].append(query_parser(item[key]))
            else:
                left, operator = key.rsplit("|",1)
                is_raw = False
                if operator == "raw":
                    is_raw = True
                    left, operator = left.rsplit("|",1)
                right = item[key]
                if item[key] != None:
                    right = str(item[key])
                if not is_raw and item[key] != None:
                    right = f"\"{item[key]}\""
                if item[key] == None:
                    right = "null"
                if operator in OPERATOR_MAPPING:
                    operator = OPERATOR_MAPPING[operator]
                block.append({"is_array":False, "left":left, "operator":operator, "right":right, "type":"item"})
                # print(left, operator, right)
    return block

def logsource_feature(feature, value, product):
    key = feature.split("|",1)[0]
    if key == "category":
        if value == "process_creation":
            if product.lower() == "vcs_cym":
                return [{
                            "cond_exps": [
                                [
                                    {
                                        "is_array": False,
                                        "left": "log_parser",
                                        "operator": "eq",
                                        "right": "\"windows_event\"",
                                        "type": "item"
                                    },
                                    {
                                        "cond_exps": [
                                            [
                                                {
                                                    "cond_exps": [
                                                        [
                                                            {
                                                                "is_array": False,
                                                                "left": "log_name",
                                                                "operator": "eq",
                                                                "right": "\"Microsoft-Windows-Sysmon/Operational\"",
                                                                "type": "item"
                                                            },
                                                            {
                                                                "is_array": False,
                                                                "left": "signature_id",
                                                                "operator": "eq",
                                                                "right": "\"1\"",
                                                                "type": "item"
                                                            }
                                                        ]
                                                    ],
                                                        "operator": "AND",
                                                        "type": "container"
                                                },
                                                {
                                                    "cond_exps": [
                                                        [
                                                            {
                                                                "is_array": False,
                                                                "left": "log_name",
                                                                "operator": "eq",
                                                                "right": "\"Security\"",
                                                                "type": "item"
                                                            },
                                                            {
                                                                "is_array": False,
                                                                "left": "signature_id",
                                                                "operator": "eq",
                                                                "right": "\"4688\"",
                                                                "type": "item"
                                                            }
                                                        ]
                                                    ],
                                                    "operator": "AND",
                                                    "type": "container"
                                                }
                                            ]
                                         ],
                                        "operator": "OR",
                                        "type": "container"
                                    }
                                ]
                            ],
                            "operator": "AND",
                            "type": "container"
                        }]

def logsource_parser(logsource, product):
    block = []
    for item in logsource:
        if item.endswith("|feature"):
            return logsource_feature(item, logsource[item], product)
        block.append({"is_array":False, "left":item, "operator":"eq", "right":f"\"{logsource[item]}\"", "type":"item"})
    block = {"cond_exps":[block],"operator":"AND","type":"container"}
    return [block]
    
def filter_parser(rule, server, access_token, cookie):
    filter = rule["filter"]
    engines_filter = {"engines_filter":{
        "action_activelist": action_activelist_parser(filter),
        "action_alert": action_alert_parser(filter),
        "action_enrichment": action_enrichment_parser(filter),  
        "condition_trees":[
            {
                "cond_exps": [logsource_parser(filter["event"]["logsource"], rule["product"])+query_parser(filter["event"]["query"])],
                "cond_notprefix": False,
                "operator": "Event",
                "type": "wrapper"
            } 
        ],
        "content": "",
        "content_old": "",
        "debug": False,
        "enable": True,
        "rule_file": "filter_anomaly_detection_.drl"
    }}
    content = gen_content(engines_filter["engines_filter"], "filter", get_rule_id(rule), rule["category"], rule["subcategory"], server, access_token, cookie)
    if content == None:
        return None
    engines_filter["engines_filter"]["content"] = content
    return engines_filter
        

# print(json.dumps(query_parser( query)))
# print(json.dumps(logsource_parser(logsource)))

def gen_content(engine_rule, engine_name, rule_id, category, subcategory, server, access_token, cookie):
    data = {
        "engine": engine_name,
        "engine_rule": engine_rule,
        "priority": 1,
        "rule_id": rule_id,
        "category": category,
        "subcategory": subcategory
    }
    # TODO: request to server to generate content filter
    content = server.gen_content(data, cookie)
    # verify_syntax = server.verify_syntax_rule(content, engine_name, cookie)
    # if "status" in verify_syntax and "detail" in verify_syntax:
    #     print(Fore.RED+"[-] "+verify_syntax["detail"]+Style.RESET_ALL)
    #     return None
    # if "code" in verify_syntax:
    #     if verify_syntax["code"] != 200:
    #         print(Fore.RED+"[-] "+verify_syntax["message"]+Style.RESET_ALL)
    #         return None
    return content

def accumulate_count(accumulate):
    for item in accumulate:
        if "count|" in item:
            return item.split("|")[1], accumulate[item]

def indicator_parser(rule, server, access_token, cookie):
    indicator = rule["indicator"]
    event = query_parser(indicator["event"]["query"])
    tags = ""
    for tag in rule["tags"]:
        tags += f"\"{tag}\", "
    tags = f"[{tags[:-2]}]"
    event.append({"is_array":False,"left":tags,"operator":"assign","right":"$tags","type":"item"})
    acc_count_operator, acc_count = accumulate_count(indicator["accumulate"])
    # print(indicator["accumulate"])
    engines_indicator = {
        "engines_indicator":{
            "action_alert":action_alert_parser(indicator),
            "condition_trees": [
                {
                    "cond_exps": [event],
                    "cond_notprefix": False,
                    "operator": "Event",
                    "type": "wrapper"
                },
                {
                    "cond_exps": [query_parser(indicator["not_alert"]["query"])],
                    "cond_notprefix": True,
                    "cond_windowtime_unit": re.findall(r"[hms]",indicator["not_alert"]["time_window"])[0],
                    "cond_windowtime_value": int(re.findall(r"\d+",indicator["not_alert"]["time_window"])[0]),
                    "operator": "AlertEvent",
                    "type": "wrapper"
                },
                {
                    "cond_count": acc_count,
                    "cond_count_operator": acc_count_operator,
                    "cond_exps": [query_parser(indicator["accumulate"]["query"])],
                    "cond_notprefix": False,
                    "cond_windowtime_unit": re.findall(r"[hms]",indicator["accumulate"]["time_window"])[0],
                    "cond_windowtime_value": int(re.findall(r"\d+",indicator["accumulate"]["time_window"])[0]),
                    "operator": "Accumulate",
                    "type": "wrapper"
                }
            ],
            "content": "",
            "content_old": "",
            "debug": False,
            "enable": True,
            "rule_file": "indicator_anomaly_detection_.drl"
        }
    }
    content = gen_content(engines_indicator["engines_indicator"], "indicator", get_rule_id(rule), rule["category"], rule["subcategory"], server, access_token, cookie)
    if content == None:
        return None
    engines_indicator["engines_indicator"]["content"] = content
    return engines_indicator
 
def create_rule(rule, server, access_token, cookie):
    engines_filter = filter_parser(rule, server, access_token, cookie)
    engines_indicator = indicator_parser(rule, server, access_token, cookie)
    if engines_filter == None or engines_indicator == None:
        return None
    rule_json = {
        "subcategory":rule["subcategory"],
        "optional_type":"custom",
        "create_time": int(time.time()*1000),
        "category":rule["category"],
        "priority":1,
        "engines_filter":engines_filter["engines_filter"],
        "engines_indicator":engines_indicator["engines_indicator"],
        "engines_falsepositive": {
            "content": "",
            "content_old": "",
            "enable": False,
            "debug": False,
            "action_enrichment": {
                "enable": False,
                "content": []
            },
            "condition_trees": [
                {
                    "type": "wrapper",
                    "operator": "Event",
                    "cond_exps": [
                        [
                            {
                                "type": "item",
                                "operator": "",
                                "right": "",
                                "left": "",
                                "is_array": False
                            }
                        ]
                    ],
                    "cond_notprefix": False
                }
            ]
        },
        "engines_enrichment": {
            "content": "",
            "content_old": "",
            "enable": False,
            "debug": False,
            "action_enrichment": {
                "enable": False,
                "content": []
            },
            "condition_trees": [
                {
                    "type": "wrapper",
                    "operator": "Event",
                    "cond_exps": [
                        [
                            {
                                "type": "item",
                                "operator": "",
                                "right": "",
                                "left": "",
                                "is_array": False
                            }
                        ]
                    ],
                    "cond_notprefix": False
                }
            ]
        },
        "engines_agg_trigger": {
            "content": "",
            "content_old": "",
            "enable": False,
            "debug": False,
            "condition_trees": [
                {
                    "type": "wrapper",
                    "operator": "Event",
                    "cond_exps": [
                        [
                            {
                                "type": "item",
                                "operator": "",
                                "right": "",
                                "left": "",
                                "is_array": False
                            }
                        ]
                    ],
                    "cond_notprefix": False
                }
            ]
        },
        "engines_agg_action": {
            "content": "",
            "content_old": "",
            "enable": False,
            "debug": False,
            "action_code": {
                "enable": False,
                "content": ""
            },
            "condition_trees": [
                {
                    "type": "wrapper",
                    "operator": "Accumulate",
                    "cond_exps": [
                        [
                            {
                                "type": "item",
                                "operator": "",
                                "right": "",
                                "left": "",
                                "is_array": False
                            }
                        ]
                    ],
                    "cond_notprefix": False
                }
            ]
        },
        "engines_whitelist": {
            "content": "",
            "content_old": "",
            "enable": False,
            "debug": False,
            "action": "drop",
            "action_alert": {
                "enable": False,
                "content": [
                    {
                        "left": "severity",
                        "right": "1"
                    },
                    {
                        "left": "object",
                        "right": "\"\""
                    },
                    {
                        "left": "object_type",
                        "right": "\"\""
                    },
                    {
                        "left": "organization_group",
                        "right": "\"\""
                    }
                ]
            },
            "action_activelist": {
                "enable": False,
                "content": []
            },
            "condition_trees": [
                {
                    "type": "wrapper",
                    "operator": "Event",
                    "cond_exps": [
                        [
                            {
                                "type": "item",
                                "operator": "",
                                "right": "",
                                "left": "",
                                "is_array": False
                            }
                        ]
                    ],
                    "cond_notprefix": False
                }
            ]
        },
        "description":rule["description"],
        "deploy":False,
        "rule_name":get_rule_name(rule),
        "modified_time":int(time.time()*1000),
        "rule_type":"builder",
        "redeploy":False,
        "rule_id":get_rule_id(rule),
        "tags":rule["tags"],
        "creator":rule["author"]
    }
    #return json.dumps(rule_json)
    return server.create_rule(rule_json, cookie)

def get_args():
    parser = argparse.ArgumentParser(description="Testing rule EDR/SIEM by check list")
    parser.add_argument("-c", "--config", dest="config", help="config filepath for EDR/SIEM server, default value is ./Converter/config.json")
    parser.add_argument("-i", "--input", dest="input", help = "rule yaml file")
    return parser.parse_args()

def main():
    args = get_args()
    config_file = f"{ROOT_PATH}\\Rule Offline\\config.json"
    if args.config != None:
        config_file = args.config
    config = json.load(open(config_file,"r"))
    rule = rule = yaml.safe_load(open(args.input, "r"))
    add_missing_field(rule)
    cookie, access_token = None, None
    server = None
    if rule["product"].lower() == "vcs_cym":
        try:
            cookie, access_token = siem_connection.login(config["vcs_cym"]["username"], config["vcs_cym"]["password"])
            server = siem_rule
            if access_token == None:
                raise Exception("Access token none")
            print(Fore.GREEN+f"[+] Logon success on VCS_CyM"+Style.RESET_ALL)
        except:
            print(Fore.RED+f"[-] Logon failed on VCS_CyM"+Style.RESET_ALL)
            return 
    if rule["product"].lower() == "vcs_ajiant":
        try:
            cookie, access_token = edr_connection.login(config["vcs_ajiant"]["username"], config["vcs_ajiant"]["password"])
            server = edr_rule
            if access_token == None:
                raise Exception("Access token none")
            print(Fore.GREEN+f"[+] Logon success on VCS_Ajiant"+Style.RESET_ALL)
        except:
            print(Fore.RED+f"[-] Logon failed on VCS_Ajiant",Style.RESET_ALL)
            return
    result = create_rule(rule, server, access_token, cookie)
    if result == None:
        return
    if "detail" in result:
        print(Fore.RED+"[-] "+result["detail"],Style.RESET_ALL)
    else:
        id = result["_id"]
        yml_rule = re.sub(r"\nid:.*",f"\nid: {id}",open(args.input, "r").read())
        open(args.input, "w").write(yml_rule)
        print(Fore.GREEN+f"[+] Created success rule {get_rule_name(rule)} with id:{id}"+Style.RESET_ALL)
    
    

main()
# print(json.dumps(create_rule(rule)))


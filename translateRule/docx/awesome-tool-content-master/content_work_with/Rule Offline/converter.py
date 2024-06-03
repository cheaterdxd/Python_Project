
import yaml
import json
import time
import re
from pathlib import Path
import os
import sys

HOME_DIR = os.getenv('HOME')
if HOME_DIR == None:
    HOME_DIR = os.path.join(os.path.dirname(__file__), '..')
REPO_DIR = HOME_DIR + '/awesome-tool-content'
ROOT_PATH = os.path.join(os.path.dirname(__file__), '..')
sys.path.append(ROOT_PATH)
from EDR import edr_connection
from EDR import edr_rule
from SIEM import siem_connection
from SIEM import siem_rule
import argparse
from colorama import init, Fore, Style
init(convert=True)
cookie_edr, cookie_siem, access_token_edr, access_token_siem  = [None] * 4
cookie, access_token, server_address, args, config, server = [None] * 6
config_file = f"{REPO_DIR}/config/config.json"

OPERATOR_MAPPING = {
    "==" : "eq",
    "!=" : "ne",
    ">" : "gt",
    ">=" : "gte",
    "<" : "lt",
    "<=" : "lte",
}
SPECIAL_OPERATOR = {
    "endswith" : "endsWith",
    "startswith" : "startsWith",
    "not endswith": "endsWith",
    "not startswith": "startsWith"
}
STATUS_LEVEL = {
    "deprecated":"-1",
    "development":"0",
    "test":"1",
    "experimental":"2",
    "stable":"3"
}
SEVERITY = {
    "info":"0",
    "low":"2",
    "medium":"9",
    "high":"11",
    "critical":"16"
}
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

def add_missing_field(rule):
    # Adding missing field and value for rule
    # Default Category and Subcategory
    if rule["product"].lower() == "vcs_ajiant":
        if not "category" in rule:
            rule.update({"category":"VCS_Content_TI"})
        if not "subcategory" in rule:
            rule.update({"subcategory":"Anomaly"})
    if rule["product"].lower() == "vcs_cym":
        rule.update({"category":"Anomaly Detection"})
        rule.update({"subcategory":""})
    # Missing indicator field
    try:
        alert = rule["indicator"]["action"]["alert"]
        # print(rule["description"])
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
        pass
    try:
        filter_alert = rule["filter"]["action"]["alert"]
        # print(rule["description"])
        if "source_log" not in filter_alert["alert_fields"] and "source_log" not in filter_alert["event_fields"]:
            filter_alert["alert_fields"].update({"source_log":"mixed"})
        if "description" not in filter_alert["alert_fields"] and "description" not in filter_alert["event_fields"]:
            filter_alert["alert_fields"].update({"description":rule["description"]})
        if "description_en" not in filter_alert["alert_fields"] and "description_en" not in filter_alert["event_fields"]:
            filter_alert["alert_fields"].update({"description_en":rule["description"]})
        if rule["product"].lower() == "vcs_cym":
            if "message" not in filter_alert["alert_fields"] and "message" not in filter_alert["event_fields"]:
                filter_alert["alert_fields"].update({"message":rule["description"]})
            if "message_en" not in alert and "message_en" not in alert["event_fields"]:
                filter_alert["alert_fields"].update({"message_en":rule["description"]})
    except:
        pass
    # 
    # Add tactic technique
    try:
        if rule["product"].lower() == "vcs_ajiant":
            attack_tactic = ""
            for item in rule["mitre-attack"]["tactic"]:
                attack_tactic += f"{item}, "
            if len(attack_tactic) >= 2:
                alert["alert_fields"].update({"attack_tactic":attack_tactic[:-2]})
            attack_technique = ""
            for item in rule["mitre-attack"]["technique"]:
                attack_technique += f"{item}, "
            if len(attack_technique) >= 2:
                alert["alert_fields"].update({"attack_technique":attack_technique[:-2]})
    except:
        pass
    try:
        if "reference" not in alert["alert_fields"] and "reference" not in alert["event_fields"]:  
            reference = ""
            if(isinstance(rule["reference"], list)):
                for item in rule["reference"]:
                    reference += item+"\\n"
                reference=reference[:-2]
            elif (isinstance(rule["reference"], str)):
                reference = str(rule["reference"])
            alert["alert_fields"].update({"reference":reference})
    except:      
        pass
        # print("W: Don't have reference in rule")
    try:
        if "reference" not in filter_alert["alert_fields"] and "reference" not in filter_alert["event_fields"]:  
            reference = ""
            if(isinstance(rule["reference"], list)):
                for item in rule["reference"]:
                    reference += item+"\\n"
                reference=reference[:-2]
            elif (isinstance(rule["reference"], str)):
                reference = str(rule["reference"])
            alert["alert_fields"].update({"reference":reference})
    except:      
        pass
    # Add tags Mitre technique and link
    try: 
        rule["tags"]=rule["tags"]+(rule["mitre-attack"]["technique"])
        rule["tags"]=list(dict.fromkeys(rule["tags"])) # remove dup tag
        tags_str = ""
        for item in rule["tags"]:
            tags_str += f"\"{item}\", "
        tags_str = f"java.util.Arrays.asList({tags_str[:-2]})"
        if "tags|raw" not in alert["alert_fields"] and "tags" not in alert["event_fields"]:
            alert["alert_fields"].update({"tags|raw":tags_str})
        if "tags|raw" not in filter_alert["alert_fields"] and "tags" not in filter_alert["event_fields"]:
            filter_alert["alert_fields"].update({"tags|raw":tags_str})
    except:
        pass   
    try:
        if "link" not in alert["alert_fields"] and "reference" not in alert["event_fields"]:
            link = ""
            for item in rule["mitre-attack"]["technique"]:
                link += "https://attack.mitre.org/techniques/"+item.upper().replace(".","/")+"/\\n"
            if link.endswith("\\n"):
                link = link[:-2]
            alert["alert_fields"].update({"link":link})
    except:
        pass
    # Add event including filtered_ids
    try:
        if rule["subcategory"] != "Correlation":
            if not "event" in rule["indicator"] :
                rule["indicator"].update({"event":{}})
            if not "query" in rule["indicator"]["event"]:
                rule["indicator"]["event"].update({"query":[]})
            is_filter = False
            for item in rule["indicator"]["event"]["query"]:
                if "filtered_ids|contains" in item or "filtered_ids|contains|raw" in item:
                    is_filter = True
                    break
            if not is_filter:
                
                rule["indicator"]["event"]["query"].append({"filtered_ids|contains":f"Filter_{get_rule_id(rule)}"})
    except:
        pass
    # Add accumulate including filtered_ids
    try:
        if rule["subcategory"] != "Correlation":
            is_filter = False
            for item in rule["indicator"]["accumulate"]["query"]:
                if "filtered_ids|contains" in item or "filtered_ids|contains|raw" in item:
                    is_filter = True
                    break
            if not is_filter:
                rule["indicator"]["accumulate"]["query"] = [{"filtered_ids|contains":f"Filter_{get_rule_id(rule)}"}] + rule["indicator"]["accumulate"]["query"]
    except:
        pass
    try:
        severity = SEVERITY[rule["severity"]]
        if rule['product'].lower() == 'vcs_ajiant':
            severity = str(int(SEVERITY[rule["severity"]]) - 1)
        # Add severity for alert
        if not "severity|raw" in rule["indicator"]["action"]["alert"]["alert_fields"]:
            rule["indicator"]["action"]["alert"]["alert_fields"].update({"severity|raw":"9"})
        if "severity" in rule:
            rule["indicator"]["action"]["alert"]["alert_fields"]["severity|raw"] = severity
    except:
        pass
    try:
        if not "severity|raw" in rule["filter"]["action"]["alert"]["alert_fields"]:
            rule["filter"]["action"]["alert"]["alert_fields"].update({"severity|raw":"9"})
        if "severity" in rule:
            rule["filter"]["action"]["alert"]["alert_fields"]["severity|raw"] = severity
    except:
        pass
    # Add release level for alert
    try:
        if not "release_level|raw" in rule["indicator"]["action"]["alert"]["alert_fields"]:
            rule["indicator"]["action"]["alert"]["alert_fields"].update({"release_level|raw":0})
        if "status" in rule:
            rule["indicator"]["action"]["alert"]["alert_fields"]["release_level|raw"] = STATUS_LEVEL[rule["status"]]
    except:
        pass
    try:
        if not "release_level|raw" in rule["filter"]["action"]["alert"]["alert_fields"]:
            rule["filter"]["action"]["alert"]["alert_fields"].update({"release_level|raw":0})
        if "status" in rule:
            status_level = STATUS_LEVEL[rule["status"]]
            if int(status_level) > 2:
                status_level = "2"
            rule["filter"]["action"]["alert"]["alert_fields"]["release_level|raw"] = status_level
    except:
        pass
    # Add object_type "device" for alert
    try:
        if not "object_type" in rule["indicator"]["action"]["alert"]["alert_fields"]:
            rule["indicator"]["action"]["alert"]["alert_fields"].update({"object_type":"device"})
        if not ("events" or "events|raw") in rule["indicator"]["action"]["alert"]["alert_fields"] and not ("events" or "events|raw") in rule["indicator"]["action"]["alert"]["event_fields"]:
            rule["indicator"]["action"]["alert"]["alert_fields"].update({"events|raw":"$events_id"})
    except:
        pass
    try:
        if not "object_type" in rule["filter"]["action"]["alert"]["alert_fields"]:
            rule["filter"]["action"]["alert"]["alert_fields"].update({"object_type":"device"})
        if not ("events" or "events|raw") in rule["filter"]["action"]["alert"]["alert_fields"] and not ("events" or "events|raw") in rule["filter"]["action"]["alert"]["event_fields"]:
            if rule["product"].lower() == "vcs_cym": 
                rule["filter"]["action"]["alert"]["alert_fields"].update({"events|raw":"$event.getEvent_id()"})
            if rule["product"].lower() == "vcs_ajiant": 
                rule["filter"]["action"]["alert"]["alert_fields"].update({"events|raw":"$event.getEvent_log_id()"})
    except:
        pass
    return rule

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

def action_alert_parser(action, fields= []):
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
            if item not in fields:
                content.append({"left":item,"right":f"$event.get{value}()"})
        # for item in action["content"]
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
        content = []
        for item in action["enrichment"]:
            value = str(action["enrichment"][item])
            try:
                field, option = item.split("|",1)
            except:
                field = item
                option = None
            if option != "raw":
                value = f"\"{value}\""
            content.append({"left":field,"right":value})
        action_enrichment["enable"] = True
        action_enrichment["content"] = content
    return action_enrichment
    
def query_parser(query, product, safe_null = True, first = True, bind_fields = []):
    block = []
    null_fields = []
    bind_field = bind_fields
    for item in query:
        for key in item:
            if (key == "AND") or (key == "OR"):
                block.append({"cond_exps":[],"operator":key,"type":"container"})
                temp_null_fields, temp_block = query_parser(item[key], product, safe_null, first=False, bind_fields=bind_field)
                block[len(block)-1]["cond_exps"].append(temp_block)
                null_fields += temp_null_fields
            else:
                left, operator = key.rsplit("|",1)
                is_raw = False
                if operator == "raw":
                    is_raw = True
                    left, operator = left.rsplit("|",1)
                right = item[key]
                if not is_raw:
                    right = json.dumps(item[key], ensure_ascii=False).encode("utf-8").decode()
                if operator in SPECIAL_OPERATOR:
                    left = f"{left}.{SPECIAL_OPERATOR[operator]}({right})"
                    right = "true" 
                    if operator.startswith("not"):
                        right = "false"
                    operator = "=="
                operatorObj = {"key":operator, "label": operator}
                if operator in OPERATOR_MAPPING:
                    operatorObj = {"key":OPERATOR_MAPPING[operator], "label": operator}
                    operator = OPERATOR_MAPPING[operator]
                if operator not in OPERATOR_MAPPING and operator.startswith("not"):
                    operator = operator.replace("not", "").strip()
                    left += " not"
                    operatorObj = {"key":operator, "label": operator}
                for bind_field in bind_fields:
                    # print (bind_field[0], bind_field[1])
                    if (bind_field[1]==left):
                        # print ('hihidada')
                        left = bind_field[1].replace(bind_field[0],'(getUnknownFields().get("'+ bind_field[0] +'")+"")')
                        # print(left)
                if product.lower() == "vcs_ajiant":
                    block.append({"is_array":False, "left":left, "operator":operator, "operatorObj":operatorObj, "right":right, "type":"item"})
                if product.lower() == "vcs_cym":
                    block.append({"is_array":False, "left":left, "operator":operator, "right":right, "type":"item"})
                if re.search(r"^\(?[a-z][a-zA-Z0-9_\$]*\.", left) and safe_null:
                    try:
                        null_fields.append(re.search(r"[a-z][a-zA-Z0-9_\$]*", left)[0])
                    except:
                        pass
                # print(left, operator, right)
    if not first:
        return null_fields, block
    if len(null_fields) == 0:
        return block
    safe_null_block=[]
    for item in set(null_fields):
        if product.lower() == "vcs_ajiant":
            safe_null_block.append({"is_array":False, "left":item, "operator":"ne", "operatorObj":{"key": "ne",
                  "label": "!="}, "right":"null", "type":"item"})
        if product.lower() == "vcs_cym":
            safe_null_block.append({"is_array":False, "left":item, "operator":"ne", "right":"null", "type":"item"})
    return ([{"cond_exps":[safe_null_block],"operator":"AND","type":"container"}]+block)

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
        if value == "access":
            if product.lower() == "vcs_cym":
                return [{
                            "cond_exps": [
                                [
                                    {
                                        "is_array": False,
                                        "left": "log_parser",
                                        "operator": "contains",
                                        "right": "\"access\"",
                                        "type": "item"
                                    },
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

def unknownfields_parser(fields: list):
    block = []
    for field in set(fields):
        block.append({"is_array":False, "left":'(getUnknownFields().get("'+ field +'") + "")', "operator":"assign", "right":field, "type":"item"})
    block = {"cond_exps":[block],"operator":"AND","type":"container"}
    return [block]


def filter_parser(rule, server, access_token, cookie, safe_null = True):
    content = None
    try:
        filter = rule["filter"]
    except:
        return {"engines_filter":{
        "action_activelist": action_activelist_parser(dict()),
        "action_alert": action_alert_parser(dict()),
        "action_enrichment": action_enrichment_parser(dict()),  
        "condition_trees":[
            {
                "cond_exps": [
                    [
                        {
                        "isFunction": False,
                        "is_array": False,
                        "left": "",
                        "operator": "",
                        "right": "",
                        "type": "item"
                        }
                    ]
                ],
                "cond_notprefix": False,
                "operator": "Event",
                "type": "wrapper"
            } 
        ],
        "content": "",
        "content_old": "",
        "debug": False,
        "enable": False,
    }}
    logsource = logsource_parser(filter["event"]["logsource"], rule["product"])
    query = query_parser(filter["event"]["query"], rule["product"], safe_null)
    engines_filter = {"engines_filter":{
        "action_activelist": action_activelist_parser(filter),
        "action_alert": action_alert_parser(filter),
        "action_enrichment": action_enrichment_parser(filter),  
        "condition_trees":[
            {
                "cond_exps": [logsource + query],
                "cond_notprefix": False,
                "operator": "Event",
                "type": "wrapper"
            } 
        ],
        "content": "",
        "content_old": "",
        "debug": False,
        "enable": True,
    }}
    try:
        content = gen_content(engines_filter["engines_filter"], "filter", get_rule_id(rule), rule["category"], rule["subcategory"], server, access_token, cookie)
    except Exception as ex:
        err_mode, unknown_fields = ex.args
        # print (err_mode)
        if 'strict-mode' in err_mode:
            unknownfields = unknownfields_parser(unknown_fields["strict-mode"])
            # print (unknownfields)
            # exit()
            engines_filter["engines_filter"]["condition_trees"][0]["cond_exps"] = [logsource + unknownfields + query]
            # print (engines_filter["engines_filter"]["content"])
            try:
                content = gen_content(engines_filter["engines_filter"], "filter", get_rule_id(rule), rule["category"], rule["subcategory"], server, access_token, cookie)
            except Exception as ex:
                err_mode, bind_fields = ex.args
                if 'bindings' in err_mode:
                    print (f'[o] Bindings err - assign unknowns fields for {bind_fields["bindings"]}')
                    query = query_parser(query=filter["event"]["query"], product=rule["product"], safe_null=safe_null, bind_fields=bind_fields["bindings"])
                    engines_filter["engines_filter"]["condition_trees"][0]["cond_exps"] = [logsource + unknownfields + query]
                    content = gen_content(engines_filter["engines_filter"], "filter", get_rule_id(rule), rule["category"], rule["subcategory"], server, access_token, cookie)
        if 'action-alert' in  err_mode:
            fields = unknown_fields
            fields = [i.lower() for i in fields['action-alert']]
            action_alert = action_alert_parser(action=filter, fields = fields)
            engines_filter['engines_filter']['action_alert'] = action_alert
            for i in engines_filter['engines_filter']['action_alert']['content']:
                if i['left'] == "tags":
                    i["right"] = i["right"][:-1]+", \"VCS_Unknown_Fields\")"
                    s = i["right"]
                    for j in fields:
                        s += '); alert.setUnknownFields("'+ j +'", $event.getUnknownFields().get("'+ j +'")'
                    i['right'] = s
            content = gen_content(engines_filter["engines_filter"], "filter", get_rule_id(rule), rule["category"], rule["subcategory"], server, access_token, cookie)

        # print(strict_list)
    if content == None:
        return None
    engines_filter["engines_filter"]["content"] = content
    return engines_filter

def false_positive_parser(rule, server, access_token, cookie, safe_null = True):
    content = ""
    engines_false_positive = {
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
        }
    }
    try:
        false_positive = rule["false_positive"]
    except:
        # print("abc")
        return engines_false_positive
    engines_false_positive["engines_falsepositive"]["enable"] = True
    engines_false_positive["engines_falsepositive"]["action_enrichment"]["enable"] = True
    features = set()
    cond_exps = []
    for event in false_positive:
        isRule_id = False
        query = []
        for item in event["event"]["query"]:
            if "set_severity|feature" in item:
                severity = SEVERITY[item["set_severity|feature"]]
                if rule["product"].lower() == "vcs_ajiant":
                    severity = int(severity) - 1 
                query.append({f"{str(severity)}|assign|raw":"$severity"})
                features.add("set_severity")
                continue
            if "rule_id|==" in item or "rule_id|contains" in item:
                isRule_id = True
            query.append(item)
        if not isRule_id:
            query = [{"rule_id|==":get_rule_id(rule)}]+query
        cond_exps.append({
                "cond_exps": [query_parser(query, rule["product"], safe_null=safe_null)],
                "cond_notprefix": False,
                "operator": "Event",
                "type": "wrapper"
            })
    for feature in features:
        if feature == "set_severity":
            engines_false_positive["engines_falsepositive"]["action_enrichment"]["content"].append({"left":"severity", "right":"$severity"})
    if len(cond_exps) == 1:
        engines_false_positive["engines_falsepositive"]["condition_trees"] = cond_exps
        try:
            content = gen_content(engines_false_positive["engines_falsepositive"], "falsepositive", get_rule_id(rule), rule["category"], rule["subcategory"], server, access_token, cookie)
        except Exception as ex:
            print (ex)
        engines_false_positive["engines_falsepositive"]["content"] = content    
        # print(json.dumps(engines_false_positive))
        return engines_false_positive
    engines_false_positive["engines_falsepositive"]["condition_trees"] = [{
        "cond_exps": [
            cond_exps
        ],
        "operator": "OR",
        "type": "container"
    }]
    # print(json.dumps(engines_false_positive))
    
    try:
        content = gen_content(engines_false_positive["engines_falsepositive"], "falsepositive", get_rule_id(rule), rule["category"], rule["subcategory"], server, access_token, cookie)
    except Exception as ex:
        print (ex)
    engines_false_positive["engines_falsepositive"]["content"] = content
    return engines_false_positive

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
    # print(content)
    verify_syntax = server.verify_syntax_rule(content, engine_name, cookie)
    if "status" in verify_syntax and "detail" in verify_syntax:
        print(Fore.RED+"[-] "+verify_syntax["detail"]+Style.RESET_ALL, file=sys.stderr)
        raise Exception("")
    if "code" in verify_syntax:
        if verify_syntax["code"] != 200:
            err_mode = []
            err_fields = {}
            # print (f'[-] Err {verify_syntax["message"]}')
            if 'strict-mode' in verify_syntax['message']:
                fields = re.findall(r"\[Error: unable to resolve method using strict-mode: .*Event\.([^\$\(\)]*).*", verify_syntax['message'])
                err_mode.append('strict-mode')
                if "" in fields: fields.remove("")
                err_fields.update({"strict-mode":list(set(fields))})
            if 'bindings' in verify_syntax['message']:
                fields = re.findall(r"Variables can not be used inside bindings. Variable \[([^\]]*)\] is being used in binding '([^']*)", verify_syntax['message'])
                err_mode.append('bindings')
                if "" in fields: fields.remove("")
                err_fields.update({"bindings":list(set(fields))})
            if 'Rule Compilation error' in verify_syntax['message'] and 'The method get' in verify_syntax['message']:
                print (verify_syntax['message'])
                fields = re.findall(r"The method get([^\(]*)", verify_syntax['message'])
                if "" in fields: fields.remove("")
                err_mode.append('action-alert')
                err_fields.update({"action-alert":list(set(fields))})
            if len(err_mode) > 0:
                raise Exception(err_mode, err_fields)
            print(Fore.RED+"[-] "+verify_syntax["message"]+Style.RESET_ALL, file=sys.stderr)
            print(Fore.RED+content+Style.RESET_ALL, file=sys.stderr)
            raise Exception("")
    return content

def white_list_parser(rule, server, access_token, cookie, safe_null):
    content = ""
    engine_white_list = {"engines_whitelist":{
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
        }}
    try:
        white_list = rule["white_list"]
    except:
        return engine_white_list
    engine_white_list["engines_whitelist"]["enable"] = True
    engine_white_list["engines_whitelist"]["action_activelist"]["enable"] = True
    engine_white_list["engines_whitelist"]["action"] = "activelist"
    query = query_parser(white_list["event"]["query"], rule["product"])
    for item in query:
        if item['left'] == 'set_rule_id' and item['operator'] == 'feature':
            item['left'] = f'addRuleId({item["right"]})'
            item['operator'] = 'eq'
            item['right'] = 'null'
            if rule["product"].lower() == 'vcs_ajiant':
                item['operatorObj'] = {'key': 'eq', 'label': '=='}
    engine_white_list["engines_whitelist"]["condition_trees"][0]["cond_exps"] = [query]
    content = gen_content(engine_white_list["engines_whitelist"], "whitelist", get_rule_id(rule), rule["category"], rule["subcategory"], server, access_token, cookie)
    #print(content)
    engine_white_list["engines_whitelist"]["content"] = content
    return engine_white_list

def accumulate_count(accumulate):
    for item in accumulate:
        if "count|" in item:
            return item.split("|")[1], accumulate[item]

def indicator_parser(rule, server, access_token, cookie):
    content, action_alert = None, None
    try:
        indicator = rule["indicator"]
    except:
        return {"engines_indicator": {
            "action_alert": {
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
            },
            "condition_trees": [
                {
                    "cond_exps": [
                        [
                            {
                                "is_array": False,
                                "left": "",
                                "operator": "",
                                "right": "",
                                "type": "item"
                            }
                        ]
                    ],
                    "cond_notprefix": False,
                    "operator": "Event",
                    "type": "wrapper"
                }
            ],
            "content": "",
            "content_old": "",
            "debug": False,
            "enable": False,
        }}
    event = query_parser(indicator["event"]["query"], rule["product"])
    acc_count_operator, acc_count = accumulate_count(indicator["accumulate"])
    action_alert = action_alert_parser(action=indicator)
    # print (action_alert)
    # print(indicator["accumulate"])
    engines_indicator = {
        "engines_indicator":{
            "action_alert":action_alert,
            "condition_trees": [
                {
                    "cond_count": None, 
                    "cond_count_operator": None, 
                    "cond_exps": [event],
                    "cond_notprefix": False,
                    "cond_windowtime_unit": "s", 
                    "cond_windowtime_value": "1", 
                    "operator": "Event",
                    "type": "wrapper"

                },
                {
                    "cond_exps": [query_parser(indicator["not_alert"]["query"], rule["product"])],
                    "cond_notprefix": True,
                    "cond_windowtime_unit": re.findall(r"[hms]",indicator["not_alert"]["time_window"])[0],
                    "cond_windowtime_value": int(re.findall(r"\d+",indicator["not_alert"]["time_window"])[0]),
                    "operator": "AlertEvent",
                    "type": "wrapper"
                },
                {
                    "cond_count": acc_count,
                    "cond_count_operator": acc_count_operator,
                    "cond_exps": [query_parser(indicator["accumulate"]["query"], rule["product"])],
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
        }
    }
    try:
        content = gen_content(engines_indicator["engines_indicator"], "indicator", get_rule_id(rule), rule["category"], rule["subcategory"], server, access_token, cookie)
    except Exception as ex:
        err_mode, fields = ex.args
        if 'action-alert' in err_mode:
            fields = [i.lower() for i in fields['action-alert']]
            action_alert = action_alert_parser(action=indicator, fields = fields)
            engines_indicator['engines_indicator']['action_alert'] = action_alert
            for i in engines_indicator['engines_indicator']['action_alert']['content']:
                if i['left'] == "tags":
                    i["right"] = i["right"][:-1]+", \"VCS_Unknown_Fields\")"
                    s = i["right"]
                    for j in fields:
                        s += '); alert.setUnknownFields("'+ j +'", $event.getUnknownFields().get("'+ j +'")'
                    i['right'] = s
            content = gen_content(engines_indicator["engines_indicator"], "indicator", get_rule_id(rule), rule["category"], rule["subcategory"], server, access_token, cookie)    
    if content == None:
        return None
    engines_indicator["engines_indicator"]["content"] = content
    return engines_indicator
 
def create_rule(rule, server, access_token, cookie, safe_null = True):
    engines_filter = filter_parser(rule = rule, server = server, access_token= access_token, cookie= cookie, safe_null= safe_null)
    engines_indicator = indicator_parser(rule, server, access_token, cookie)
    engines_falsepositive = false_positive_parser(rule, server, access_token, cookie, safe_null)
    engines_whitelist = white_list_parser(rule, server, access_token, cookie, safe_null)
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
        "engines_falsepositive": engines_falsepositive["engines_falsepositive"],
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
        "engines_whitelist": engines_whitelist["engines_whitelist"],
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
    # print(json.dumps(rule_json))
    #return json.dumps(rule_json)
    return server.create_rule(rule_json, cookie)

 
def update_rule(rule, server, access_token, cookie, safe_null = True):
    engines_filter = filter_parser(rule = rule, server=server,access_token= access_token,cookie= cookie,safe_null= safe_null)
    engines_indicator = indicator_parser(rule, server, access_token, cookie)
    engines_falsepositive = false_positive_parser(rule, server, access_token, cookie, safe_null)
    engines_whitelist = white_list_parser(rule, server, access_token, cookie, safe_null)
    if engines_filter == None or engines_indicator == None:
        return None
    rule_json = {
        "subcategory":rule["subcategory"],
        "optional_type":"custom",
        "category":rule["category"],
        "priority":1,
        "engines_filter":engines_filter["engines_filter"],
        "engines_indicator":engines_indicator["engines_indicator"],
        "engines_falsepositive": engines_falsepositive["engines_falsepositive"],
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
        "engines_whitelist": engines_whitelist["engines_whitelist"],
        "description":rule["description"],
        "deploy":False,
        "rule_name":get_rule_name(rule),
        "modified_time":int(time.time()*1000),
        "rule_type":"builder",
        "redeploy":False,
        "rule_id":get_rule_id(rule),
        "tags":rule["tags"],
        "creator":rule["author"],
        "_id":str(rule["id"])
    }
    # print(json.dumps(rule_json))
    return server.update_rule(rule_json, cookie)

def get_rule_link(id, product):
    global server_address
    if product.lower() == "vcs_cym":
        return f"{server_address}/correlation/view?type=builder&_id={id}"
    if product.lower() == "vcs_ajiant":
        return f"{server_address}/#/settings/rule_detail/view/{id}"

def handle_result(res, rule):
    global args, server_address
    if res == None:
        return 0
    if 'detail' in res:
        print(Fore.RED+"[-] "+res["detail"],Style.RESET_ALL, file=sys.stderr)
        return -1
    if 'update' in res:
        id = res["update"]["_id"]
        yml_rule = re.sub(r"\nid:.*",f"\nid: {id}",open(args.input.strip(), "r").read())
        open(args.input.strip(), "w").write(yml_rule)
        print(Fore.GREEN+f"[+] Update success rule {get_rule_name(rule)} with id:{id}"+Style.RESET_ALL)   
        link = get_rule_link(id, rule["product"])
        # print(Fore.GREEN+f"[+] You can follow by link: {link}"+Style.RESET_ALL)   
        if sys.platform == 'linux':
            aa = '/'
        else:
            aa = '\\'
        new_file = os.path.dirname(args.input.strip()) + aa + rule["rule_name"].replace(" ", "_").lower()+".yml"
        if args.rename and args.input.strip() != new_file:
            os.rename(args.input.strip(), new_file)  
            print(Fore.GREEN+f"[+] Rule was renamed to {new_file}"+Style.RESET_ALL) 
            # print ()

        return 1
    if '_id' in res:
        id = res["_id"]
        yml_rule = re.sub(r"\nid:.*",f"\nid: {id}",open(args.input.strip(), "r").read())
        open(args.input.strip(), "w").write(yml_rule)
        print(Fore.GREEN+f"[+] Created success rule {get_rule_name(rule)} with id:{id}"+Style.RESET_ALL)
        link = get_rule_link(id, rule["product"])
        # print(Fore.GREEN+f"[+] You can follow by link: {link}"+Style.RESET_ALL)    
        if sys.platform == 'linux':
            aa = '/'
        else:
            aa = '\\'  
        new_file = os.path.dirname(args.input.strip()) + aa + rule["rule_name"].replace(" ", "_").lower()+".yml"
        if args.rename and args.input.strip() != new_file:
            os.rename(args.input.strip(), new_file)  
            print(Fore.GREEN+f"[+] Rule was renamed to {new_file}"+Style.RESET_ALL) 
            # print ()
        return 2

def work_with_rule(rule):
    global server, args, cookie, access_token
    add_missing_field(rule)
    if args.update == True:
        search_result = server.search_rule(get_rule_name(rule), cookie = cookie)
        # print (search_result)
        if search_result == {}:
            raise ValueError("Rule not exist")
        if 'detail' in search_result:
            if 'rule_id has not existed' in search_result['detail']:
                raise ValueError("Rule not exist")
        if search_result['_id'] != rule['id']:
            rule['id'] = search_result['_id']
        res = update_rule(rule=rule, server=server, access_token=access_token, cookie=cookie, safe_null=args.safe)
        handle_result(res, rule)
        return 0
    res = create_rule(rule=rule, server=server, access_token=access_token, cookie=cookie, safe_null=args.safe)
    # update_rule(rule=rule, server=server, access_token=access_token, cookie=cookie, safe_null=args.safe)
    handle_result(res, rule)
    return 0

def get_args():
    parser = argparse.ArgumentParser(description="Convert rule Offline")
    parser.add_argument("-c", "--config", dest="config", help="config filepath for EDR/SIEM server, default value is ./config/config.json")
    parser.add_argument("-i", "--input", dest="input", help = "rule yaml file")
    parser.add_argument("-u", "--update", dest="update", action="store_true", help="update rule")
    parser.add_argument("-s", "--safe", dest="safe", action="store_false", help="disable auto safe null")
    parser.add_argument("-r", "--rename", dest="rename", action="store_true", help="renaming rule file by rule name")
    return parser.parse_args()

def config_module(rule, config):
    global args, server, config_file, cookie_edr, access_token_edr, cookie_siem, access_token_siem, cookie, access_token, siem_rule, edr_rule
    if rule["product"].lower() == "vcs_ajiant":
        if cookie_edr == None:
            try:
                edr_connection.login.__defaults__ = ('','',config['vcs_ajiant']['server'])
                cookie_edr, access_token_edr = edr_connection.login(config["vcs_ajiant"]["username"], config["vcs_ajiant"]["password"])
                if access_token_edr == None:
                    raise Exception("Access token none")
                print(Fore.GREEN+f"[+] Logon success on VCS_Ajiant"+Style.RESET_ALL)
            except:
                print(Fore.RED+f"[-] Logon failed on VCS_Ajiant",Style.RESET_ALL, file=sys.stderr)
        cookie, access_token = cookie_edr, access_token_edr
        if 'server' in config['vcs_ajiant']:
            server_address = config['vcs_ajiant']['server']
            edr_rule.update_rule.__defaults__ = ('','',server_address)
            edr_rule.search_rule.__defaults__ = (str,str,server_address)
            edr_rule.create_rule.__defaults__ = ('','',server_address)
            edr_rule.gen_content.__defaults__ = (None, None, server_address)
            edr_rule.verify_syntax_rule.__defaults__ = ('','','',server_address)
            server = edr_rule

    if rule["product"].lower() == "vcs_cym":
        if cookie_siem == None:
            try:
                siem_connection.login.__defaults__ = ('','',config['vcs_cym']['server'])
                cookie_siem, access_token_siem = siem_connection.login(config["vcs_cym"]["username"], config["vcs_cym"]["password"])
                if access_token_siem == None:
                    raise Exception("Access token none")
                print(Fore.GREEN+f"[+] Logon success on VCS_CyM"+Style.RESET_ALL)
            except:
                print(Fore.RED+f"[-] Logon failed on VCS_CyM",Style.RESET_ALL, file=sys.stderr)
        cookie, access_token = cookie_siem, access_token_siem
        if 'server' in config['vcs_cym']:
            server_address = config['vcs_cym']['server']
            siem_rule.update_rule.__defaults__ = ('','',server_address)
            siem_rule.search_rule.__defaults__ = (str,str,server_address)
            siem_rule.create_rule.__defaults__ = ('','',server_address)
            siem_rule.gen_content.__defaults__ = (None, None, server_address)
            siem_rule.verify_syntax_rule.__defaults__ = ('','','',server_address)
            server = siem_rule

def main():
    global args, server, config_file,  cookie, access_token, siem_rule, edr_rule

    args = get_args()
    if args.config != None:
        config_file = args.config
    config = json.load(open(config_file,"r"))

    if args.input != None:
        try:
            # if input is dir 
            list_dir = os.listdir(args.input.strip())
            list_dir = [os.path.join(args.input.strip(), file) for file in list_dir]
            for filename in list_dir:
                if '.yml' in filename or '.yaml' in filename:
                    args.input = filename
                    try:
                        rule = yaml.safe_load(open(filename, "r", encoding="utf-8"))
                    except Exception as e:
                        print (filename, e, file=sys.stderr)
                    config_module(rule, config)
                    try:
                        work_with_rule(rule)
                    except ValueError as ve:
                        # create rule
                        add_missing_field(rule)
                        res = create_rule(rule=rule, server=server, cookie=cookie, access_token=access_token, safe_null=args.safe)
                        update_rule(rule=rule, server=server, cookie=cookie, access_token=access_token, safe_null=args.safe)
                        handle_result(res, rule)
                    time.sleep(2)
        except Exception as ex:
            # if ex == 'Rule not exist':
            #     print ('aabb')
            # print ('hehe')
            rule = yaml.safe_load(open(args.input.strip(), "r", encoding="utf-8"))
            config_module(rule, config)
            try:
                # print(123)
                work_with_rule(rule)
            except Exception as ex:
                add_missing_field(rule)
                res = create_rule(rule=rule, server=server, cookie=cookie, access_token=access_token, safe_null=args.safe)
                update_rule(rule=rule, server=server, cookie=cookie, access_token=access_token, safe_null=args.safe)
                handle_result(res, rule)

main()

# print(json.dumps(create_rule(rule)))
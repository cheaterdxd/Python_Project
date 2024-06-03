import openpyxl
import sys, os
import argparse

# get arg EDR or SIEM
parser = argparse.ArgumentParser()

parser.add_argument("--edr", action="store", help="EDR_xlsx_file_name.xlsx")
parser.add_argument("--siem", action="store", help="SIEM_xlsx_file_name.xlsx")
args = parser.parse_args()

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# import model 
from EDR import edr_connection
from EDR import edr_rule
from Model import RuleContent

cookie, access_token = edr_connection.login("oanhptk", "123qweA@")
# print(edr_rule.search_rule("T1105_Ingress_Tool_Transfer_ver1", cookie).json()["data"][0]["engines_filter"]["content"])


form_txt = """# {}

## Description
{}

## Rule link
[{}](../../rules/{}/{}.zip)

## Rule Detail
{}

## Testcase

## Mitre ATT&CK

{}

## Reference
{}

"""

def str_tag_list(list_tag):
    form = " - [{}](https://attack.mitre.org/{}/)\n"
    str = ""
    for i in list_tag:
        str += form.format(i, i.replace(".", "/"))
    return str

def str_rule_detail(list_detail):
    str = ""
    for i in list_detail:
        str += (i + "\n")
    return str

def check_ref(ref):
    form = " - [{}]({})"
    if (str.__contains__(ref,"http")):
        return (form.format(ref, ref))
    else:
        return ("")
        
def init_md(platform, filename):
    wb = openpyxl.load_workbook(filename)
    ws = wb.active
    # in ra so hang so cot
    print('Hang '+str(ws.max_row)+'.Cot : '+str(ws.max_column))

    class Rule:
        def __init__(self, name, tag, des, detail, ref):
            self.name = name
            self.tag = tag
            self.des = des
            self.detail = detail
            self.ref = ref

    list_rule = []
    for i in range(2, ws.max_row + 1):
        #rule_name.append(str(ws.cell(row=i,column=2).value))
        #tag = str(ws.cell(row=2,column=3).value).replace(' ', '').split(",")
        #Rule(rule_name, tag)
        #rulename = ...
        #rule_json = edr_rule.search_rule(rulename, cookie).json()["data"][0]
        
        rule_name = str(ws.cell(row=i,column=1).value).strip()
        rule_tag = str(ws.cell(row=i,column=3).value).replace(' ', '').split(",")
        rule_json = edr_rule.search_rule(rule_name, cookie)
        if(len(rule_json)==0):
            print(rule_json)
            continue
        
        # Fix wrong rule name
        rule = rule_json
        rulecontent = RuleContent.RuleContent(rule)

        rule_des = rulecontent.get_rule_desc()
        rule_detail = rulecontent.get_rule_blocks()
        rule_ref = str(rulecontent.get_rule_references())

        rule = Rule(rule_name, rule_tag, rule_des, rule_detail, rule_ref)
        list_rule.append(rule)

    for rule in list_rule:
        txt = form_txt.format(
            #name
            rule.name.replace("_", " ").replace("Ver1", ""),
            #des
            rule.des,
            #link
            rule.name,
            platform,
            rule.name,
            #detail = block
            str_rule_detail(rule.detail),
            #tag
            str_tag_list(rule.tag),
            #ref
            check_ref(rule.ref)
        )
        if not os.path.exists(platform):
            os.makedirs(platform)
        with open(".\\"+ platform + "\\" + rule.name+".md", 'w+', encoding="utf-8") as f:
               f.write(txt)

def main():
    if (args.edr != None):
        init_md("EDR", args.edr)
    if (args.siem != None):
        init_md("SIEM", args.siem)

main()
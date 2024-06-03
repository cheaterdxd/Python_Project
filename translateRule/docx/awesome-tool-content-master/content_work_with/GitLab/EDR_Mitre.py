import os
import re
import json

{
    "Process Creation":"1",
    "Command Execution":"1"
}

def get_tech(guide):
    techs = re.findall(r"\[(T?1[0-9]{3}\.[0-9]{2}[1-9]|T?1[0-9]{3})\]", str(guide))
    return techs

def get_data_source(guide):
    search = re.findall("(signature_id == \"?\d{1,}\"?)|(signature_id in \((\"?\d{1,}\"?,?(\s+)?){1,}\))", str(guide))
    data_components = set()
    for dc in search:
        
        for item in dc:  
            data_components.update(re.findall("\d{1,}", item))
    return data_components

mitre_map = {}
path = os.path.abspath("C:\\Users\hieunc\\vcs-mitre-att-ck-version-2\\guides\\EDR\\")
dir_list = os.listdir(path)
for name in dir_list:
    guide = open(path+"\\"+name,"rb").read()
    techs = get_tech(guide)
    data_source = get_data_source(guide)
    if(len(data_source)==0):
        print(name)
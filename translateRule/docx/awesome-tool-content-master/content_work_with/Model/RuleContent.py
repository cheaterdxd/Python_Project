import re

def __assemble(temp=[], parser={"left":[],"operator":[],"right":[]}, counter=int):
    side = ""
    for item in temp:
        side += item
    if side == "not":
        temp.append(" ")
        return temp, parser, counter
    temp = []
    if counter == 0:
        parser["left"].append(side)
    if counter == 1:
        parser["operator"].append(side)
    if counter == 2:
        parser["right"].append(side)
    counter = (counter+1) % 3
    return temp, parser, counter

def side_parser(pattern=str):
    flag = []
    counter = 0
    temp = []

    parser = {
        "left":[],
        "operator":[],
        "right":[]
    }
    
    for char in pattern:
        if len(flag) == 0:
            if char == "\"" or char == "(" or char == "\\":
                flag.append(char)
            if char != " " and char != ",":
                temp.append(char)
            if (char == " " or char == ",") and len(temp) > 0:
                temp, parser, counter = __assemble(temp=temp, parser=parser, counter=counter)
            continue
        if flag[len(flag)-1] == "\"":
            if char == "\"":
                flag.pop()
            temp.append(char)
            continue
        if flag[len(flag)-1] == "(":
            if char == ")":
                flag.pop()
            if char == "\"":
                flag.append(char)
            temp.append(char)
            continue
        if flag[len(flag)-1] == "\\":
            flag.pop()
            temp.append(char)
           
    if(len(temp)>0):
        temp, parser, counter = __assemble(temp=temp, parser=parser, counter=counter)
    return parser
                
class RuleContent:
    
    def __init__(self, rule_json):
        # __rule_name init
        self.__rule_name = rule_json["rule_name"]
        
        # __rule_id init
        self.__rule_id = rule_json["rule_id"]
                
        # __rule_description init
  
        self.__rule_desc = rule_json["description"]
        
        # __rule_blocks init
        
        # __rule_creator init
        self.__rule_creator = rule_json["creator"]
        
        # __rule_modifier init
        self.__rule_modifier = rule_json["modifier"]        
        
        self.__rule_blocks = []
        rule_filters = re.findall(r"Event\(.*\)\n", rule_json["engines_filter"]["content"])
        for rule_filter in rule_filters:
            self.__rule_blocks.append("```java\n"+re.sub(r",\n\$(reference|referer) : \"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)\"", "",rule_filter
                 .replace("Event(","").replace(")\n",""))+"\n```")      
            
        # __rule references init
        self.__rule_references = None
        references = re.findall(r"\$reference : \".*\"", rule_json["engines_filter"]["content"])
        if(len(references)>0):
            self.__rule_references = references[0].replace("$reference : ","").replace("\"", "")
        references = re.findall(r"\$referer : \".*\"", rule_json["engines_filter"]["content"])
        if(self.__rule_references == None and len(references)>0):
            self.__rule_references = references[0].replace("$referer : ","").replace(")", "").replace("\"", "")
        references = re.findall(r"setReference\(.*\)", rule_json["engines_indicator"]["content"])
        if(self.__rule_references == None and len(references)>0):
            self.__rule_references = references[0].replace("setReference(","").replace(")", "").replace("\"", "")
        self.__rule_indicator = rule_json["engines_indicator"]["content"]
        
        # __rule technique init
        self.__rule_technique = []
        for tag in rule_json["tags"]:
            if re.search(r"T[0-9]{4}(\.[0-9]{3})?$", tag):
                self.__rule_technique.append(tag)
                
        self.__rule_filter = rule_json["engines_filter"]["content"]
        
    def get_rule_name(self):
        return self.__rule_name
    
    def get_rule_blocks(self):
        return self.__rule_blocks
    
    def get_rule_desc(self):
        return self.__rule_desc
    
    def get_rule_references(self):
        return self.__rule_references
    
    def get_rule_indicator(self):
        return self.__rule_indicator
    
    def get_rule_filter(self):
        return re.sub("Functions\\.debug.*","",self.__rule_filter)
    
    def get_rule_id(self):
        return self.__rule_id
    
    def get_rule_creator(self):
        return self.__rule_creator
    
    def get_rule_modifier(self):
        return self.__rule_modifier
    
    def get_rule_technique(self):
        return self.__rule_technique
    
    def set_test_case(self, test_case=str()):
        try:
            self.__test_case = test_case.splitlines()
        except:
            self.__test_case = []
    
    def get_test_case(self):
        return self.__test_case
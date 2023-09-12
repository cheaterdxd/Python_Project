'''
site: thanh-tuan-le.atlassian.net 
access_token = ATATT3xFfGF0aCFPLsNIFL9V0Xg7LJJwHra3ojTLOFzi5vKQCXxHzBKo4pFFNlhjZIGEf27ojiBP5Ib35-z8Znygew25wIlTYJHgJEmLy60gHalpFQ6YbFLe-O7GRDPC-7lgqhadvgX_Du4mGFgvLzTHFL-JSR1ck7BaXobp4itQ5dze6jmC6PA=F4E12B65
'''
from atlassian import Jira


oauth_dict = {
    'access_token': api_token,
    'access_token_secret': api_token,
    'consumer_key': api_token,
    'key_cert': api_token}


jira = Jira(url="thanh-tuan-le.atlassian.net/rest/api/2/project",
            oauth = oauth_dict)

for proj in jira.projects():
    print(proj.key)

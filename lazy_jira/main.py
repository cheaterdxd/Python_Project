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

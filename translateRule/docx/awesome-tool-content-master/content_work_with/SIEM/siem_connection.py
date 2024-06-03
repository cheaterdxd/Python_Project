#!/usr/bin/env python3
import requests
import warnings

warnings.filterwarnings('ignore')

def login(username="", password="", server = "https://siem.staging.vcs.vn"):
    session = requests.Session()
    login_session = session.post(
        server+"/oauth/login",
        verify = False, 
        json = {"username":username,"password":password}, 
        )
    cookie = login_session.history[0].headers["Set-Cookie"]
    login_session = session.get(
        server+"/oauth/authorize?scope=login&client_id=cym_portal&audience=cym_api&response_type=code&redirect_uri=https%3A%2F%2Fsiem.staging.vcs.vn&include_granted_scope=false",
        verify = False,
        headers = {"Cookie":cookie}
    )
    referer = login_session.history[0].headers["Location"]
    code = referer.replace("https://siem.staging.vcs.vn?code=", "")    
    login_session = session.post(
        server+"/oauth/token",
        verify = False,
        headers = {"Cookie":cookie, "Referer":referer},
        data = {"code":code, "client_id":"cym_portal", "grant_type":"authorization_code", "redirect_uri":"https%3A%2F%2Fsiem.staging.vcs.vn", "audience":"gatekeeper"}
    )
    access_token = login_session.json()["access_token"]
    # access_token = None
    return cookie, access_token


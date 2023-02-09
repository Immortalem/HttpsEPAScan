import functools
import requests
from requests_ntlm import HttpNtlmAuth
import argparse


import urllib3
urllib3.disable_warnings()

import spnego.channel_bindings
def wrap_hook_GssChannelBindingsArg(oldfunction, newfunction):
    def run(*args, **kwargs):
        return newfunction(oldfunction, *args, **kwargs)
    return run

OVERRIDE=None

def hook_GssChannelBindingsArg(oldfunc, application_data):
    if OVERRIDE == True:
        application_data = b'tls-server-end-point: A'
    return oldfunc(application_data=application_data)

spnego.channel_bindings.GssChannelBindings = wrap_hook_GssChannelBindingsArg(
        spnego.channel_bindings.GssChannelBindings, hook_GssChannelBindingsArg)



def run_https_noEPA(inputUser, inputPassword, target):
    global OVERRIDE
    OVERRIDE = False
    resp = requests.get(target, verify=False, auth=HttpNtlmAuth(inputUser, inputPassword, send_cbt=False))
    if resp.status_code == 200:
        return False
    elif resp.status_code == 401:
        return True
    else:
        raise Exception("Unexpected HTTP response code")

def run_https_withEPAError(inputUser, inputPassword, target):
    global OVERRIDE
    OVERRIDE=True
    resp = requests.get(target, verify=False, auth=HttpNtlmAuth(inputUser, inputPassword, send_cbt=True))
    if resp.status_code == 200:
        return False
    elif resp.status_code == 401:
        return True
    else:
        raise Exception("Unexspected HTTP response code")
    
def run_https_noAuth(target):
    global OVERRIDE
    OVERRIDE = False
    resp = requests.get(target, verify=False)
    if resp.status_code == 401:
        return True
    else:
        raise Exception("Target URL doesn't require authentication")

def run_https_withEPA(inputUser, inputPassword, target):
    global OVERRIDE
    OVERRIDE=False
    resp = requests.get(target, verify=False, auth=HttpNtlmAuth(inputUser, inputPassword, send_cbt=True))
    if resp.status_code == 200:
        return True
    else:
        raise Exception("Invalid Credentials")
    pass



def main():
    parser = argparse.ArgumentParser(
            add_help=True, description="Check a specified target URL for its EPA configuration.")
    parser.add_argument('-t', required=True, action='store', metavar="[Target]", help='Target URL. E.g., https://server.local/certsrv')
    parser.add_argument('-u', required=True, action='store', metavar="[Username]", help='Username WITHOUT the domain part')
    parser.add_argument('-d', required=True, action='store', metavar="[Domain]", help='Domain Name, e.g., corp.local')
    parser.add_argument('-p', required=True, action='store', metavar="[Password]", help='Password')


    options = parser.parse_args()

    inputUser = options.d + "\\" + options.u
    inputPassword = options.p
    target = options.t
    
    httpsRequiresAuth = run_https_noAuth(target)
    hasValidCredentials = run_https_withEPA(inputUser, inputPassword, target)

    if (httpsRequiresAuth and hasValidCredentials):
        # True if EPA is set to Always
        httpsEPAAlwaysCheck = run_https_noEPA(inputUser, inputPassword, target)
        # True if EPA set to WhenSupported
        httpsEPAWhenSupportedCheck = run_https_withEPAError(inputUser, inputPassword, target)

        if httpsEPAAlwaysCheck == False and httpsEPAWhenSupportedCheck == True:
            print("[-] (HTTPS) channel binding is set to \"when supported\" - this")
            print("            may prevent an NTLM relay depending on the client's")
            print("            support for channel binding.")
        elif httpsEPAAlwaysCheck == False and httpsEPAWhenSupportedCheck == False:
            print("[+] (HTTPS) channel binding is set to \"Never\". PARTY TIME!")
        elif httpsEPAAlwaysCheck == True:
            print("[-] (HTTPS) channel binding is set to \"requried\", sadge")
        else:
            print("\nSomethings wrong. We fked up")
            exit()

    
if __name__ == "__main__":
    main()

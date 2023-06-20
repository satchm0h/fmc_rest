import os
import time
import sys
import json
import logging
import argparse
import coloredlogs
from fmc_rest import cdFMCRest

CDO_TOKEN_FILE = '~/.cdo_token'
CDO_TOKEN_EV = 'CDO_TOKEN'
CDO_DEFAULT_REGION = 'us'

def _format(json_obj):
    return json.dumps(json_obj, sort_keys=True, indent=2, separators=(',', ': '))


def init():
    '''
        init()
        Handle command line args, setup log, etc..
    '''

    global DEFAULTS

    # Configure logging
    coloredlogs.install(level='DEBUG',
                        fmt='%(asctime)s %(levelname)s %(message)s')

    # Supress requests log
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

    # Handle command line args
    parser = argparse.ArgumentParser(description='Read/Dump cdFMC AC Policies')
    parser.add_argument('-D, --debug', dest='debug',
                        help='Full debug output',
                        action='store_true')
    parser.add_argument('-t --token', dest='token',
                        help=f'CDO API token (Please use {CDO_TOKEN_FILE} file or {CDO_TOKEN_EV} env var instead)',
                        default=None)
    parser.add_argument('-r --region', dest='region',
                        help=f'CDO Region. Must be one of: "us", "eu", or "apj" Default: {CDO_DEFAULT_REGION}',
                        default=CDO_DEFAULT_REGION)
    parser.add_argument('-b, --bulk', dest='bulk', action='store_true',
                        help='Process all the Access Policies on the FMC at once',
                        default=None)
    options = parser.parse_args()

    # Enable debug
    if not options.debug:
        coloredlogs.decrease_verbosity()

    # Load from env or file if not provided on the command line
    if options.token is None:
        if 'CDO_TOKEN' in os.environ:
            logging.debug('Loading token from environment')
            options.token = os.environ.get({CDO_TOKEN_EV})
        elif os.path.isfile(os.path.expanduser(CDO_TOKEN_FILE)):
            logging.debug('Loading token from file')
            with open(os.path.expanduser(CDO_TOKEN_FILE), 'r') as fh:
                options.token = fh.read().strip()
        else:
            logging.fatal("Unable to find CDO token file")
            exit(5)
        
    return options


def main(options):
    ''' Let's make do stuff
    '''

    # Connect to the FMC RestAPI
    start = time.time()
    logging.info(f'Connecting to cdFMC')
    fmc = cdFMCRest(options.token, options.region)
    logging.debug(f"Connected.")
    elapsed = time.time() - start
    logging.info('Time elapsed for session establishment: %1.1f secs', elapsed)

    # Grab the list of AC policies on the FMC
    ac_policies = getACPList(fmc)
    rval = {}

    # If the bulk flag is not passed, promt the user to select an individual policy
    if options.bulk == None :
        print("\nSelect an Access Policy:")
        index = 0
        for policy in ac_policies:
            if 'name' in policy:
                print (f"  {index} - {policy['name']}")
            index = index + 1
        print("Select one :")
        index = int(input())
        logging.debug(f"Policy_id: {ac_policies[index]['id']}")
        rval[ac_policies[index]['id']] = getACPolicy(fmc, ac_policies[index]['id'])
    
    # If the bulk flag is passed, dump all the policies
    else:
        for policy in ac_policies:
            rval[policy['id']] = getACPolicy(fmc, policy['id'])
    print(_format(rval))


def getACPolicy(fmc, id):
    ret = {}
    ret['global'] = fmc.get(f"/policy/accesspolicies/{id}")
    ret['rules'] = list()
    reponse = fmc.get(f"/policy/accesspolicies/{id}/accessrules?expanded=true")
    if 'items' in reponse:
        ret['rules'] = reponse['items']
    # logging.debug(_format(ret))
    return ret

def getACPList(fmc):
    reponse = fmc.get("/policy/accesspolicies")
    if 'items' in reponse:
        return reponse['items']
    return []

if __name__ == '__main__':
    main(init())

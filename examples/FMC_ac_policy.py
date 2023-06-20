import os
import time
import sys
import json
import logging
import argparse
import coloredlogs
from fmc_rest import FMCRest


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
    parser = argparse.ArgumentParser(description='IRead/Dump FMC AC Policies')
    parser.add_argument('-D, --debug', dest='debug',
                        help='Full debug output',
                        action='store_true')
    parser.add_argument('-s, --server', dest='hostname',
                        help='FMC Hostname or IP (in the format hostname:port)',
                        default=None)
    parser.add_argument('-u, --user', dest='username',
                        help='FMC API username (Please use FMC_USERNAME env var instead)',
                        default=None)
    parser.add_argument('-p, --password', dest='password',
                        help='FMC API password (Please use FMC_PASSWORD env var instead)',
                        default=None)
    parser.add_argument('-b, --bulk', dest='bulk', action='store_true',
                        help='Process all the Access Policies on the FMC at once')
    options = parser.parse_args()

    # Enable debug
    if not options.debug:
        coloredlogs.decrease_verbosity()

    # Load from env if not provided on the command line
    if options.hostname is None:
        options.hostname = os.environ.get('FMC_HOSTNAME')
        logging.debug('Loading hostname from environment')
    if options.username is None:
        options.username = os.environ.get('FMC_USERNAME')
        logging.debug('Loading username from environment')
    if options.password is None:
        options.password = os.environ.get('FMC_PASSWORD')
        logging.debug('Loading password from environment')

    if options.hostname is None:
        logging.fatal('No fmc hostname provided')
        sys.exit(3)
    if options.username is None:
        logging.fatal('No username provided')
        sys.exit(5)
    if options.password is None:
        logging.fatal('No password provided')
        sys.exit(7)

    # Strip off 'https://' from the hostname if it is provided
    # ...took me way too long to realize this was my problem :)
    if str(options.hostname).startswith('https://'):
        options.hostname = str(options.hostname).replace('https://', '', 1)

    return options


def main(options):
    ''' Let's make do stuff
    '''

    # Connect to the FMC RestAPI
    start = time.time()
    logging.info(f'Connecting to FMC... ({options.hostname})')
    fmc = FMCRest(options.hostname, options.username, options.password)
    logging.debug(f"Connected. Session ({fmc.session.headers['X-auth-access-token']})")
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
    ret['rules'] = fmc.get(f"/policy/accesspolicies/{id}/accessrules?expanded=true")['items']
    logging.debug(_format(ret))
    return ret

def getACPList(fmc):
    resp = fmc.get("/policy/accesspolicies")
    logging.debug(_format(resp))
    return resp['items']

if __name__ == '__main__':
    main(init())

"""
Utility module for connecting to and interacting with
FMC REST API
"""

import json
import requests
import logging
from time import time as now
from time import sleep

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Explicitly export symbols
__all__ = ['FMCRest', 'cdFMCRest' 'FMCException']

class FMCException(Exception):
    """ Utility exception for Module specific errors
    """

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class FMCRest(object):
    """FMC Reset API utility class
    """

    AUTH_PATH = "fmc_platform/v1/auth/generatetoken"
    REFRESH_PATH = "fmc_platform/v1/auth/refreshtoken"
    HEADERS = {'Content-Type': 'application/json'}

    def __init__(self, server, username, password, ssl_verify=False, url='/api/', domain='Global'):
        """ Constructor
        :param server: Hostname or IP of FMC
        :param username: Username of user to authenticate to the FMC
        :param password: Password of use to authenticate to the FMC
        :param ssl_verify: Enable SSL verification. Note this does not work for self-signed certs.
        :param url: Base API url
        :param domain: Domain name
        """
        self.server = server
        self.base_url = 'https://' + server + url
        self.session = requests.Session()
        self.session.verify = ssl_verify
        self.session.headers = FMCRest.HEADERS
        self.domain = None

        # FMC has a 30 minute exriry on auth tokens.
        self.token_expires = now() + 30 * 60

        logging.debug(f"Server: {self.server}")
        logging.debug(f"Base URL: {self.base_url}")
        logging.debug(f"SSL Verify: {self.session.verify}")

        self._auth(username, password, domain)

    # Public API
    def get(self, url):
        url = "fmc_config/v1/domain/" + self.domain['uuid'] + url
        return self._request("GET", url)

    def post(self, url, payload):
        url = "fmc_config/v1/domain/" + self.domain['uuid'] + url
        return self._request("POST", url, payload)

    def put(self, url, payload):
        url = "fmc_config/v1/domain/" + self.domain['uuid'] + url
        return self._request("PUT", url, payload)

    def delete(self, url):
        url = "fmc_config/v1/domain/" + self.domain['uuid'] + url
        return self._request("DELETE", url)

    # Private Methods

    def _auth(self, username=None, password=None, domain='Global'):
        """ Private function to either auethenticate w/ username & password
            or refresh w/ the refresh token. Refresh if username is not provided
        """
        new_refresh = now() + 30 * 60
        try:
            if username != None:
                logging.debug("Login Authentication")
                resp = self.session.post(self.base_url + FMCRest.AUTH_PATH,
                                         auth=requests.auth.HTTPBasicAuth(username, password))
                if not 200 <= resp.status_code < 300:
                    logging.error('Authentication Failed')
                    resp.raise_for_status()

                # Grab the provided domain uuid out of the header.
                self.domain_list = json.loads(resp.headers.get('DOMAINS', default='[]'))
                logging.debug("Domain: " + format(self.domain_list))
                for dom_obj in self.domain_list:
                    if dom_obj['name'] == domain:
                        #logging.debug("Domain: " + dom_obj['name'] + " = " + domain)
                        self.domain = dom_obj

                if self.domain is None:
                    error = 'No domain defined'
                    logging.error(error)
                    raise FMCException(error)

            # Refresh if we need to
            elif self.token_expires < now():
                logging.debug("Refresh Authentication")
                resp = self.session.post(self.base_url + FMCRest.REFRESH_PATH)

            # Don't need to refresh, no-op.
            else:
                return

            # Extract tokens from the response
            auth_token = resp.headers.get('X-auth-access-token', default=None)
            refresh_token = resp.headers.get('X-auth-refresh-token', default=None)

            if auth_token is None:
                error = 'Authentication token not found in header: X-auth-access-token'
                logging.error(error)
                raise FMCException(error)

            if refresh_token is None:
                error = 'Refresh token not found in header: X-auth-refresh-token'
                logging.error(error)
                raise FMCException(error)

            # Store tokens in the session headers.
            self.session.headers['X-auth-access-token'] = auth_token
            self.session.headers['X-auth-refresh-token'] = refresh_token
            logging.debug(f"Headers: {self.session.headers}")
        except Exception as err:
            logging.error("Error establishing session --> " + str(err))
            raise err

        # Only update the refresh time if the above was successful
        self.token_expires = new_refresh

    def _request(self, verb, url, req_data=None):
        """ Private API request driver
        """

        try:

            while True:
                # See if we need to refresh
                self._auth()

                # Do the needful based on the HTTP verb
                if verb.lower() == "get":
                    resp = self.session.get(self.base_url + url)
                elif verb.lower() == "delete":
                    resp = self.session.delete(self.base_url + url)
                elif verb.lower() == "put":
                    resp = self.session.put(self.base_url + url, data=json.dumps(req_data))
                elif verb.lower() == "post":
                    resp = self.session.post(self.base_url + url, data=json.dumps(req_data))
                else:
                    raise FMCException(f"Invalid verb '{verb}' passed to request")

                status_code = resp.status_code
                payload = resp.text

                # Happy case
                if status_code < 300 and status_code >= 200:
                    return json.loads(payload)
                # Rate limit handling
                elif status_code == 429:
                    logging.warn(f"Rate Limit hit : 60 sec backoff triggered")
                    sleep(60)
                # HTTP Error encountered.
                else:
                    resp.raise_for_status()

        # Log and pass through HTTP exceptions to be handled outside the library.
        except requests.exceptions.HTTPError as err:
            logging.error(f"Error in connection --> {str(err)}")
            raise err

class cdFMCRest(FMCRest):
    """cdFMC Reset API utility class
    """

    CDFMC_HOST_ENDPOINT= 'aegis/rest/v1/services/targets/devices?q=deviceType:FMCE'
    CDFMC_DOMAIN_ENDPOINT = 'fmc_platform/v1/info/domain'
    HEADERS = { 
        "Accept": "application/json",
        "Content-Type": "application/json;charset=utf-8"
    }

    def __init__(self, token, region, ssl_verify=True, url='/api/', domain='Global'):
        """ Constructor
        :param server: Hostname or IP of FMC
        :param api_key: CDO API key from User Management UI
        :param ssl_verify: Enable SSL verification. Note this does not work for self-signed certs.
        :param url: Base API url
        :param domain: Domain name
        """

        self.session = requests.Session()
        self.session.verify = ssl_verify
        self.session.headers = cdFMCRest.HEADERS
        self.session.headers['Authorization'] = f'Bearer {token}'
        self.cdo_base_url = 'https://' + self._get_region_endpoint(region) + '/'
        self.base_url = 'https://' + self._determine_cdFMC_endpoint() + url
        self.domain = self._determine_cdFMC_domain()

        logging.debug(f"CDO Base URL: {self.cdo_base_url}")
        logging.debug(f"cdFMC Base URL: {self.base_url}")
        logging.debug(f"SSL Verify: {self.session.verify}")

    def _get_region_endpoint(self, cdo_region: str) -> str:
        """Set the api endpoint based on the region of the CDO deployment"""
        if cdo_region.lower() == "us":
            return "www.defenseorchestrator.com"
        elif cdo_region.lower() == "eu":
            return "www.defenseorchestrator.eu"
        elif cdo_region.lower() == "apj":
            return "apj.cdo.cisco.com"
        else:
            error = f'Invalid region provided {cdo_region}'
            logging.error(error)
            raise FMCException(error)
    
    # Need to do some inital setup before we can use the common _request private method
    def _raw_get(self, url):
        """ Raw get boilerplate
        """
        try:
            resp = self.session.get(url)
            status_code = resp.status_code
            payload = resp.text

            # Happy case
            if status_code < 300 and status_code >= 200:
                return json.loads(payload)

            # HTTP Error encountered.
            else:
                logging.error(f"Error occurred in raw get --> {payload}")
                resp.raise_for_status()

        # Log and pass through HTTP exceptions to be handled outside the library.
        except requests.exceptions.HTTPError as err:
            logging.error(f"Error in connection --> {str(err)}")
            raise err

    def _determine_cdFMC_endpoint(self) -> str:
        payload = self._raw_get(self.cdo_base_url + cdFMCRest.CDFMC_HOST_ENDPOINT)
        if 'host' in payload[0]:
            logging.debug(f"cdFMC endpoint found: {payload[0]['host']}")
            return payload[0]['host']
        else:
            raise FMCException(f"Unable to locate cdFMC in tenant --> {payload}")

    def _determine_cdFMC_domain(self) -> str:
        rval = dict()
        payload = self._raw_get(self.base_url + cdFMCRest.CDFMC_DOMAIN_ENDPOINT)
        if 'items' in payload:
            # Note that cdFMC only ever has a single 'Global' domain
            if 'uuid' in payload['items'][0]:
                logging.debug(f"Found domain UUID: {payload['items'][0]['uuid']}")
                rval['name'] = payload['items'][0]['name']
                rval['uuid'] = payload['items'][0]['uuid']
                return rval
        
        raise FMCException("Unable to determine uuid for Global Domain")

    # For cdFMC this is a noop since we do not have to deal with token timeouts
    def _auth(self, username=None, password=None, domain='Global'):
        return
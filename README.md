# Bare bones FMC (or cdFMC) REST API driver

Simple Python 3 REST driver for Cisco Secure Firewall Management Center (FMC) and Cloud-delivered Firewall Management Center (cdFMC) within Cisco Defense Orchestrator

## Installation

- Check out this repo: `git clone git@github.com:satchm0h/fmc_rest.git`
- `cd` into the `fmc_rest` directory
- Run `pip3 install .`
  - or `pip3 install -e .` if you want to do module development in place in your clone

## Usage

For FMC

```python
from fmc_rest import FMCRest

fmc = FMCRest(hostname, username, password)
policies = fmc.get("/policy/accesspolicies")

```

For cdFMC

```python
from fmc_rest import cdFMCRest

fmc = cdFMCRest(options.token, options.region)
policies = fmc.get("/policy/accesspolicies")

```

Both the `FMC` and `cdFMC` objects expose the following methods

- `get(url)`
- `post(url, payload)`
- `put(url, payload)`
- `delete(url)`

`url` is the unique endpoint within the `fmc_config/v1/domain/{DOMAIN_UUID}`. Note that this library is currently limited to the config endpoints.

`payload` is a python data structure that will be converted to JSON by the driver

## Examples

Example scripts can be found in the top-level `examples` directory of this repo

### FMC_ac_policy
This is an example script that will list all the available access policies, allow the user to select one, then dump it and it's rules to stdout. Note that it does not handle pagination or object resolution.

Usage:

    % python3 examples/FMC_ac_policy.py -h
    usage: FMC_ac_policy.py [-h] [-D, --debug] [-s, --server HOSTNAME] [-u, --user USERNAME] [-p, --password PASSWORD] [-b, --bulk]

    IRead/Dump FMC AC Policies

    options:
    -h, --help            show this help message and exit
    -D, --debug           Full debug output
    -s, --server HOSTNAME
                            FMC Hostname or IP (in the format hostname:port)
    -u, --user USERNAME   FMC API username (Please use FMC_USERNAME env var instead)
    -p, --password PASSWORD
                            FMC API password (Please use FMC_PASSWORD env var instead)
    -b, --bulk            Process all the Access Policies on the FMC at once

### cdFMC_ac_policy
This is the same script as the `FMC_ac_policy.py` mentioned above, but leverages the `cdFMC` driver instead of the `FMC` driver.

Usage: 

    %  python3 examples/cdFMC_ac_policy.py -h
    usage: cdFMC_ac_policy.py [-h] [-D, --debug] [-t --token TOKEN] [-r --region REGION] [-b, --bulk]

    Read cdFMC AC Policies

    options:
    -h, --help          show this help message and exit
    -D, --debug         Full debug output
    -t --token TOKEN    CDO API token (Please use ~/.cdo_token file or CDO_TOKEN env var instead)
    -r --region REGION  CDO Region. Must be one of: "us", "eu", or "apj" Default: us
    -b, --bulk          Process all the Access Policies on the FMC at once

## Running Tests

Install test requirements and run the suite with coverage enabled:

    pip install pytest coverage

    python -m coverage run -m pytest
    python -m coverage xml
    python -m coverage report

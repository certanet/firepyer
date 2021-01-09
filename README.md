![Firepyer](docs/_static/firepyer-logo.png "Firepyer logo")

Firepyer provides a way of interacting with Cisco Firepower devices via their REST APIs in Python. Currently FTD devices using FDM (not FMC) are supported.
The intended usage is to replace some of the tedious clicking tasks from the GUI, perform actions on a large number of devices or execute bulk imports of objects, rules etc.

The following versions have been used in development (others should work but YMMV):
- Python 3.9 (3.6+ should be fine)
- FTD 6.6.1-91

Please see the brief instructions below on installing and using Firepyer and visit [the documentation](https://certanet.github.io/firepyer/) for a more comprehensive guide and examples.


## Installation

The latest release is available to download from PyPI, simply using `pip install firepyer`.

Alternatively, as this project is still in early development, the best place to get the most recent features is directly from the [source GitHub repo](https://github.com/certanet/firepyer).

## Usage

All functionailty for interacting with an FTD device is contained within the Fdm class and it’s methods. Authentication is taken care of transparently when calling a method, so this doesn’t need to be done explicilty.

Import the Fdm class and instantiate an object, passing in your FTD hostname/IP, username and password:

    >>> from firepyer import Fdm
    >>> fdm = Fdm(host='192.168.45.45', username='admin', password='Admin123')

Then call any of the available methods to run against your FTD:

    >>> fdm.get_hostname()
         'firepyer2120'

    >>> fdm.get_net_objects('any-ipv4')
         {'description': None,
          'dnsResolution': None,
          'id': '00f7b297-4d44-11eb-9e04-13721b05d633',
          'isSystemDefined': True,
          'links': {'self': 'https://192.168.45.45/api/fdm/latest/object/networks/00f7b297-4d44-11eb-9e04-13721b05d633'},
          'name': 'any-ipv4',
          'subType': 'NETWORK',
          'type': 'networkobject',
          'value': '0.0.0.0/0',
          'version': 'kxd2dzxm2gtwn'}

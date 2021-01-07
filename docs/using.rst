Using Firepyer
==================

Interacting
-----------

All functionailty for interacting with an FTD device is contained within the Fdm class and it's methods.
Authentication is taken care of transparently when calling a method, so this doesn't need to be done explicitly.

.. module:: firepyer

.. autoclass:: Fdm

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

Error Handling
--------------
Some common errors that may be encountered when using Fdm methods:

.. module:: firepyer.exceptions

.. autoexception:: AuthError
.. autoexception:: ResourceNotFound
.. autoexception:: UnreachableError
# FirePyer

FirePyer provides a way of interacting with Cisco FTD devices via the FDM REST API in Python. The intended usage is to replace some of the tedious clicking tasks from the FDM GUI or before bulk imports of objects, rules etc.

The following versions have been tested (others should work but YMMV):
- Python 3.9 (3.6+ should be fine)
- FTD 6.6.1-91

## Usage

TBC

`from firepyer import Fdm`

`fdm = Fdm('192.168.45.1', 'admin', 'Admin123')`
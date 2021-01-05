![Firepyer](docs/_static/firepyer-logo.png "Firepyer logo")

Firepyer provides a way of interacting with Cisco Firepower devices via their REST APIs in Python. Currently FTD devices using FDM (not FMC) are supported. The intended usage is to replace some of the tedious clicking tasks from the GUI or perform bulk imports of objects, rules etc.

The following versions have been used in development (others should work but YMMV):
- Python 3.9 (3.6+ should be fine)
- FTD 6.6.1-91

## Usage

TBC

`from firepyer import Fdm`

`fdm = Fdm('192.168.45.1', 'admin', 'Admin123')`
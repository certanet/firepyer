import json
from time import sleep
from datetime import datetime
import logging

import requests

from firepyer.exceptions import AuthError, ResourceNotFound, UnreachableError


__version__ = '0.0.2'


class Fdm:
    def __init__(self, host, username, password):
        """Provides a connection point to an FTD device

        :param host: The IP or hostname of the FTD device
        :type host: str
        :param username: Username to login to FDM
        :type username: str
        :param password: Password to login to FDM
        :type password: str
        """
        self.ftd_host = host
        self.username = username
        self.password = password
        self.access_token = None
        self.access_token_expiry_time = None
        requests.packages.urllib3.disable_warnings()

    def api_call(self, uri, method, data=None, get_auth=True, files=None):
        # Check for http allows passing in full URL e.g. from pagination next page link
        if 'http' not in uri:
            uri = f"https://{self.ftd_host}/api/fdm/latest/{uri}"

        headers = {"Accept": "application/json", 'User-Agent': f'firepyer/{__version__}'}
        if get_auth:
            headers['Authorization'] = f'Bearer {self._check_get_access_token()}'
        if not files:
            # When sending files, requests will auto populate CT as multipart/form-data
            headers['Content-Type'] = "application/json"

        try:
            response = requests.request(method, uri,
                                        data=data,
                                        headers=headers,
                                        verify=False,
                                        files=files)
            return response
        except requests.exceptions.ConnectionError:
            raise UnreachableError(f'Unable to contact the FTD device at {self.ftd_host}')

    def post_api(self, uri, data=None, get_auth=True, files=None):
        return self.api_call(uri, 'POST', data=data, get_auth=get_auth, files=files)

    def put_api(self, uri, data=None):
        return self.api_call(uri, 'PUT', data=data)

    def get_api(self, uri, data=None):
        return self.api_call(uri, 'GET', data=data)

    def get_api_items(self, uri, data=None):
        try:
            return self.get_api(uri, data).json()['items']
        except KeyError:
            # No items field
            return None

    def get_api_single_item(self, uri, data=None):
        if self.get_api_items(uri) is not None:
            try:
                return self.get_api_items(uri, data)[0]
            except (IndexError, TypeError):
                # Items list is empty or not items list
                return None
        else:
            return None

    def check_api_status(self):
        api_alive = False

        while not api_alive:
            try:
                api_status = self.api_call('#/login', 'GET', get_auth=False)
            except UnreachableError:
                api_status = None

            if api_status is not None:
                if api_status.status_code == 401:
                    logging.info('API Alive!')
                    api_alive = True
                elif api_status.status_code == 503:
                    logging.warn('FTD alive, API service unavailable...')
            else:
                logging.warn('Unable to reach FTD')
            sleep(10)

    def _get_access_token(self) -> str:
        """
        Login to FTD device and obtain an access token. The access token is required so that the user can
        connect to the device to send REST API requests.
        :return: OAUTH access token
        """
        access_token = None
        access_token_expiry_time = None

        payload = f'{{"grant_type": "password", "username": "{self.username}", "password": "{self.password}"}}'
        resp = self.post_api('fdm/token', payload, get_auth=False)
        if resp.status_code == 400:
            raise AuthError('Failed to authenticate against FTD - check username/password')
        else:
            access_token = resp.json().get('access_token')

            epoch_now = datetime.timestamp(datetime.now())
            access_token_valid_secs = 1740  # FDM access token lasts 30mins, this is 29mins
            access_token_expiry_time = epoch_now + access_token_valid_secs

            logging.info(f"Login successful, access_token obtained, expires at: {datetime.fromtimestamp(access_token_expiry_time)}")

        return access_token, access_token_expiry_time

    def _check_get_access_token(self) -> str:
        """
        Checks if a valid (29mins hasn't passed since obtaining) access token exists, if not gets one
        :return: str Either a new or the existing valid access token
        """

        get_token = False
        epoch_now = datetime.timestamp(datetime.now())

        if self.access_token is None:
            # No token has been generated yet
            get_token = True
        elif epoch_now > self.access_token_expiry_time:
            # Token expired
            get_token = True

        if get_token:
            self.access_token, self.access_token_expiry_time = self._get_access_token()
        return self.access_token

    def _get_object_subset(self, obj: dict) -> dict:
        """
        Gets the significant fields from a full object
        :param obj: dict An object retrieved from any endpoint
        :return: dict A subet of the uniquely identifiable fields from the object
        """
        object_subset = {}
        object_subset['id'] = obj['id']
        object_subset['type'] = obj['type']
        object_subset['version'] = obj['version']
        object_subset['name'] = obj['name']
        return object_subset

    def get_class_by_name(self, get_class: dict, obj_name: str, name_field_label: str = 'name') -> dict:
        """
        Get the dict for the Class with the given name
        :param get_class: dict The 'items' in a GET reponse from an FDM Model query
        :param obj_name: str The name of the object to find
        :param name_field_label: str The field to use as the 'name' to match on, defaults to name
        :return: dict if an object with the name is found, None if not
        """

        if get_class is not None:
            for obj in get_class:
                if obj[name_field_label] == obj_name:
                    return obj
        return None

    def get_paged_items(self, uri: str) -> list:
        response = self.get_api(uri).json()
        all_items = response['items']
        next_url = response['paging']['next']

        while next_url:
            response = self.get_api(next_url[0]).json()
            all_items += response['items']
            next_url = response['paging']['next']

        return all_items

    def get_obj_by_filter(self, url, filter):
        first_param = '?'
        if url.endswith('&'):
            first_param = ''
        return self.get_api_single_item(f'{url}{first_param}filter={filter}')

    def get_obj_by_name(self, url, name):
        return self.get_obj_by_filter(url, filter=f'name:{name}')

    def get_net_objects(self, name=''):
        """Gets all NetworkObjects or a single NetworkObject if a name is provided

        :param name: The name of the NetworkObject to find, defaults to ''
        :type name: str, optional
        :return: A list of all NetworkObjects if no name is provided, or a dict of the single NetworkObject with the given name
        :rtype: list|dict
        """
        if name:
            return self.get_obj_by_name('object/networks?limit=0&', name)
        else:
            return self.get_api_items('object/networks?limit=0')

    def get_net_groups(self, name=''):
        """Gets all NetworkGroups or a single NetworkGroup if a name is provided

        :param name: The name of a NetworkGroup to find, defaults to ''
        :type name: str, optional
        :return: A list of all NetworkGroups if no name is provided, or a dict of the single NetworkGroup with the given name
        :rtype: list|dict
        """
        if name:
            return self.get_obj_by_name('object/networkgroups?limit=0&', name)
        else:
            return self.get_api_items('object/networkgroups?limit=0')

    def get_net_obj_or_grp(self, name) -> dict:
        """Get a NetworkObject or NetworkGroup by the given name

        :param name: The name of the object/group to retrieve
        :type name: str
        :return: Single dict describing the object, if a resource with the name is found
        :rtype: dict
        """
        net = None
        name_filter = {'name': name}
        net_finders = [self.get_net_objects,
                       self.get_net_groups]

        for get_net_method in net_finders:
            net = get_net_method(**name_filter)
            if net:
                break
        return net

    def create_object(self, name: str, value: str, type: str = 'HOST', description: str = None):

        host_object = {"name": name,
                       "description": description,
                       "subType": type.upper(),
                       "value": value,
                       "dnsResolution": "IPV4_ONLY",
                       "type": "networkobject"
                       }
        return self.post_api('object/networks', json.dumps(host_object))

    def create_group(self, name: str, group_type: str, objects_for_group: list, description: str = None):
        """
        Creates a group of pre-existing Network or Port objects
        :param name: str Name of the group being created
        :param group_type: str Should be either 'network' or 'port' depending on group class
        :param objects_for_group: [Obj] All API-gathered Objects to be added to the group
        :param description: str Description of the group being created
        """
        object_group = {"name": name,
                        "description": description,
                        "objects": objects_for_group,
                        "type": f"{group_type}objectgroup"
                        }

        return self.post_api(f'object/{group_type}groups', json.dumps(object_group))

    def create_net_group(self, name: str, objects: list, description: str = None):
        """Creates a NetworkGroup object, containing at least 1 existing Network or NetworkGroup object

        :param name: Name of the NetworkGroup to be created
        :type name: str
        :param objects: Names of the Network or NetworkGroup objects to be added to the group
        :type objects: list
        :param description: A description for the NetworkGroup, defaults to None
        :type description: str, optional
        :return: The full requests response object or None if an error occurred
        :rtype: Response|None
        """
        objects_for_group = []
        for obj_name in objects:
            objects_for_group.append(self.get_net_obj_or_grp(obj_name))

        return self.create_group(name, 'network', objects_for_group, description)

    def get_pending_changes(self) -> list:
        """Gets any configuration changes that have not yet been deployed

        :return: List of each change to be applied, empty list if there are none
        :rtype: list
        """
        return self.get_paged_items('operational/pendingchanges')

    def deploy_now(self) -> str:
        """Starts a deployment, regardless of if there are any pending configuration changes

        :return: The ID for the Deployment task
        :rtype: str
        """
        response = self.post_api('operational/deploy').json()
        return response.get('id')

    def get_deployment_status(self, deploy_id: str) -> str:
        """Gets the status of a Deployment task

        :param deploy_id: The ID of the Deployment task to check
        :type deploy_id: str
        :raises ResourceNotFound: If the deployment ID does not exist
        :return: The status of the deployment, one of either ['QUEUED', 'DEPLOYING', DEPLOYED', 'FAILED']
        :rtype: str
        """
        state = None
        response = self.get_api(f'operational/deploy/{deploy_id}')

        if response.status_code == 200:
            state = response.json().get('state')
        elif response.status_code == 404:
            raise ResourceNotFound(f'Resource with ID "{deploy_id}" not does not exist!')

        return state

    def deploy_config(self):
        """Checks if there's any pending config changes and deploys them, waits until deploy finishes to return

        :return: True if deployment was successful, False if deployment failed or not required
        :rtype: bool
        """
        if self.get_pending_changes():
            deployment_id = self.deploy_now()
            state = self.get_deployment_status(deployment_id)
            while state != 'DEPLOYED' and state != 'FAILED':
                sleep(10)
                state = self.get_deployment_status(deployment_id)
            if state == 'DEPLOYED':
                return True
            elif state == 'FAILED':
                return False
        else:
            # Nothing to deploy
            return False

    def get_vrfs(self, name=''):
        """Gets all VRFs or a single VRF if a name is provided

        :param name: The name of a VRF to find, defaults to ''
        :type name: str, optional
        :return: A list of all VRFs if no name is provided, or a dict of the single VRF with the given name
        :rtype: list|dict
        """
        if name:
            return self.get_obj_by_name('devices/default/routing/virtualrouters', name)
        else:
            return self.get_api_items('devices/default/routing/virtualrouters')

    def get_bgp_general_settings(self):
        """Gets the device's general BGP settings if any are set

        :return: The BGPGeneralSettings object or None if none are set
        :rtype: dict
        """
        return self.get_api_single_item('devices/default/routing/bgpgeneralsettings')

    def set_bgp_general_settings(self, asn: str, name='BgpGeneralSettings', description=None, router_id=None):
        """Set the device's general BGP settings

        :param asn: The AS number for the BGP process
        :type asn: str
        :param name: A name for the settings, defaults to 'BgpGeneralSettings'
        :type name: str, optional
        :param description: A description for the settings, defaults to None
        :type description: str, optional
        :param router_id: A router ID for the BGP process, defaults to None
        :type router_id: str, optional
        :return: The full requests response object or None if an error occurred
        :rtype: Response|None
        """
        bgp_settings = {"name": name,
                        "description": description,
                        "asNumber": asn,
                        "routerId": router_id,
                        # "scanTime": 0,
                        # "aggregateTimer": 0,
                        # "bgpNextHopTriggerDelay": 0,
                        # "bgpNextHopTriggerEnable": true,
                        # "maxasLimit": 0,
                        # "logNeighborChanges": true,
                        # "transportPathMtuDiscovery": true,
                        # "fastExternalFallOver": true,
                        # "enforceFirstAs": true,
                        # "asnotationDot": true,
                        "type": "bgpgeneralsettings"
                        }
        return self.post_api('devices/default/routing/bgpgeneralsettings', data=json.dumps(bgp_settings))

    def get_bgp_settings(self, vrf='Global'):
        """Get the BGP settings for a specifc VRF or the default (Global)

        :param vrf: Name of a VRF to get the BGP settings, defaults to 'Global'
        :type vrf: str, optional
        :return: The BGPSettings object or None if none are set
        :rtype: dict
        """
        vrf_id = self.get_vrfs(vrf)['id']
        return self.get_api_single_item(f'/devices/default/routing/virtualrouters/{vrf_id}/bgp')

    def set_bgp_settings(self, asn, name='', description=None, router_id=None, vrf='Global', af=4, auto_summary=False,
                         neighbours=[], networks=[], default_originate=False):
        """Configures BGP settings for the give (or default) VRF

        :param asn: The AS Number of the BGP process, MUST be the same as in the BGPGeneralSettings
        :type asn: str
        :param name: Name for the BGPSettings, MUST be unique across the device, defaults to 'VRFNAME-BGPSettings'
        :type name: str, optional
        :param description: Description for the BGPSettings, defaults to None
        :type description: str, optional
        :param router_id: A router ID for the BGP process, defaults to None
        :type router_id: str, optional
        :param vrf: Name of the VRF to configure BGP in, defaults to 'Global'
        :type vrf: str, optional
        :param af: BGP Address-Family to use, should be either [4, 6], defaults to 4
        :type af: int, optional
        :param auto_summary: Automatically summarise subnet routes to network routes, defaults to False
        :type auto_summary: bool, optional
        :param neighbours: Neighbours to add to the BGP process, each neighbour in the list should be a dict in format
             {"remoteAs": "65001", "activate": True, "ipv4Address": "192.168.1.1"}, defaults to []
        :type neighbours: list, optional
        :param networks: Names of NetworkObjects to add to as networks into the BGP, defaults to []
        :type networks: list, optional
        :param default_originate: Enable or disable default originate for BGP, defaults to False
        :type default_originate: bool, optional
        :return: The full requests response object or None if an error occurred
        :rtype: Response|None
        """
        if not name:
            name = f'{vrf}-BGPSettings'

        af_networks = []
        af_neighbours = []

        if af == 4:
            for network in networks:
                net_obj = self.get_net_objects(network)
                af_net = {"routeMap": {},  # TODO
                          "ipv4Network": net_obj,
                          "type": "afipv4network"
                          }
                af_networks.append(af_net)

            for neighbour in neighbours:
                neighbour['type'] = 'neighboripv4'
                af_neighbours.append(neighbour)

            address_family = {"addressFamilyIPv4": {
                                "autoSummary": auto_summary,
                                "neighbors": af_neighbours,
                                "networks": af_networks,
                                "defaultInformationOrginate": default_originate,
                                "type": "afipv4"}
                              }
        elif af == 6:
            pass  # TODO

        bgp_settings = {"name": name,
                        "description": description,
                        "asNumber": asn,
                        "routerId": router_id,
                        "type": "bgp"
                        }
        bgp_settings.update(address_family)

        vrf_id = self.get_vrfs(vrf)['id']
        return self.post_api(f'/devices/default/routing/virtualrouters/{vrf_id}/bgp',
                             json.dumps(bgp_settings))

    def get_interfaces(self, name=''):
        if name:
            return self.get_obj_by_name('devices/default/interfaces', name)
        else:
            return self.get_api_items('devices/default/interfaces')

    def get_interface_by_phy(self, phy_name: str):
        """
        Get the dict for a Interface with the given physical name e.g. GigabitEthernet0/0
        :param phy_name: str The physical name of the Interface to find
        :return: dict if Interface is found, None if not
        """
        return self.get_class_by_name(self.get_interfaces(), phy_name, name_field_label='hardwareName')

    def get_dhcp_servers(self) -> dict:
        """Gets the DHCP server configuration, including any pools

        :return: The DHCP server container object for all DHCP settings
        :rtype: dict
        """
        return self.get_api_single_item('devicesettings/default/dhcpservercontainers')

    def delete_dhcp_server_pools(self):
        dhcp_server = self.get_dhcp_servers()
        dhcp_server['servers'] = []
        return self.put_api(f'/devicesettings/default/dhcpservercontainers/{dhcp_server["id"]}',
                            data=json.dumps(dhcp_server))

    def send_command(self, cmd: str):
        """Send a CLI command to the FTD device and return the output

        :param cmd: The full command to be sent to the CLI, abbreviations aren't supported
        :type cmd: str
        :return: The output from entering the command or None if the command failed
        :rtype: str
        """
        cmd_body = {"commandInput": cmd,
                    "type": "Command"}
        response = self.post_api('action/command', data=json.dumps(cmd_body))
        if response.status_code == 200:
            return response.json()['commandOutput']
        else:
            return None

    def get_port_groups(self, name=''):
        """Gets all PortGroups or a single PortGroup if a name is provided

        :param name: The name of a PortGroup to find, defaults to ''
        :type name: str, optional
        :return: A list of all PortGroups if no name is provided, or a dict of the single PortGroup with the given name
        :rtype: list|dict
        """
        if name:
            return self.get_obj_by_name('object/portgroups?limit=0&', name)
        else:
            return self.get_api_items('object/portgroups?limit=0')

    def get_tcp_ports(self, name=''):
        """Gets all TCP type Ports or a single TCP Port object if a name is provided

        :param name: The name of a TCP Port to find, defaults to ''
        :type name: str, optional
        :return: A list of all TCP Ports if no name is provided, or a dict of the single TCP Port with the given name
        :rtype: list|dict
        """
        if name:
            return self.get_obj_by_name('object/tcpports?limit=0&', name)
        else:
            return self.get_api_items('object/tcpports?limit=0')

    def get_udp_ports(self, name=''):
        """Gets all UDP type Ports or a single UDP Port object if a name is provided

        :param name: The name of a UDP Port to find, defaults to ''
        :type name: str, optional
        :return: A list of all UDP Ports if no name is provided, or a dict of the single UDP Port with the given name
        :rtype: list|dict
        """
        if name:
            return self.get_obj_by_name('object/udpports?limit=0&', name)
        else:
            return self.get_api_items('object/udpports?limit=0')

    def get_icmp_ports(self, name='', af='4'):
        """Gets all ICMPv4/6 type Ports or a single ICMPv4/6 Port object if a name is provided

        :param name: The name of a ICMPv4 Port to find, defaults to ''
        :type name: str, optional
        :param af: Address family, '4' for an ICMPv4 object, '6' for an ICMPv6 object, defaults to '4'
        :type af: str, optional
        :return: A list of all ICMPv4 Ports if no name is provided, or a dict of the single ICMPv4 Port with the given name
        :rtype: list|dict
        """
        if name:
            return self.get_obj_by_name(f'object/icmpv{af}ports?limit=0&', name)
        else:
            return self.get_api_items(f'object/icmpv{af}ports?limit=0')

    def create_icmp_port(self, name, type, code=None, af='4', description=None):
        """Create an ICMPv4/6 Port object

        :param name: Name of the object
        :type name: str
        :param type: Must be a valid ICMPv4 or ICMPv6 type, see enum for options
        :type type: str
        :param code: Must be a valid ICMPv4 or ICMPv6 code, see enum for options, defaults to None
        :type code: str, optional
        :param af: Address family, '4' for an ICMPv4 object, '6' for an ICMPv6 object, defaults to '4'
        :type af: str, optional
        :param description: Description for the Port object, defaults to None
        :type description: str, optional
        :return: The full requests response object or None if an error occurred
        :rtype: Response
        """
        if code:
            code = code.upper()

        icmp_object = {'description': description,
                       f'icmpv{af}Code': code,
                       f'icmpv{af}Type': type.upper(),
                       'name': name,
                       'type': f'icmpv{af}portobject'}

        return self.post_api(f'object/icmpv{af}ports', json.dumps(icmp_object))

    def get_port_obj_or_grp(self, name) -> dict:
        """Get a Port (tcp/udp/icmpv4/icmpv6) object or PortGroup by the given name

        :param name: Name of the object/group to find
        :type name: str
        :return: Single dict describing the object, if a resource with the name is found
        :rtype: dict
        """
        port = None
        name_filter = {'name': name}
        port_finders = {self.get_tcp_ports: {},
                        self.get_udp_ports: {},
                        self.get_port_groups: {},
                        self.get_icmp_ports: {'af': '4'},
                        self.get_icmp_ports: {'af': '6'}}

        for get_port_method in port_finders:
            port_finders[get_port_method].update(name_filter)
            port = get_port_method(**port_finders[get_port_method])
            if port:
                break
        return port

    def create_port_object(self, name: str, port: str, type: str, description: str = None):
        """Create a TCP or UDP Port object to use in access rules

        :param name: Name of the Port object to be created
        :type name: str
        :param port: A single port number or '-' separated range of ports e.g. '80' or '8000-8008'
        :type port: str
        :param type: The protocol, must be one of ['tcp', 'udp']
        :type type: str
        :param description: A description for the Port, defaults to None
        :type description: str, optional
        :return: The full requests response object or None if an error occurred
        :rtype: Response
        """
        port_object = {"name": name,
                       "description": description,
                       "port": port,
                       "type": f"{type.lower()}portobject"
                       }
        return self.post_api(f'object/{type.lower()}ports', json.dumps(port_object))

    def create_port_group(self, name: str, objects: list, description: str = None):
        """Creates a PortGroup object, containing at least one existing tcp/udp/icmp Port or PortGroup

        :param name: Name of the PortGroup to create
        :type name: str
        :param objects: Names of the tcp/udp/icmp Port or PortGroup objects to be added to the group
        :type objects: list
        :param description: A description for the PortGroup, defaults to None
        :type description: str, optional
        :return: The full requests response object or None if an error occurred
        :rtype: Response
        """
        objects_for_group = []
        for obj_name in objects:
            objects_for_group.append(self.get_port_obj_or_grp(obj_name))

        return self.create_group(name, 'port', objects_for_group, description)

    def get_initial_provision(self) -> dict:
        return self.get_api_single_item('/devices/default/action/provision')

    def set_initial_provision(self, new_password, current_password='Admin123'):
        provision = self.get_initial_provision()
        provision["acceptEULA"] = True
        provision["currentPassword"] = current_password
        provision["newPassword"] = new_password
        provision.pop('links')
        provision.pop('version')

        return self.post_api('/devices/default/action/provision',
                             data=json.dumps(provision))

    def get_hostname_obj(self) -> dict:
        return self.get_api_single_item('devicesettings/default/devicehostnames')

    def get_hostname(self) -> str:
        """Get the hostname of the system

        :return: The hostname
        :rtype: str
        """
        return self.get_hostname_obj()['hostname']

    def set_hostname(self, hostname):
        """Sets the hostname of the system

        :param hostname: The hostname to set
        :type hostname: str
        :return: The full requests response object or None if an error occurred
        :rtype: Response
        """
        current_hostname = self.get_hostname_obj()
        hostname_id = current_hostname['id']
        new_hostname = {"hostname": hostname,
                        "id": hostname_id,
                        "version": current_hostname['version'],
                        "type": "devicehostname"}

        return self.put_api(f'devicesettings/default/devicehostnames/{hostname_id}',
                            data=json.dumps(new_hostname))

    def get_upgrade_files(self):
        return self.get_api('managedentity/upgradefiles').json()

    def get_upgrade_file(self, file_id):
        return self.get_api(f'managedentity/upgradefiles/{file_id}').json()

    def upload_upgrade(self, filename):
        # API parameter is called fileToUpload
        files = {'fileToUpload': open(filename, 'rb')}

        return self.post_api('action/uploadupgrade',
                             files=files)

    def perform_upgrade(self):
        return self.post_api('action/upgrade')

    def get_system_info(self) -> dict:
        """Gets system information such as software versions, device model, serial number and management details

        :return: The target FTD system information
        :rtype: dict
        """
        return self.get_api('/operational/systeminfo/default').json()

    def get_security_zones(self, name=''):
        if name:
            return self.get_obj_by_name('object/securityzones?limit=0&', name)
        else:
            return self.get_api_items('object/securityzones?limit=0')

    def create_security_zone(self, name, description='', interfaces=[], phy_interfaces=[], mode='ROUTED'):
        """
        Creates a security zone
        :param name: str The name of the Security Zone
        :param description: str Description
        :param interfaces: list The logical names of any Interfaces to be part of this Security Zone e.g. inside
        :param phy_interfaces: list The physical names of any Interfaces to be part of this Security Zone e.g. GigabitEthernet0/0
        :param mode: str The mode of the Security Zone, either ROUTED or PASSIVE
        """

        zone_interfaces = []

        for intf in phy_interfaces:
            intf_obj = self.get_interface_by_phy(intf)
            zone_interfaces.append(intf_obj)

        for intf in interfaces:
            intf_obj = self.get_interfaces(name=intf)
            zone_interfaces.append(intf_obj)

        zone_object = {"name": name,
                       "description": description,
                       "interfaces": zone_interfaces,
                       "mode": mode.upper(),
                       "type": "securityzone"
                       }
        return self.post_api('object/securityzones', json.dumps(zone_object))

    def get_acp(self):
        return self.get_api_single_item('policy/accesspolicies')

    def get_access_rules(self, name=''):
        """Gets all AccessRules or a single AccessRule if a name is provided

        :param name: The name of the AccessRule to find, defaults to ''
        :type name: str, optional
        :return: A list of all AccessRules if no name is provided, or a dict of the single AccessRules with the given name
        :rtype: list|dict
        """
        policy_id = self.get_acp()['id']
        if name:
            # Access rules cannot be filtered by name via the API so use get_class_by_name instead:
            return self.get_class_by_name(self.get_access_rules(), name)
        else:
            return self.get_paged_items(f'policy/accesspolicies/{policy_id}/accessrules')

    def add_rule_item(self, item_name, item_obj, item_list):
        if item_obj:
            item_list.append(item_obj)
        else:
            raise ResourceNotFound(f'Resource with name "{item_name}" not does not exist!')

    def create_access_rule(self, name, action, src_zones=[], src_networks=[], src_ports=[],
                           dst_zones=[], dst_networks=[], dst_ports=[], int_policy='', syslog='', log=''):
        """Create an AccessRule to be used in the main Access Policy. If any optional src/dst values are not
        provided, they are treated as an 'any'

        :param name: Name of the AccessRule
        :type name: str
        :param action: The action the rule should take if matched, should be one of ['PERMIT', 'TRUST', 'DENY']
        :type action: str
        :param src_zones: List of names of source Security Zones, defaults to []
        :type src_zones: list, optional
        :param src_networks: List of names of source networks, names can be of either NetworkObject or NetworkGroup, defaults to []
        :type src_networks: list, optional
        :param src_ports: List of names of source ports, names can be of either tcp/udp PortObject or PortGroup, defaults to []
        :type src_ports: list, optional
        :param dst_zones: List of destination Security Zones, defaults to []
        :type dst_zones: list, optional
        :param dst_networks: List of names of destination networks, names can be of either NetworkObject or NetworkGroup, defaults to []
        :type dst_networks: list, optional
        :param dst_ports: List of names of destination ports, names can be of either tcp/udp PortObject or PortGroup, defaults to []
        :type dst_ports: list, optional
        :param int_policy: Name of an IntrusionPolicy to apply to the rule, defaults to ''
        :type int_policy: str, optional
        :param syslog: Name of a SyslogServer to log the rule to, in the format of IP:PORT, defaults to ''
        :type syslog: str, optional
        :param log: Log the rule at start and end of connection, end of connection, or no log, should be one of ['BOTH', 'END', ''], defaults to ''
        :type log: str, optional
        :raises ResourceNotFound: If any of the object names passed in cannot be found e.g. a source network or dest port has not been created
        :return: The full requests response object or None if an error occurred
        :rtype: Response|None
        """

        rule_src_zones = []
        rule_src_networks = []
        rule_src_ports = []
        rule_dst_zones = []
        rule_dst_networks = []
        rule_dst_ports = []
        rule_int_policy = None
        rule_syslog = None

        for zone in src_zones:
            z = self.get_security_zones(name=zone)
            self.add_rule_item(zone, z, rule_src_zones)

        for network in src_networks:
            net = self.get_net_obj_or_grp(network)
            self.add_rule_item(network, net, rule_src_networks)

        for port in src_ports:
            p = self.get_port_obj_or_grp(port)
            self.add_rule_item(port, p, rule_src_ports)

        for zone in dst_zones:
            z = self.get_security_zones(name=zone)
            self.add_rule_item(zone, z, rule_dst_zones)

        for network in dst_networks:
            net = self.get_net_obj_or_grp(network)
            self.add_rule_item(network, net, rule_dst_networks)

        for port in dst_ports:
            p = self.get_port_obj_or_grp(port)
            self.add_rule_item(port, p, rule_dst_ports)

        if int_policy:
            ip = self.get_intrusion_policies(int_policy)
            if ip:
                # Can't just pass the whole IntrusionPolicy object through like most others, so just pass the req'd fields
                rule_int_policy = self._get_object_subset(ip)

        if syslog:
            syslog_server = self.get_syslog_servers(syslog)
            if syslog_server:
                rule_syslog = syslog_server

        if log.upper() == 'BOTH':
            log = 'LOG_BOTH'
        elif log.upper() == 'END':
            log = 'LOG_FLOW_END'
        else:
            log = 'LOG_NONE'

        rule = {"name": name,
                "sourceZones": rule_src_zones,
                "destinationZones": rule_dst_zones,
                "sourceNetworks": rule_src_networks,
                "destinationNetworks": rule_dst_networks,
                "sourcePorts": rule_src_ports,
                "destinationPorts": rule_dst_ports,
                "ruleAction": action.upper(),
                "eventLogAction": log,
                "intrusionPolicy": rule_int_policy,
                "syslogServer": rule_syslog,
                "type": "accessrule"
                }

        policy_id = self.get_acp()['id']
        return self.post_api(f'policy/accesspolicies/{policy_id}/accessrules',
                             data=json.dumps(rule))

    def get_smartlicense(self):
        return self.get_api_items('license/smartlicenses')

    def set_smartlicense(self, license_type):
        """
        Activates a SmartLicense of the given type
        :param license_type: str The type of license to apply, must be one of ['BASE', 'MALWARE', 'THREAT', 'URLFILTERING', 'APEX', 'PLUS', 'VPNOnly']
        :return: dict The new license object, or the error message from the JSON response
        """
        license_object = {"count": 1,
                          "compliant": True,
                          "licenseType": license_type,
                          "type": "license"
                          }
        return self.post_api('license/smartlicenses',
                             data=json.dumps(license_object)).json()

    def get_intrusion_policies(self, name=''):
        """Gets all IntrusionPolicies or a single IntrusionPolicy if a name is provided

        :param name: The name of the IntrusionPolicy to find, defaults to ''
        :type name: str, optional
        :return: A list of all IntrusionPolicies if no name is provided, or a dict of the single IntrusionPolicy with the given name
        :rtype: list|dict
        """
        if name:
            return self.get_obj_by_name('policy/intrusionpolicies', name)
        else:
            return self.get_api_items('policy/intrusionpolicies')

    def get_syslog_servers(self, name=''):
        """Gets all SyslogServers or a single SyslogServer if a name is provided

        :param name: The name of the SyslogServer to find. The name is stored in the format IP:PORT, defaults to ''
        :type name: str, optional
        :return: A list of all SyslogServers if no name is provided, or a dict of the single SyslogServer with the given name
        :rtype: list|dict
        """
        if name:
            # Syslog server names are stored as IP:PORT, so unable to query using URL filter
            return self.get_class_by_name(self.get_syslog_servers(), name)
        else:
            return self.get_api_items('object/syslogalerts?limit=0')

    def create_syslog_server(self, ip, protocol='UDP', port='514', interface=None):
        """Creates a SyslogServer to be able to send access rule and system logs to

        :param ip: IP address of the syslog server
        :type ip: str
        :param protocol: Protocol used to send syslog messages, must be one of ['TCP', 'UDP'], defaults to 'UDP'
        :type protocol: str, optional
        :param port: Port number used to send syslog messages, defaults to '514'
        :type port: str, optional
        :param interface: Name of a data interface to use as the source to reach the syslog server IP, otherwise mgmt will be used, defaults to None
        :type interface: str, optional
        :return: The new SyslogServer object
        :rtype: dict
        """
        use_mgmt = True
        interface_object = None

        if interface:
            use_mgmt = False
            interface_object = self.get_interfaces(name=interface)

        syslog_object = {"deviceInterface": interface_object,
                         "useManagementInterface": use_mgmt,
                         "protocol": protocol.upper(),
                         "host": ip,
                         "port": port,
                         "type": "syslogserver"
                         }
        return self.post_api('object/syslogalerts',
                             data=json.dumps(syslog_object)).json()

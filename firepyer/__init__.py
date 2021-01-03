import json
from json.decoder import JSONDecodeError
from pprint import pprint
from time import sleep
from datetime import datetime

import requests
from requests import api


ACCESS_TOKEN_VALID_SECS = 1740  # FDM access token lasts 30mins, this var is 29mins in secs


class Fdm:
    def __init__(self, host, username, password):
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
        
        headers = {"Accept": "application/json", 'User-Agent': 'firepyer/0.0.1'}
        if get_auth:
            headers['Authorization'] = f'Bearer {self.check_get_access_token()}'
        if not files:
            # When sending files, requests will auto populate CT as multipart/form-data
            headers['Content-Type'] = "application/json"
        
        try:
            response = requests.request(method, uri,
                                        data=data,
                                        headers=headers,
                                        verify=False,
                                        files=files)
            pprint(response)
            if response.status_code != 200:
                pprint(response.status_code)
                pprint(uri)
                pprint(data)
                pprint(response.text)
                pprint(response.request.headers)
                try:
                    pprint(response.json())
                except JSONDecodeError:
                    pass
            return response
        except Exception as e:
            print(f"Unable to {method} request: {str(e)}")
            return None
        
    def post_api(self, uri, data=None, get_auth=True, files=None):
        return self.api_call(uri, 'POST', data=data, get_auth=get_auth, files=files)
    
    def put_api(self, uri, data=None):
        return self.api_call(uri, 'PUT', data=data)
        
    def get_api(self, uri, data=None):
        return self.api_call(uri, 'GET', data=data)
    
    def check_api_status(self):
        api_alive = False
        
        while not api_alive:
            api_status = self.api_call('#/login', 'GET', get_auth=False)
            if api_status != None:
                if api_status.status_code == 401:
                    print('API Alive!')
                    api_alive = True
                elif api_status.status_code == 503:
                    print('API service unavailable...')
            else:
                print('Unable to reach API')
                # Exception when device is rebooted/unreachable:
                # HTTPSConnectionPool
            sleep(10)
    
    def get_access_token(self) -> str:
        """
        Login to FTD device and obtain an access token. The access token is required so that the user can
        connect to the device to send REST API requests. 
        :return: OAUTH access token
        """
        access_token = None
        access_token_expiry_time = None
        
        payload = f'{{"grant_type": "password", "username": "{self.username}", "password": "{self.password}"}}'
        resp = self.post_api('fdm/token', payload, get_auth=False)
        if resp is not None:
            access_token = resp.json().get('access_token')

            epoch_now = datetime.timestamp(datetime.now())
            access_token_expiry_time = epoch_now + ACCESS_TOKEN_VALID_SECS
            
            print(f"Login successful, access_token obtained, expires at: {datetime.fromtimestamp(access_token_expiry_time)}")

        return access_token, access_token_expiry_time
    
    def check_get_access_token(self) -> str:
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
            self.access_token, self.access_token_expiry_time = self.get_access_token()
        return self.access_token
    
    def get_class_by_name(self, get_class: dict, obj_name: str, name_field_label: str = 'name') -> dict:
        """
        Get the dict for the Class with the given name
        :param get_class: dict The GET reponse from an FDM Model query
        :param obj_name: str The name of the object to find
        :param name_field_label: str The field to use as the 'name' to match on, defaults to name
        :return: dict if an object with the name is found, None if not
        """
        
        if get_class is not None:
            for obj in get_class['items']:
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
        return self.get_api(f'{url}?filter={filter}').json()['items']

    def get_obj_by_name(self, url, name):
        return self.get_obj_by_filter(url, filter=f'name:{name}')

    def get_net_objects(self):
        return self.get_api('object/networks?limit=0').json()
    
    def get_net_objects_filter(self, filter: str):
        return self.get_obj_by_filter('object/networks', filter)
    
    def get_net_object_by_name(self, net_name: str):
        """
        Get the dict for a NetworkObject with the given name
        :param net_name: str The name of the NetworkObject to find
        :return: dict if NetworkObject is found, None if not
        """
        return self.get_class_by_name(self.get_net_objects(), net_name)
    
    def get_net_groups(self, name):
        if name:
            return self.get_obj_by_name('object/networkgroups', name)
        else:
            return self.get_api('object/networkgroups?limit=0').json()

    def get_net_group_filter(self, filter: str):
        return self.get_obj_by_filter('object/networkgroups', filter)
    
    def get_net_obj_or_grp(self, name) -> dict:
        """
        Get a network object or network group by the given name
        :param name: str The name of the object/group to find
        :return: dict The object of the resource if found 
        """
        
        net = self.get_net_objects_filter(f'name:{name}')
        if net:
            return net
        else:
            net = self.get_net_group_filter(f'name:{name}')
            if net:
                return net
        return None

    def create_object(self, name: str, value: str, type: str = 'HOST', description: str = None):

        host_object = {"name": name,
                       "description": description,
                       "subType": type.upper(),
                       "value": value,
                       "dnsResolution": "IPV4_ONLY",
                       "type": "networkobject"
                       }
        return self.post_api('object/networks', json.dumps(host_object))

    def create_group(self, name: str, group_type: str, all_objects: list, object_names: list, description: str = None):
        """
        Creates a group of pre-existing Network or Port objects
        :param name: str Name of the group being created
        :param group_type: str Should be either network or port depending on group class
        :param all_objects: [Obj] All API-gathered Objects that exist for the type of group class being created
        :param object_names: [str] Names of objects to be added to the group
        :param description: str Description of the group being created
        """

        objects_for_group = []

        for obj_name in object_names:
            for obj in all_objects:
                if obj['name'] == obj_name:
                    objects_for_group.append(obj)
        
        object_group = {"name": name,
                        "description": description,
                        "objects": objects_for_group,
                        "type": f"{group_type}objectgroup"
                        }

        return self.post_api(f'object/{group_type}groups', json.dumps(object_group))

    def create_network_group(self, name: str, objects: list, description: str = None):
        """
        Creates a NetworkGroup object, containing at least 1 existing Network or NetworkGroup object
        :param name: str Name of the NetworkGroup
        :param objects: [str] Names of the Network or NetworkGroup objects to be added to the group
        :param description: str A description for the NetworkGroup
        """
        all_objects = self.get_net_objects()
        all_groups = self.get_net_groups()
        all_nets = all_objects['items'] + all_groups['items']
        
        return self.create_group(name, 'network', all_nets, objects, description)
    
    def get_pending_changes(self):
        """
        Sends a GET rquest to obtain the pending changes from the FTD device
        :return: True if changes are pending, otherwise False
        """
        changes_found = False
        response = self.get_api('operational/pendingchanges')
        if response.status_code != 200:
            print("Failed GET pending changes response {} {}".format(response.status_code, response.json()))
        else:
            pprint(response.json())
            if response.json().get('items'):
                changes_found = True
        return changes_found

    def post_deployment(self) -> str:
        """
        Send a deployment POST request
        :return: unique id for the deployment task
        """
        deploy_id = None
        response = self.post_api('operational/deploy')
        if response.status_code != 200:
            print("Failed POST deploy response {} {}".format(response.status_code, response.json()))
        else:
            pprint(response.json())
            deploy_id = response.json().get('id')
            print(deploy_id)
        return deploy_id

    def get_deployment_status(self, deploy_id: str) -> str:
        """
        Wait for a deployment to complete
        :param deploy_id: unique identifier for deployment task
        :return: str Status name of the deployment, None if unable to get status
        """
        state = None
        deploy_url = 'operational/deploy'
        response = self.get_api(f'{deploy_url}/{deploy_id}')
        if response.status_code != 200:
            print("Failed GET deploy response {} {}".format(response.status_code, response.json()))
        else:
            state = response.json().get('state')
            pprint(response.json())
            pprint(state)

        return state
    
    def deploy_policy(self):
        if self.get_pending_changes():
            deployment_id = self.post_deployment()
            if deployment_id is not None:
                state = self.get_deployment_status(deployment_id)
                while state != 'DEPLOYED':
                    # Final states should be 'FAILED' or 'DEPLOYED'
                    sleep(10)
                    state = self.get_deployment_status(deployment_id)
                print('Deployment complete!')
                return True
            else:
                print('Deploymentg request failed, unable to get deployment ID!')
        else:
            print('No pending changes!')
    
    def get_vrfs(self):
        return self.get_api('devices/default/routing/virtualrouters').json()
    
    def get_vrf_by_name(self, vrf_name: str):
        """
        Get the dict for a VRF with the given name
        :param vrf_name: str The name of the VRF to find
        :return: dict if VRF is found, None if not
        """
        return self.get_class_by_name(self.get_vrfs(), vrf_name)

    def get_bgp_general_settings(self):
        return self.get_api('devices/default/routing/bgpgeneralsettings').json()
    
    def set_bgp_general_settings(self):
        bgp_settings = {"name": "BgpGeneralSettings",
                        "asNumber": "65500",
                        # "routerId": "string",
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
    
    def get_bgp_settings(self):
        vrf_id = self.get_vrf_by_name('Global')['id']
        bgp_settings = self.get_api(f'/devices/default/routing/virtualrouters/{vrf_id}/bgp')
        return bgp_settings.json()
    
    def set_bgp_settings(self):
        with open('bgp_settings.json') as bgp_settings:
            bgp_settings_json = json.load(bgp_settings)

        vrf_id = self.get_vrf_by_name('Global')['id']
        return self.post_api(f'/devices/default/routing/virtualrouters/{vrf_id}/bgp',
                             json.dumps(bgp_settings_json))

    def get_interfaces(self):
        return self.get_api('/devices/default/interfaces').json()
    
    def get_interface_filter(self, filter: str):
        return self.get_obj_by_filter('devices/default/interfaces', filter)
    
    def get_interface_by_phy(self, phy_name: str):
        """
        Get the dict for a NetworkObject with the given name
        :param net_name: str The name of the NetworkObject to find
        :return: dict if NetworkObject is found, None if not
        """
        return self.get_class_by_name(self.get_interfaces(), phy_name, name_field_label='hardwareName')
    
    def update_interfaces(self):
        with open('interfaces.json') as int_settings:
            int_settings_dict = json.load(int_settings)
        
        for interface in int_settings_dict:
            interface_obj = self.get_interface_by_phy(interface)
            if interface_obj is not None:
                interface_obj['description'] = int_settings_dict[interface]['description']
                interface_obj['ipv4']['ipAddress']['ipAddress'] = int_settings_dict[interface]['ip']
                interface_obj['ipv4']['ipAddress']['netmask'] = int_settings_dict[interface]['netmask']
                
                response = self.put_api(f'devices/default/interfaces/{interface_obj["id"]}',
                                        data=json.dumps(interface_obj))
                if response is not None:
                    pprint(response.json())
    
    def get_dhcp_servers(self):
        return self.get_api('devicesettings/default/dhcpservercontainers').json()
    
    def delete_dhcp_server_pools(self):
        dhcp_server = self.get_dhcp_servers()['items'][0]
        dhcp_server['servers'] = []
        return self.put_api(f'/devicesettings/default/dhcpservercontainers/{dhcp_server["id"]}',
                            data=json.dumps(dhcp_server))
    
    def send_command(self, cmd: str):
        cmd_body = {"commandInput": cmd,
                    "type": "Command",}
        return self.post_api('action/command',
                             data=json.dumps(cmd_body)).json()
    
    def get_port_groups(self, filter=''):
        if filter:
            return self.get_obj_by_filter('object/portgroups', filter)
        else:
            return self.get_api('object/portgroups').json()
    
    def get_tcp_ports(self, filter=''):
        if filter:
            return self.get_obj_by_filter('object/tcpports', filter)
        else:
            return self.get_api('object/tcpports?limit=0').json()
    
    def get_udp_ports(self, filter=''):
        if filter:
            return self.get_obj_by_filter('object/udpports', filter)
        else:
            return self.get_api('object/udpports?limit=0').json()

    def get_port_obj_or_grp(self, name) -> dict:
        """
        Get a Port (tcp/udp) object or PortGroup by the given name
        :param name: str The name of the object/group to find
        :return: dict The object of the resource if found
        """

        port = self.get_tcp_ports(filter=f'name:{name}')
        if port:
            return port
        else:
            port = self.get_udp_ports(filter=f'name:{name}')
            if port:
                return port
            else:
                port = self.get_port_groups(filter=f'name:{name}')
                if port:
                    return port
        return None

    def create_port_object(self, name: str, port: str, type: str, description: str = None):
        """
        Creates a Port object
        :param name: str The name of the Port object
        :param port: str A single port number or '-' separated range of ports e.g. 80 or 8000-8008
        :param type: str The protocol, either tcp or udp
        :param description: str A description for the Port
        """
        port_object = {"name": name,
                       "description": description,
                       "port": port,
                       "type": f"{type}portobject"
                       }
        return self.post_api(f'object/{type}ports', json.dumps(port_object))
       
    def create_port_group(self, name: str, objects: list, description: str = None):
        """
        Creates a PortGroup object, containing at least 1 tcp/udp Port or an existing PortGroup
        :param name: str Name of the PortGroup
        :param objects: [str] Names of the tcp/udp Port or PortGroup objects to be added to the group
        :param description: str A description for the PortGroup
        """
        tcp_ports = self.get_tcp_ports()
        udp_ports = self.get_udp_ports()
        port_groups = self.get_port_groups()
        all_ports = tcp_ports['items'] + udp_ports['items'] + port_groups['items']
        
        return self.create_group(name, 'port', all_ports, objects, description)
    
    def get_initial_provision(self):
        return self.get_api('/devices/default/action/provision').json()
    
    def set_initial_provision(self, new_password, current_password='Admin123'):
        get_provis = self.get_initial_provision()
        provision = get_provis['items'][0]
        provision["acceptEULA"] = True
        provision["currentPassword"] = current_password
        provision["newPassword"] = new_password
        provision.pop('links')
        provision.pop('version')

        return self.post_api('/devices/default/action/provision',
                             data=json.dumps(provision))

    def get_hostname(self):
        return self.get_api('devicesettings/default/devicehostnames').json()
    
    def set_hostname(self, hostname):
        current_hostname = self.get_hostname()['items'][0]
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
        return self.get_api('/operational/systeminfo/default').json()

    def get_security_zone_filter(self, filter: str):
        return self.get_obj_by_filter('object/securityzones', filter)

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
            intf_obj = self.get_interface_filter(f'name:{intf}')
            zone_interfaces.append(intf_obj[0])

        zone_object = {"name": name,
                       "description": description,
                       "interfaces": zone_interfaces,
                       "mode": mode.upper(),
                       "type": "securityzone"
                       }
        return self.post_api('object/securityzones', json.dumps(zone_object))

    def get_acp(self):
        return self.get_api('policy/accesspolicies').json()['items']
    
    def get_access_rules(self):
        policy_id = self.get_acp()[0]['id']
        return self.get_paged_items(f'policy/accesspolicies/{policy_id}/accessrules')

    def add_rule_item(self, item_name, item_obj, item_list):
        if item_obj:
            item_list.append(item_obj[0])
        else:
            print(f'{item_name} does not exist!')
    
    def create_access_rule(self, name, action, src_zones=[], src_networks=[], src_ports=[],
                           dst_zones=[], dst_networks=[], dst_ports=[], int_policy='', log=''):
        """
        Create an access rule
        :param name: str Name of the AccessRule
        :param action: str The action the rule should take, should be one of ['PERMIT', 'TRUST', 'DENY']
        :param src_zones: [str] An optional list of names of source Security Zones
        :param src_networks: [str] An optional list of names of source networks, names can be of either NetworkObject or NetworkGroup
        :param src_ports: [str] An optional list of names of source ports, names can be of either tcp/udp PortObject or PortGroup
        :param dst_zones: [str] An optional list of destination Security Zones
        :param dst_networks: [str] An optional list of names of destination networks, names can be of either NetworkObject or NetworkGroup
        :param dst_ports: [str] An optional list of names of destination ports, names can be of either tcp/udp PortObject or PortGroup
        :param int_policy: str Optionally provide a name of the IntrusionPolicy to apply to the rule
        :param log: str Optionally log the rule at start and end of connection, end of connection, or not at all, should be one of ['BOTH', 'END']
        :return: 
        """

        rule_src_zones = []
        rule_src_networks = []
        rule_src_ports = []
        rule_dst_zones = []
        rule_dst_networks = []
        rule_dst_ports = []
        rule_int_policy = None

        for zone in src_zones:
            z = self.get_security_zone_filter(f'name:{zone}')
            self.add_rule_item(zone, z, rule_src_zones)

        for network in src_networks:
            net = self.get_net_obj_or_grp(network)
            self.add_rule_item(network, net, rule_src_networks)

        for port in src_ports:
            p = self.get_port_obj_or_grp(port)
            self.add_rule_item(port, p, rule_src_ports)

        for zone in dst_zones:
            z = self.get_security_zone_filter(f'name:{zone}')
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
                rule_int_policy = {}
                rule_int_policy['id'] = ip[0]['id']
                rule_int_policy['type'] = ip[0]['type']
                rule_int_policy['version'] = ip[0]['version']
                rule_int_policy['name'] = ip[0]['name']

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
                # "syslogServer": {
                #     "id": "string",
                #     "type": "string",
                #     "version": "string",
                #     "name": "string"
                #     },
                "type": "accessrule"
                }

        pprint(rule)

        policy_id = self.get_acp()[0]['id']
        return self.post_api(f'policy/accesspolicies/{policy_id}/accessrules',
                             data=json.dumps(rule))

    def get_smartlicense(self):
        return self.get_api('license/smartlicenses').json()['items']

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
        if name:
            return self.get_obj_by_name('policy/intrusionpolicies', name)
        else:
            return self.get_api('policy/`intrusionpolicies').json()['items']

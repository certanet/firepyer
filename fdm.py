import json
import csv
from pprint import pprint
from time import sleep
from datetime import datetime

import requests


requests.packages.urllib3.disable_warnings()

ACCESS_TOKEN_VALID_SECS = 1740  # FDM access token lasts 30mins, this var is 29mins in secs


class Fdm:
    def __init__(self):
        self.ftd_host = '192.168.98.59'
        self.username = 'admin'
        self.password = 'Admin123'
        self.access_token = None
        self.access_token_expiry_time = None

    def post_api(self, uri, data=None, additional_headers=None, get_auth=True, method='POST'):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        if get_auth:
            headers['Authorization'] = f'Bearer {self.check_get_access_token()}'

        try:
            if method == 'POST':
                response = requests.post(f"https://{self.ftd_host}/api/fdm/latest/{uri}",
                                        data=data, verify=False, headers=headers)
            elif method == 'PUT':
                response = requests.put(f"https://{self.ftd_host}/api/fdm/latest/{uri}",
                                        data=data, verify=False, headers=headers)
            pprint(response)
            if response.status_code == 200:
                return response
            else:
                pprint(uri)
                pprint(data)
                pprint(response.json())
        except Exception as e:
            print(f"Unable to {method} request: {str(e)}")
            return None
        
    def get_api(self, uri, data=None, additional_headers=None):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        headers['Authorization'] = f'Bearer {self.check_get_access_token()}'
        try:
            response = requests.get(f"https://{self.ftd_host}/api/fdm/latest/{uri}",
                                     data=data, verify=False, headers=headers)
            if response.status_code == 200:
                return response
        except Exception as e:
            print("Unable to GET request: {}".format(str(e)))
            return None
    
    def get_access_token(self):
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
    
    def check_get_access_token(self):
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
    
    def get_class_by_name(self, get_class, obj_name, name_field_label='name'):
        """
        Get the dict for the Class with the given name
        :param obj_name:  str The name of the object to find
        :param name_field_label:  str The field to use as the 'name' to match on, defaults to name
        :return: dict if an object with the name is found, None if not
        """
        
        if get_class is not None:
            for obj in get_class['items']:
                if obj[name_field_label] == obj_name:
                    return obj
        return None
    
    def get_net_objects(self):
        return self.get_api('object/networks').json()
    
    def get_net_object_by_name(self, net_name):
        """
        Get the dict for a NetworkObject with the given name
        :param net_name: str The name of the NetworkObject to find
        :return: dict if NetworkObject is found, None if not
        """
        return self.get_class_by_name(self.get_net_objects(), net_name)
    
    def get_object_groups(self):
        return self.get_api('object/networkgroups').json()

    def create_object(self, name, value, type='HOST', description=None):

        host_object = {"name": name,
                       "description": description,
                       "subType": type.upper(),
                       "value": value,
                       "dnsResolution": "IPV4_ONLY",
                       "type": "networkobject"
                       }
        return self.post_api('object/networks', json.dumps(host_object))

    def create_network_group(self, name, object_names, description=None):
        all_objects = self.get_net_objects()

        objects_for_group = []

        for obj_name in object_names:
            for net_object in all_objects['items']:
                if net_object['name'] == obj_name:
                    objects_for_group.append(net_object)
        
        network_group = {"name": name,
                         "description": description,
                         "objects": objects_for_group,
                         "type": "networkobjectgroup"
                         }

        return self.post_api('object/networkgroups', json.dumps(network_group))
    
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

    def post_deployment(self):
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

    def get_deployment_status(self, deploy_id):
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
    
    def get_bgp_general_settings(self):
        return self.get_api('devices/default/routing/bgpgeneralsettings').json()
    
    def set_bgp_general_settings(self):
        bgp_settings = {"name": "MCAPI-BgpGeneralSettings",
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
    
    def get_vrf_by_name(self, vrf_name):
        """
        Get the dict for a VRF with the given name
        :param vrf_name: str The name of the VRF to find
        :return: dict if VRF is found, None if not
        """
        return self.get_class_by_name(self.get_vrfs(), vrf_name)

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
    
    def get_interface_by_phy(self, phy_name):
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
                
                response = self.post_api(f'devices/default/interfaces/{interface_obj["id"]}',
                                         data=json.dumps(interface_obj),
                                         method='PUT')
                if response is not None:
                    pprint(response.json())
    
    def get_dhcp_servers(self):
        return self.get_api('devicesettings/default/dhcpservercontainers').json()
    
    def delete_dhcp_server_pools(self):
        dhcp_server = self.get_dhcp_servers()['items'][0]
        dhcp_server['servers'] = []
        return self.post_api(f'/devicesettings/default/dhcpservercontainers/{dhcp_server["id"]}',
                             data=json.dumps(dhcp_server),
                             method='PUT')
    
    def send_command(self, cmd):
        cmd_body = {"commandInput": cmd,
                    "type": "Command",}
        return self.post_api('action/command',
                             data=json.dumps(cmd_body)).json()



def read_objects_csv(filename):
    objs = []
    with open(filename) as objects_csv:
        objects_dict = csv.DictReader(objects_csv)
        for obj in objects_dict:
            objs.append(obj)
    return objs


if __name__ == '__main__':
    fdm = Fdm()

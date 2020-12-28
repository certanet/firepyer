import json
import csv
from pprint import pprint
from time import sleep

import requests


requests.packages.urllib3.disable_warnings()


class Fdm:
    def __init__(self):
        self.ftd_host = '192.168.98.59'
        self.username = 'admin'
        self.password = 'Admin123'

    def post_api(self, uri, data=None, additional_headers=None, get_auth=True):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        if get_auth:
            headers['Authorization'] = f'Bearer {self.get_access_token()}'

        try:
            response = requests.post(f"https://{self.ftd_host}/api/fdm/latest/{uri}",
                                     data=data, verify=False, headers=headers)
            pprint(response)
            if response.status_code == 200:
                return response
            else:
                pprint(response.json())
        except Exception as e:
            print("Unable to POST request: {}".format(str(e)))
            return None
        
    def get_api(self, uri, data=None, additional_headers=None):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        headers['Authorization'] = f'Bearer {self.get_access_token()}'
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
        Requires Python 3.0 or greater and requests lib.
        Login to FTD device and obtain an access token. The access token is required so that the user can
        connect to the device to send REST API requests. 
        :return: OAUTH access token
        """
        access_token = None
        
        payload = f'{{"grant_type": "password", "username": "{self.username}", "password": "{self.password}"}}'
        resp = self.post_api('fdm/token', payload, get_auth=False)
        if resp is not None:
            access_token = resp.json().get('access_token')
            print("Login successful, access_token obtained")

        return access_token
    
    def get_net_objects(self):
        return self.get_api('object/networks').json()
    
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

    def check_access_token(self):
        # TODO This method should check the contents of self.access_token if None then get_access_token
        # Also check self.token_time is not greater than 30mins ago, else get token again
        return
    
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
        :param: str The name of the VRF to find
        :return: dict if VRF is found, None if not
        """
        vrfs = self.get_vrfs()
        
        if vrfs is not None:
            for vrf in self.get_vrfs()['items']:
                if vrf['name'] == vrf_name:
                    return vrf
        return None

    def get_bgp_settings(self):
        vrf_id = self.get_vrf_by_name('Global')['id']
        bgp_settings = self.get_api(f'/devices/default/routing/virtualrouters/{vrf_id}/bgp')
        return bgp_settings.json()
    
    def set_bgp_settings(self):
        """
        {'addressFamilyIPv4': {'afTableMap': None,
                                  'aggregateAddressesIPv4s': [],
                                  'aggregateTimer': 30,
                                  'autoSummary': False,
                                  'bgpNextHopTriggerDelay': 5,
                                  'bgpNextHopTriggerEnable': True,
                                  'bgpRedistributeInternal': False,
                                  'bgpSupressInactive': False,
                                  'defaultInformationOrginate': False,
                                  'distance': {'externalDistance': 20,
                                               'internalDistance': 200,
                                               'localDistance': 200,
                                               'type': 'afbgpdistance'},
                                  'distributeLists': [],
                                  'injectMaps': [],
                                  'maximumPaths': None,
                                  'neighbors': [],
                                  'networks': [],
                                  'redistributeProtocols': [],
                                  'scanTime': 60,
                                  'synchronization': False,
                                  'type': 'afipv4'},
            'addressFamilyIPv6': None,
            'asNumber': '65501',
            'description': None,
            'id': '14e174f8-4852-11eb-a06f-1b5b930bf2e3',
            'links': {'self': 'https://192.168.98.59/api/fdm/latest/devices/default/routing/virtualrouters/42e95fbf-fd5a-42bf-a95f-bffd5a42bfd6/bgp/14e174f8-4852-11eb-a06f-1b5b930bf2e3'},
            'name': 'bgp65501',
            'routerId': None,
            'type': 'bgp',
            'version': 'pw7jyuvyju4bf'}
        """
        bgp_settings = {}
    




def read_objects_csv(filename):
    objs = []
    with open(filename) as objects_csv:
        objects_dict = csv.DictReader(objects_csv)
        # return objects_dict
        for obj in objects_dict:
            objs.append(obj)
            # print(obj)
    return objs


if __name__ == '__main__':
    fdm = Fdm()
    
    # objects = read_objects_csv('networks.csv')
    # # objects = read_objects_csv('hosts.csv')
    # for host in objects:
    #     print(host)
    #     pprint(fdm.create_object(**host))

    # TODO HOW WILL THIS LIDT OF OBJ NAMES BE STORED IN CSV??
    # new_group = {'name': 'api_group', 'object_names': ['Host-1']}
    # pprint(fdm.create_network_group(**new_group))

    # pprint(fdm.get_object_groups())

    # pprint(fdm.get_pending_changes())
    # pprint(fdm.get_deployment_status('052e8fbb-4846-11eb-a06f-db3f0f9aa3ac'))

    # pprint(fdm.get_bgp_general_settings())
    pprint(fdm.set_bgp_general_settings())
    # pprint(fdm.get_bgp_general_settings())

    pprint(fdm.deploy_policy())

    # pprint(fdm.get_vrfs())
    # pprint(fdm.get_vrf_by_name('Global'))
    pprint(fdm.get_bgp_settings())

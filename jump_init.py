# -*- coding: utf-8 -*-


import requests
import random
import string
import json


class JumpApi(object):
    def __init__(self, username, password, jump_addr):
        self.username = username
        self.password = password
        self.jump_server = 'http://{}/api/v1'.format(jump_addr)
        self.token = self.get_token()
        self.header_info = {"Authorization": 'Bearer ' + self.token}

    def get_token(self):
        url = '{}/authentication/auth/'.format(self.jump_server)
        query_args = {
            "username": self.username,
            "password": self.password
        }
        response = requests.post(url, data=query_args, verify=False)
        return json.loads(response.text)['token']

    # 获取用户详情
    def get_user_info(self):
        url = '{}/users/users/'.format(self.jump_server)
        response = requests.get(url, headers=self.header_info)
        if response.status_code == 200:
            return response.json()
        else:
            return False

    #获取jump的admin用户id
    def get_user_jump_adminid(self):
        userlist = self.get_user_info()
        if userlist:
            for u in userlist:
                if u['username'] == 'admin':
                    return u['id']
            return False
        else:
            return False

    # 资产列表
    def assets_get(self):
        url = '{}/assets/assets/'.format(self.jump_server)
        response = requests.get(url, headers=self.header_info)
        if response.status_code == 200:
            return response.json()
        else:
            return False

    # 通过hostname获取资产id
    def get_assets_id(self, hostname):
        url = '{}/assets/assets/'.format(self.jump_server)
        try:
            response = requests.get(url, headers=self.header_info)
            if response.status_code != 200:
                return False
            flog = True
            for assets_info in response.json():
                if assets_info['hostname'] == hostname:
                    return assets_info['id']
                else:
                    flog = False
            return flog
        except Exception as e:
            print(e)
            return False

    # 通过hostid获取资产id
    def get_hostid_assets(self, host_id):
        url = '{}/assets/assets/'.format(self.jump_server)
        try:
            response = requests.get(url, headers=self.header_info)
            if response.status_code != 200:
                return False
            flog = True
            for assets_info in response.json():
                if assets_info['public_ip'] == host_id:
                    return assets_info['id']
                else:
                    flog = False
            return flog
        except Exception as e:
            print(e)
            return False

    # 通过节点路径 获取节点id
    def nodes_get(self, full_value):
        url = '{}/assets/nodes/'.format(self.jump_server)
        try:
            response = requests.get(url, headers=self.header_info).json()
            flog = True
            for node_info in response:
                if node_info['full_value'] == full_value:
                    return node_info['id']
                else:
                    flog = False
            return flog
        except Exception as  e:
            print('获取节点异常')
            return False

    # 添加资产
    def assets_post(self, hostname, ip, platform, full_value, host_id):
        url = '{}/assets/assets/'.format(self.jump_server)

        # nodes = self.nodes_get('/Default/test')
        nodes = self.nodes_get(full_value)
        if not nodes:
            return

        root_user = self.admin_root()
        if not root_user:
            root_user = ""
        data_info = {
            "hostname": hostname,
            "ip": ip,
            "public_ip": host_id,
            "is_active": True,
            "platform": platform,
            "admin_user": root_user,
            "nodes": [nodes]
        }
        response = requests.post(url, headers=self.header_info, data=data_info)
        if response.status_code != 200:
            return response.json()
        else:
            return False

    # 删除主机
    def assets_del(self, host_id):
        # assets_id=self.get_assets_id(hostname)
        assets_id = self.get_hostid_assets(host_id)
        if not assets_id:
            return False
        url = '{}/assets/assets/{}/'.format(self.jump_server, assets_id)

        response = requests.delete(url, headers=self.header_info)
        if response.status_code in [204, 200]:
            return True
        else:
            return False

    # 更新主机
    def assets_up(self, hostname, ip, full_value, host_id):
        '81272130-d1f4-410e-8c52-41370357789f'
        # assets_id = self.get_assets_id(hostname)
        assets_id = self.get_hostid_assets(host_id)
        if not assets_id:
            return False
        nodes = self.nodes_get(full_value)
        if not nodes:
            return False
        url = '{}/assets/assets/{}/'.format(self.jump_server, assets_id)
        data_info = {
            'id': assets_id,
            'hostname': hostname,
            'ip': ip,
            'platform': "Linux",
            'public_ip': host_id,
            'nodes': [nodes],
            "is_active": True,
        }
        response = requests.put(url, headers=self.header_info, data=data_info)
        if response.status_code == 200:
            return response.json()
        else:
            return False

    # 获取操作日志列表
    def operate_logs(self):
        url = '{}/audits/operate-logs/'.format(self.jump_server)
        response = requests.get(url, headers=self.header_info)
        if response.status_code == 200:
            return response.json()
        else:
            return False

    # 获取命令记录列表
    def terminal_commands(self):
        '/terminal/commands/'
        url = '{}/terminal/commands/'.format(self.jump_server)
        response = requests.get(url, headers=self.header_info)
        if response.status_code == 200:
            return response.json()
        else:
            return False

    # 管理用户列表
    def admin_user_list(self):
        '/assets/admin-users/'
        url = '{}/assets/admin-users/'.format(self.jump_server)
        response = requests.get(url, headers=self.header_info)
        if response.status_code == 200:
            return response.json()
        else:
            return False

    # 返回root用户id
    def admin_root(self):
        userlist = self.admin_user_list()
        flog = False
        for u in userlist:
            if u['name'] == 'root':
                return u['id']
        return flog

    # 返回系统用户
    def system_users_list(self):
        url = '{}/assets/system-users/'.format(self.jump_server)
        response = requests.get(url, headers=self.header_info)
        if response.status_code == 200:
            return response.json()
        else:
            return False

    # 获取系统用户id
    def system_user_getid(self):
        userlist = self.system_users_list()
        if userlist:
            for u in userlist:
                if u['name'] == 'root':
                    return u['id']
            return False
        else:
            return False

    # 创建管理用户
    def assets_admin_users_create(self,private_key):

        url = '{}/assets/admin-users/'.format(self.jump_server)
        data_info = {
            "name": 'root',
            "username": 'root',
            'password': '123456',
            'private_key': private_key
        }
        response = requests.post(url, headers=self.header_info, data=data_info, verify=False)
        return json.loads(response.text)

    # 创建系统用户
    def assets_system_users_create(self,private_key):
        url = '{}/assets/system-users/'.format(self.jump_server)
        data_info = {
            "name": 'root',
            "username": 'root',
            'password': '123456',
            'private_key': private_key
        }
        response = requests.post(url, headers=self.header_info, data=data_info, verify=False)
        return json.loads(response.text)

    # 创建授权规则
    def perms_asset_permissions_create(self):

        url = '{}/perms/asset-permissions/'.format(self.jump_server)
        nodes = self.nodes_get('/Default')
        if not nodes:
            return False

        admin_user = self.get_user_jump_adminid()
        if not admin_user:
            return False

        system_root_user = self.system_user_getid()
        if not system_root_user:
            return False

        data_info = {
            "name": 'grant_test',
            "is_active": True,
            'users': [admin_user],
            'nodes': [nodes],
            'system_users': [system_root_user],
            "actions": ["all", "connect", "upload_file", "download_file", "updownload", "clipboard_copy",
                        "clipboard_paste", "clipboard_copy_paste"]
        }
        response = requests.post(url, headers=self.header_info, data=data_info, verify=False)
        return json.loads(response.text)


private_key_dic={
    '10.150.0.52':'''-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA2Y'''
    '10.150.0.54':'''-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAqt'''
    '10.150.0.55':'''-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAnt'''
    '10.150.0.56':'''-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA'''
    '10.150.0.57':'''-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA'''
    '10.150.0.58':'''-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA'''
    '10.150.0.59':'''-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA'''
    '10.150.0.60':'''-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ'''
    '10.150.0.61':'''-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ'''
    '10.150.0.62':'''-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQE'''
    '10.150.0.63':'''-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCA'''
}

for k,v in private_key_dic.items():
    try:
        jobj = JumpApi('admin', 'jumpserxxxx', '{}:8080'.format(k))
        print(jobj.assets_admin_users_create(v))
        print(jobj.assets_system_users_create(v))
        print(jobj.perms_asset_permissions_create())
    except Exception as e:
        print("{} 连接异常".format(k))

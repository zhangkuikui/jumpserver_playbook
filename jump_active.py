#-*-coding:utf8-*-
import json
import requests
import time
import random
import string



class JumpApi(object):
    def __init__(self,username,password,jump_addr):
        self.username=username
        self.password=password
        self.jump_server = 'http://{}/api/v1'.format(jump_addr)
        self.token=self.get_token()
        self.header_info = { "Authorization": 'Bearer ' + self.token }

    def get_token(self):
        url = '{}/authentication/auth/'.format(self.jump_server)
        query_args = {
            "username": self.username,
            "password": self.password
        }
        response = requests.post(url, data=query_args, verify=False)
        print(response.text)
        return json.loads(response.text)['token']

    # 获取用户详情
    def get_user_info(self):
        url = '{}/users/users/'.format(self.jump_server)
        response = requests.get(url, headers=self.header_info)
        if response.status_code==200:
            return response.json()
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
    def get_assets_id(self,hostname):
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

    #通过hostid获取资产id
    def get_hostid_assets(self,host_id):
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
    def nodes_get(self,full_value):
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

    #添加资产
    def assets_post(self,hostname,ip,platform,full_value,host_id):
        url = '{}/assets/assets/'.format(self.jump_server)

        # nodes = self.nodes_get('/Default/test')
        nodes = self.nodes_get(full_value)
        if not nodes:
            return

        root_user=self.admin_root()
        if not root_user:
            root_user=""
        data_info = {
            "hostname": hostname,
            "ip": ip,
            "public_ip":host_id,
            "is_active": True,
            "platform": platform,
            "admin_user": root_user,
            "nodes": [nodes]
        }
        response = requests.post(url, headers=self.header_info, data=data_info)
        if response.status_code != 200:
            return  response.json()
        else:
            return False

    # 删除主机
    def assets_del(self,host_id):
        # assets_id=self.get_assets_id(hostname)
        assets_id=self.get_hostid_assets(host_id)
        if not assets_id:
            return False
        url = '{}/assets/assets/{}/'.format(self.jump_server,assets_id)

        response = requests.delete(url, headers=self.header_info)
        if response.status_code in [204,200]:
            return True
        else:
            return False

    #更新主机
    def assets_up(self,hostname,ip,full_value,host_id):
        '81272130-d1f4-410e-8c52-41370357789f'
        # assets_id = self.get_assets_id(hostname)
        assets_id = self.get_hostid_assets(host_id)
        if not assets_id:
            return False
        nodes = self.nodes_get(full_value)
        if not nodes:
            return False
        url = '{}/assets/assets/{}/'.format(self.jump_server,assets_id)
        data_info={
            'id':assets_id,
            'hostname':hostname,
            'ip':ip,
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

    #获取命令记录列表
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

    def jump_admin_chpass(self,jump_admin_id):
        url = '{}/users/users/{}/password/'.format(self.jump_server,jump_admin_id)
        data_info = {
            'password': "jumpserver",
        }
        response = requests.put(url, headers=self.header_info, data=data_info)
        if response.status_code == 200:
            print(response.json())
            return response.json()
        else:
            return False

#jobj = JumpApi('admin', 'xxx', '10.150.0.52:8080')
jobj = JumpApi('admin', 'xxx', '10.150.0.54:8080')
#jobj = JumpApi('admin', 'xxx', '172.16.1.1:8080')
#jobj = JumpApi('admin', 'xxx', '127.0.0.1:8080')
# print(jobj.get_user_info()) # 8dd0bfd0-031d-4415-816f-54edba56abfc
# jobj.jump_admin_chpass('8dd0bfd0-031d-4415-816f-54edba56abfc') # pbkdf2_sha256$216000$zd8d8rnGZtcH$qWnf5ROPfxjwBSiQcb3x4Gm5q9+n0LGqGe7ECmSskAo=

# Copyright (c) 2014 Mirantis Inc.
#
# Licensed under the Apache License, Version 2.0 (the License);
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an AS IS BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import sqlalchemy

from cloudferrylib.base import identity
from keystoneclient.v2_0 import client as keystone_client
from utils import Postman, Templater, GeneratorPassword

NOVA_SERVICE = 'nova'


class KeystoneIdentity(identity.Identity):
    """The main class for working with Openstack Keystone Identity Service."""

    def __init__(self, config):
        super(KeystoneIdentity, self).__init__()
        self.config = config
        self.keystone_client = self.get_client()
        self.keystone_db_conn_url = self.compose_keystone_db_conn_url()
        if 'mail' in self.config:
            self.postman = Postman(**self.config['mail'])
        else:
            self.postman = None
        self.templater = Templater()
        self.generator = GeneratorPassword()

    def read_info(self):
        resource = {'tenants': self.get_tenants_list(),
                    'users': self.get_users_list(),
                    'roles': self.get_roles_list(),
                    'user_tenants_roles': self.__get_user_tenants_roles()}
        if not self.config['generate_passwd']:
            resource['user_passwords'] = self.__get_user_passwords()
        return resource

    def deploy(self, resource):
        self.__deploy_tenants(resource['tenants'])
        self.__deploy_roles(resource['roles'])
        self.__deploy_users(resource['users'], resource['tenants'])
        if not self.config['generate_passwd']:
            self.__upload_user_passwords(resource['users'], resource['user_passwords'])
        self.__upload_user_tenant_roles(resource['user_tenants_roles'])

    def __deploy_users(self, users, tenants):
        tenant_list = self.get_tenants_list()
        template = 'templates/email.html'
        for user in users:
            tenant_name = [tenant.name for tenant in tenants if tenant.id == user.tenantId][0]
            tenant_id = [tenant.id for tenant in tenant_list if tenant.name == tenant_name]
            password = self.__generate_password() if self.config['generate_passwd'] else 'password'
            self.create_user(user.name, self.__generate_password(), user.email, tenant_id)
            if self.config['generate_passwd']:
                self.__send_msg(user.email,
                                'New password notification',
                                self.__render_template(template,
                                                       {'name': user.name,
                                                        'password': password}))

    def __deploy_roles(self, roles):
        for role in roles:
            self.create_role(role.name)

    def __deploy_tenants(self, tenants):
        for tenant in tenants:
            self.create_tenant(tenant.name, tenant.description)

    def get_client(self):
        """ Getting keystone client """

        ks_client_for_token = keystone_client.Client(
            username=self.config["user"],
            password=self.config["password"],
            tenant_name=self.config["tenant"],
            auth_url="http://" + self.config["host"] + ":35357/v2.0/")

        return keystone_client.Client(
            token=ks_client_for_token.auth_ref["token"]["id"],
            endpoint="http://" + self.config["host"] + ":35357/v2.0/")

    def get_service_name_by_type(self, service_type):
        """Getting service_name from keystone. """

        for service in self.get_services_list():
            if service.type == service_type:
                return service.name
        return NOVA_SERVICE

    def get_public_endpoint_service_by_id(self, service_id):
        """Getting endpoint public URL from keystone. """

        for endpoint in self.keystone_client.endpoints.list():
            if endpoint.service_id == service_id:
                return endpoint.publicurl

    def get_service_id(self, service_name):
        """Getting service_id from keystone. """

        for service in self.get_services_list():
            if service.name == service_name:
                return service.id

    def get_endpoint_by_service_name(self, service_name):
        """ Getting endpoint public URL by service name from keystone. """

        service_id = self.get_service_id(service_name)
        return self.get_public_endpoint_service_by_id(service_id)

    def get_tenant_by_name(self, tenant_name):
        """ Getting tenant by name from keystone. """

        for tenant in self.get_tenants_list():
            if tenant.name == tenant_name:
                return tenant

    def get_tenant_by_id(self, tenant_id):
        """ Getting tenant by id from keystone. """

        return self.keystone_client.tenants.get(tenant_id)

    def get_services_list(self):
        """ Getting list of available services from keystone. """

        return self.keystone_client.services.list()

    def get_tenants_list(self):
        """ Getting list of tenants from keystone. """

        return self.keystone_client.tenants.list()

    def get_users_list(self):
        """ Getting list of users from keystone. """

        return self.keystone_client.users.list()

    def get_roles_list(self):
        """ Getting list of available roles from keystone. """

        return self.keystone_client.roles.list()

    def create_role(self, role_name):
        """ Create new role in keystone. """

        self.keystone_client.roles.create(role_name)

    def create_tenant(self, tenant_name, description=None, enabled=True):
        """ Create new tenant in keystone. """

        self.keystone_client.tenants.create(tenant_name=tenant_name,
                                            description=description,
                                            enabled=enabled)

    def create_user(self, name, password=None, email=None, tenant_id=None,
                    enabled=True):
        """ Create new user in keystone. """

        return self.keystone_client.users.create(name=name,
                                                 password=password,
                                                 email=email,
                                                 tenant_id=tenant_id,
                                                 enabled=enabled)

    def update_tenant(self, tenant_id, tenant_name=None, description=None,
                      enabled=None):
        """Update a tenant with a new name and description."""

        return self.keystone_client.tenants.update(tenant_id,
                                                   tenant_name=tenant_name,
                                                   description=description,
                                                   enabled=enabled)

    def update_user(self, user, **kwargs):
        """Update user data.

        Supported arguments include ``name``, ``email``, and ``enabled``.
        """

        return self.keystone_client.users.update(user, **kwargs)

    def get_auth_token_from_user(self):
        return self.keystone_client.auth_token_from_user

    def compose_keystone_db_conn_url(self):

        """ Compose keystone database connection url for SQLAlchemy """

        return '{}://{}:{}@{}/keystone'.format(self.config['identity']['connection'],
                                               self.config['user'],
                                               self.config['password'],
                                               self.config['host'])

    def __get_user_passwords(self):
        info = {}
        with sqlalchemy.create_engine(self.keystone_db_conn_url).begin() as connection:
            for user in self.get_users_list():
                for password in connection.execute(sqlalchemy.text("SELECT password FROM user WHERE id = :user_id"),
                                                   user_id=user.id):
                    info[user.name] = password[0]
        return info

    def __get_user_tenants_roles(self):
        roles = {}
        tenants = self.get_tenants_list()
        for user in self.get_users_list():
            for tenant in tenants:
                roles[user.name][tenant.name] = self.keystone_client.roles_for_user(user.id, tenant.id)
        return roles

    def __upload_user_passwords(self, users, user_passwords):
        with sqlalchemy.create_engine(self.keystone_db_conn_url).begin() as connection:
            for user in self.keystone_client.users.list():
                if user.name in users:
                    connection.execute(sqlalchemy.text("UPDATE user SET password = :password WHERE id = :user_id"),
                                       user_id=user.id,
                                       password=user_passwords[user.name])

    def __upload_user_tenant_roles(self, user_tenants_roles):
        users_id = {user.name: user.id for user in self.get_users_list()}
        tenants_id = {tenant.name: tenant.id for tenant in self.get_tenants_list()}
        roles_id = {role.name: role.id for role in self.get_roles_list()}
        for user in user_tenants_roles:
            for tenant in user_tenants_roles[user]:
                for role in user_tenants_roles[user][tenant]:
                    self.keystone_client.roles.add_user_role(users_id[user], roles_id[role], tenants_id[tenant])

    def __generate_password(self):
        return self.generator.get_random_password()

    def __send_msg(self, to, subject, msg):
        if self.postman:
            with self.postman as p:
                p.send(to, subject, msg)

    def __render_template(self, name_file, args):
        if self.templater:
            return self.templater.render(name_file, args)
        else:
            return None

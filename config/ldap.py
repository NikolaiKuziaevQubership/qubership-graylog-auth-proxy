# Copyright 2024-2025 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

import common.log as log
from config.utils import str_to_bool, get_password

logger = log.get_logger(__name__)


class LDAPConfig:

    def __init__(self, url, starttls, over_ssl, ca_cert_path, cert_path, key_path, insecure_skip_verify,
                 disable_referrals, basedn, filter, binddn,
                 plain_password, htpasswd, realm,
                 requests_timeout):
        self.url = url
        self.timeout = requests_timeout
        self.starttls = str_to_bool(starttls)
        self.over_ssl = str_to_bool(over_ssl)
        self.ca_cert_path = ca_cert_path
        self.cert_path = cert_path
        self.key_path = key_path
        self.insecure_skip_verify = str_to_bool(insecure_skip_verify)
        self.disable_referrals = str_to_bool(disable_referrals)
        self.basedn = basedn
        self.template = filter
        self.binddn = binddn
        self.bind_password = get_password(plain_password, htpasswd)
        self.realm = realm

    def verify_config(self) -> bool:
        if self.url is None or not self.url:
            logger.error('Invalid LDAP config: URL is empty')
            return False
        if self.basedn is None or not self.basedn:
            logger.error('Invalid LDAP config: BaseDN is empty')
            return False
        if self.binddn is None or not self.binddn:
            logger.error('Invalid LDAP config: BindDN is empty')
            return False
        if self.starttls or self.over_ssl:
            if self.insecure_skip_verify:
                logger.warning('Skipping verification of certificates from LDAP server is enabled')
            else:
                if self.ca_cert_path is None or not self.ca_cert_path:
                    logger.error('Invalid LDAP config: Set CA certificate if you want to use STARTTLS or LDAP over SSL')
                    return False
                if not os.path.exists(self.ca_cert_path):
                    logger.error('Invalid LDAP config: Path to the CA certificate is incorrect')
                    return False
            if self.cert_path is not None and self.cert_path:
                if not os.path.exists(self.cert_path):
                    logger.error('Invalid LDAP config: Path to the client certificate is incorrect')
                    return False
            if self.key_path is not None and self.key_path:
                if not os.path.exists(self.key_path):
                    logger.error('Invalid LDAP config: Path to the private key file is incorrect')
                    return False
        return True

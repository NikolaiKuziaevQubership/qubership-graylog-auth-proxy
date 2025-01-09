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
from config.utils import str_to_bool

logger = log.get_logger(__name__)


class CommonConfig:

    def __init__(self, host, port, metrics_port, tls_enabled, cert_path, key_path, cookie_name):
        self.proxy_host = host
        self.proxy_port = port
        self.proxy_metrics_port = metrics_port
        self.tls_enabled = str_to_bool(tls_enabled)
        self.proxy_scheme = "http"
        if self.tls_enabled:
            self.proxy_scheme = "https"
        self.cert_path = cert_path
        self.key_path = key_path
        self.cookie_name = cookie_name

    def verify_config(self) -> bool:
        if self.cookie_name is None or not self.cookie_name:
            logger.error('Invalid common config: cookie name is empty')
            return False
        if self.tls_enabled:
            if self.cert_path is not None and self.cert_path:
                if not os.path.exists(self.cert_path):
                    logger.error('Invalid common config: Path to the certificate file for the proxy is incorrect')
                    return False
            else:
                logger.error('Invalid common config: Path to the certificate file for the proxy must not be empty '
                             'if the proxy is started in the secure mode')
                return False
            if self.key_path is not None and self.key_path:
                if not os.path.exists(self.key_path):
                    logger.error('Invalid common config: Path to the private key file for the proxy is incorrect')
                    return False
            else:
                logger.error('Invalid common config: Path to the private key file for the proxy must not be empty '
                             'if the proxy is started in the secure mode')
                return False
        return True

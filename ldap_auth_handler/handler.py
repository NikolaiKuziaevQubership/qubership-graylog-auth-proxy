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

import datetime
import base64
import time
from urllib.parse import urljoin

import requests

import common.log as log
import logging

from ldap.filter import escape_filter_chars

from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler

import common.session as session
import common.vars as common_vars
from common.graylog import graylog_handle
from config.common_config import CommonConfig
from config.graylog import GraylogConfig
from config.ldap import LDAPConfig
from ldap_auth_handler.ldap_connector import ldap_auth_handle

logger = log.get_logger(__name__)
logging.getLogger("urllib3").setLevel(logging.ERROR)


class LDAPAuthHandler(BaseHTTPRequestHandler):

    @classmethod
    def set_common_params(cls, params: CommonConfig):
        cls.common_params = params

    def get_common_params(self) -> CommonConfig:
        return self.common_params

    @classmethod
    def set_auth_params(cls, params: LDAPConfig):
        cls.ldap_params = params

    def get_auth_params(self) -> LDAPConfig:
        return self.ldap_params

    @classmethod
    def set_graylog_params(cls, params: GraylogConfig):
        cls.graylog_params = params

    def get_graylog_params(self) -> GraylogConfig:
        return self.graylog_params

    @classmethod
    def set_user(cls, user: str):
        cls.user = user

    def get_user(self) -> str:
        return self.user

    @classmethod
    def set_passwd(cls, passwd: str):
        cls.passwd = passwd

    def get_passwd(self) -> str:
        return self.passwd

    @classmethod
    def set_auth_cookie_exist(cls, auth_cookie_exist: bool):
        cls.auth_cookie_exist = auth_cookie_exist

    def get_auth_cookie_exist(self) -> bool:
        return self.auth_cookie_exist

    def get_cookie(self, name):
        cookies = self.headers.get('Cookie')
        if cookies:
            auth_cookie = SimpleCookie(cookies).get(name)
            if auth_cookie:
                return auth_cookie.value
            else:
                return None
        else:
            return None

    @staticmethod
    def set_cookie(cookie, cookie_name, cookie_value, max_age=3600, expires_hours=1):
        cookie[cookie_name] = cookie_value
        cookie[cookie_name]['path'] = '/'
        cookie[cookie_name]['max-age'] = max_age
        expires = datetime.datetime.utcnow() + datetime.timedelta(hours=expires_hours)
        cookie[cookie_name]['expires'] = expires.strftime("%a, %d %b %Y %H:%M:%S GMT")
        return cookie

    def send_resp_headers(self, resp, cookies=None):
        if cookies is not None:
            for c in cookies:
                c_key, c_value = str(cookies[c]).split(':', 1)
                self.send_header(c_key, c_value.strip())
        resp_headers = resp.headers
        for key in resp_headers:
            if key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding',
                           'transfer-encoding', 'content-length', 'Content-Length']:
                self.send_header(key, resp_headers[key])
        self.send_header('Content-Length', str(len(resp.content)))
        self.end_headers()

    def parse_headers(self):
        req_header = {}
        for i, j in self.headers.items():
            req_header[i] = j
        req_header['X-Forwarded-For'] = common_vars.PROXY_CONTAINER_NAME
        if self.user != common_vars.DEFAULT_ADMIN_USER or 'sessions' in self.path:
            req_header.pop('Authorization', None)
            req_header.pop('authorization', None)
            req_header['X-Forwarded-User'] = self.user
        return req_header

    def send_response_with_headers(self, resp):
        self.send_response(resp.status_code)
        if not self.auth_cookie_exist:
            session_id = session.get_session_id_by_username(self.user)
            if session_id is None:
                session_id = session.create_new_session(self.user)
            c = SimpleCookie()
            # expires in 1 hour
            c = self.set_cookie(c, self.common_params.cookie_name, session_id, max_age=3600, expires_hours=1)
            self.send_resp_headers(resp, c)
        else:
            self.send_resp_headers(resp)

    def auth_handle(self):
        logger.debug('Performing authorization')
        auth_header = self.headers.get('Authorization')
        auth_cookie = self.get_cookie(self.common_params.cookie_name)
        self.set_auth_cookie_exist(False)

        if auth_cookie is not None and auth_cookie != '':
            auth_header = session.get_username_by_session_id(auth_cookie)
            self.set_auth_cookie_exist(True)
            logger.debug(f"Using session ID from cookie {self.common_params.cookie_name}")
        else:
            logger.debug("Using username/password from authorization header")

        if self.auth_cookie_exist:
            self.set_user(auth_header)
            # Continue request processing with username found by session ID
            return True

        if auth_header is None or not auth_header.lower().startswith('basic '):
            self.send_response(401)
            self.send_header('WWW-Authenticate', f'Basic realm="{self.ldap_params.realm}"')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()

            return False

        logger.debug('Decoding credentials')

        try:
            auth_decoded = base64.b64decode(auth_header[6:])
            auth_decoded = auth_decoded.decode("utf-8")
            user, passwd = auth_decoded.split(':', 1)
        except Exception as e:
            self.auth_failed(str(e))
            return False

        self.set_user(escape_filter_chars(user))
        self.set_passwd(passwd)

        # Continue request processing
        return True

    def auth_and_graylog_handle(self):
        logger.debug('Initializing basic auth handler')
        if not self.auth_handle():
            # request already processed, auth wasn't successful
            return False
        # LDAP auth, creating/updating of users and sharing of streams happen only for the first time in a session
        # and only for not a default Graylog admin user
        if self.user != common_vars.DEFAULT_ADMIN_USER and not self.auth_cookie_exist:
            member_of = ldap_auth_handle(self.ldap_params, self.user, self.passwd)
            if member_of is None or not member_of:
                self.auth_failed()
                return False
            graylog_handle(self.graylog_params, member_of, self.user)
        elif self.user == common_vars.DEFAULT_ADMIN_USER:
            logger.debug('Log in as default admin user: skip LDAP authentication')
        return True

    def do_HEAD(self):
        self.do_GET(body=False)
        return

    def do_GET(self, body=True):
        logger.debug(f"Start GET handling: {self.path}")
        start_time = time.time()
        try:
            if not self.auth_and_graylog_handle():
                return

            # Successfully authenticated user
            logger.debug('Trying to proxy to Graylog')
            req_headers = self.parse_headers()
            resp = requests.get(urljoin(self.graylog_params.url, self.path), headers=req_headers,
                                verify=self.graylog_params.verify, cert=self.graylog_params.cert,
                                timeout=self.graylog_params.timeout)
            self.send_response_with_headers(resp)
            msg = resp.text
            if body:
                self.wfile.write(msg.encode(encoding='UTF-8', errors='strict'))
        except Exception as e:
            self.auth_failed(str(e))
        current_exec_time = time.time() - start_time
        logger.debug(f'GET execution time: {current_exec_time}')
        common_vars.GET_REQUEST_DURATION.observe(current_exec_time)
        return

    def do_POST(self):
        logger.debug(f"Start POST handling: {self.path}")
        start_time = time.time()
        try:
            if not self.auth_and_graylog_handle():
                return

            # Successfully authenticated user
            logger.debug('Trying to proxy to Graylog')
            content_len = int(self.headers.get('content-length', 0))
            post_body = self.rfile.read(content_len)
            req_headers = self.parse_headers()
            resp = requests.post(urljoin(self.graylog_params.url, self.path), headers=req_headers, data=post_body,
                                 verify=self.graylog_params.verify, cert=self.graylog_params.cert,
                                 timeout=self.graylog_params.timeout)
            self.send_response_with_headers(resp)
            self.wfile.write(resp.content)
        except Exception as e:
            self.auth_failed(str(e))
        current_exec_time = time.time() - start_time
        logger.debug(f'POST execution time: {current_exec_time}')
        common_vars.POST_REQUEST_DURATION.observe(current_exec_time)
        return

    def do_PUT(self):
        logger.debug(f"Start PUT handling: {self.path}")
        start_time = time.time()
        try:
            if not self.auth_and_graylog_handle():
                return

            # Successfully authenticated user
            logger.debug('Trying to proxy to Graylog')
            content_len = int(self.headers.get('content-length', 0))
            put_body = self.rfile.read(content_len)
            req_headers = self.parse_headers()
            resp = requests.put(urljoin(self.graylog_params.url, self.path), headers=req_headers, data=put_body,
                                verify=self.graylog_params.verify, cert=self.graylog_params.cert,
                                timeout=self.graylog_params.timeout)
            self.send_response_with_headers(resp)
            self.wfile.write(resp.content)
        except Exception as e:
            self.auth_failed(str(e))
        current_exec_time = time.time() - start_time
        logger.debug(f'PUT execution time: {current_exec_time}')
        common_vars.PUT_REQUEST_DURATION.observe(current_exec_time)
        return

    def do_DELETE(self):
        logger.debug(f"Start DELETE handling: {self.path}")
        start_time = time.time()
        try:
            if not self.auth_and_graylog_handle():
                return

            # Successfully authenticated user
            logger.debug('Trying to proxy to Graylog')
            content_len = int(self.headers.get('content-length', 0))
            delete_body = self.rfile.read(content_len)
            req_headers = self.parse_headers()
            resp = requests.delete(urljoin(self.graylog_params.url, self.path), headers=req_headers, data=delete_body,
                                   verify=self.graylog_params.verify, cert=self.graylog_params.cert,
                                   timeout=self.graylog_params.timeout)
            self.send_response_with_headers(resp)
            self.wfile.write(resp.content)
        except Exception as e:
            self.auth_failed(str(e))
        current_exec_time = time.time() - start_time
        logger.debug(f'DELETE execution time: {current_exec_time}')
        common_vars.DELETE_REQUEST_DURATION.observe(current_exec_time)
        return

    # Log the error and complete the request with appropriate status
    def auth_failed(self, errmsg=None):
        if errmsg is not None:
            msg = f'Raised exception: {errmsg}'
        else:
            msg = 'Authentication failed'
        if self.graylog_params.url is not None and self.graylog_params.url:
            msg += f', Graylog url: {self.graylog_params.url}'
        if self.ldap_params.url is not None and self.ldap_params.url:
            msg += f', LDAP url: {self.ldap_params.url}'
        if self.user is not None and self.user:
            msg += f', user: {self.user}'
        logger.error(msg)
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="' + self.ldap_params.realm + '"')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()

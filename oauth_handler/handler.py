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

import base64
import datetime
import time

import requests

import common.log as log
import logging


from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler

import common.session as session
import common.vars as common_vars
from common.graylog import graylog_handle
from config.common_config import CommonConfig
from config.graylog import GraylogConfig
from config.oauth import OAuthConfig
from oauth_handler.oauth_connector import OAuthHTTPClient, check_state
from urllib.parse import urlparse, parse_qs, urljoin

logger = log.get_logger(__name__)
logging.getLogger("urllib3").setLevel(logging.ERROR)


class OAuthHandler(BaseHTTPRequestHandler):

    @classmethod
    def set_common_params(cls, params: CommonConfig):
        cls.common_params = params

    def get_common_params(self) -> CommonConfig:
        return self.common_params

    @classmethod
    def set_auth_params(cls, params: OAuthConfig):
        cls.oauth_params = params

    def get_auth_params(self) -> OAuthConfig:
        return self.oauth_params

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
            req_header['X-Forwarded-User'] = self.user
        return req_header

    def send_response_with_headers(self, resp):
        self.send_response(resp.status_code)
        if not self.get_auth_cookie_exist():
            session_id = session.get_session_id_by_username(self.user)
            if session_id is None:
                session_id = session.create_new_session(self.user)
            c = SimpleCookie()
            # expires in 1 hour
            c = self.set_cookie(c, self.common_params.cookie_name, session_id, max_age=3600, expires_hours=1)
            self.send_resp_headers(resp, c)
        else:
            self.send_resp_headers(resp)

    def cookie_handle(self):
        logger.debug('Performing authorization')
        auth_cookie = self.get_cookie(self.common_params.cookie_name)
        self.set_auth_cookie_exist(False)

        if auth_cookie is not None and auth_cookie != '':
            user = session.get_username_by_session_id(auth_cookie)
            if user is None or not user:
                logger.debug("There is no session assigned to this cookie. Initialize new authorization process")
                return False
            self.set_user(user)
            self.set_auth_cookie_exist(True)
            logger.debug(f"Using session ID from cookie {self.common_params.cookie_name}")
            return True
        else:
            logger.debug("There is no cookie in the request")
            return False

    def auth_and_graylog_handle(self):
        if self.cookie_handle():
            # cookie is present, authorization is not required
            return True
        # Handle Authorization header for API calls from the logging-operator
        auth_header = self.headers.get('Authorization')
        if auth_header is not None and auth_header:
            auth_decoded = base64.b64decode(auth_header[6:])
            auth_decoded = auth_decoded.decode("utf-8")
            user, passwd = auth_decoded.split(':', 1)
            if user == common_vars.DEFAULT_ADMIN_USER:
                self.set_user(user)
                logger.debug('Log in as default admin user: skip OAuth authentication')
                return True

        oauth_http_client = OAuthHTTPClient(self.oauth_params)
        parsed_url = urlparse(self.path)
        parsed_query = parse_qs(parsed_url.query)
        if parsed_url.path == self.oauth_params.redirect_uri_path:
            try:
                state = parsed_query.get('state', [''])
                if not check_state(state[0]):
                    logger.warn("State is not correct in the response during OAuth2 authentication")
                    self.send_response(302)
                    self.send_header('Location', '/')
                    self.end_headers()
                    return False
                code = parsed_query.get('code', [''])
                token = oauth_http_client.get_token(code[0])
                user, roles = oauth_http_client.get_user(token)
                self.set_user(user)
            except Exception as e:
                logger.warn(f"Error occurred during getting token and userinfo from the OAuth server: {e}")
                return False
            graylog_handle(self.graylog_params, roles, self.user)
        else:
            login_url = oauth_http_client.login()
            if login_url is not None:
                self.send_response(302)
                self.send_header('Location', login_url)
                self.end_headers()
                return False
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
    def auth_failed(self, errmsg=''):
        logger.error(errmsg)
        self.send_response(401)
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()

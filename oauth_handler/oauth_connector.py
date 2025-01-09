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

import secrets
import logging

import requests
from oauthlib.oauth2 import WebApplicationClient
import jsonpath_ng

from common import log
from config.oauth import OAuthConfig

logger = log.get_logger(__name__)
logging.getLogger("urllib3").setLevel(logging.ERROR)


oauth_session_data = dict()


def check_state(state: str) -> bool:
    if oauth_session_data is not None:
        saved_state = oauth_session_data.get('state', None)
        if saved_state is not None:
            return saved_state == state
    return False


class OAuthHTTPClient:
    def __init__(self, params: OAuthConfig):
        self.params = params

    def login(self):
        client = WebApplicationClient(self.params.client_id)
        oauth_session_data['state'] = secrets.token_urlsafe(16)

        url_to_redirect = client.prepare_request_uri(
            self.params.authorization_url,
            redirect_uri=self.params.redirect_uri,
            scope=[self.params.scopes],
            state=oauth_session_data['state'],
            allow_signup='false'
        )

        return url_to_redirect

    def get_token(self, code: str) -> str:
        client = WebApplicationClient(self.params.client_id)

        # Prepare body for request
        data = client.prepare_request_body(
            code=code,
            redirect_uri=self.params.redirect_uri,
            client_id=self.params.client_id,
            client_secret=self.params.client_secret
        )

        token_header = {'Content-Type': 'application/x-www-form-urlencoded'}
        response = requests.post(self.params.token_url, headers=token_header, data=data,
                                 verify=self.params.verify, cert=self.params.cert, timeout=self.params.timeout)
        if not response.ok:
            logger.error(f'Error occurred during requesting the Access Token with code {response.status_code}')

        client.parse_request_body_response(response.text)

        token = client.token.get('access_token', None)
        if token is None or not token:
            logger.error("There is no Access Token in the response from the OAuth server")
            return ""

        return token

    def get_user(self, token: str) -> (str, list[str]):
        if not token:
            logger.error("Access Token is empty")
            return "", []
        header = {'Authorization': f'Bearer {token}'}

        response = requests.get(self.params.userinfo_url, headers=header,
                                verify=self.params.verify, cert=self.params.cert, timeout=self.params.timeout)
        if not response.ok:
            logger.error(f'Error occurred during requesting userinfo with code {response.status_code}')

        json_dict = response.json()

        user_expr = jsonpath_ng.parse(self.params.user_jsonpath)
        user_list = user_expr.find(json_dict)
        if len(user_list) > 0:
            user = user_list[0].value
        else:
            logger.error(f"No users were found using this pattern: {self.params.user_jsonpath}")
            return "", []
        roles_expr = jsonpath_ng.parse(self.params.roles_jsonpath)
        roles = [match.value for match in roles_expr.find(json_dict)]

        return user, roles

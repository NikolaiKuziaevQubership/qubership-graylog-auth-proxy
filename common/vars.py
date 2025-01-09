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

from jinja2 import Environment, select_autoescape, FileSystemLoader
from prometheus_client import Histogram

TEMPLATES_ENV = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape()
)
DEFAULT_ADMIN_USER = 'admin'
DEFAULT_ROLES = []
PROXY_CONTAINER_NAME = 'graylog_auth_proxy'

GET_REQUEST_DURATION = Histogram('get_requests_duration', 'GET requests response time in seconds')
POST_REQUEST_DURATION = Histogram('post_requests_duration', 'POST requests response time in seconds')
PUT_REQUEST_DURATION = Histogram('put_requests_duration', 'PUT requests response time in seconds')
DELETE_REQUEST_DURATION = Histogram('delete_requests_duration', 'DELETE requests response time in seconds')

GRAYLOG_API_USERS = '/api/users/'
GRAYLOG_API_STREAMS = '/api/streams/'
GRAYLOG_API_USERS_ID = '/api/users/id/'

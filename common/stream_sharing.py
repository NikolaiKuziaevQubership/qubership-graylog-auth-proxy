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

import json

import requests

import common.log as log

import common.vars as common_vars
from config.graylog import GraylogConfig

logger = log.get_logger(__name__)


def get_stream_id(streams_json_dict, stream_name):
    for s in streams_json_dict.get('streams', []):
        if s.get('title', '').lower() == stream_name.lower():
            return s.get('id')
    return None


def get_streams(params: GraylogConfig):
    get_headers = {
        'Accept': 'application/json',
        'X-Forwarded-User': params.admin_user
    }
    resp_get = requests.get(params.url_get_streams(), headers=get_headers,
                            verify=params.verify, cert=params.cert, timeout=params.timeout)
    if resp_get.status_code == 200:
        return json.loads(resp_get.text)
    else:
        logger.error(f'Error occurred during getting streams with code {resp_get.status_code}')
    return {}


def share_stream(params: GraylogConfig, stream_id, user_id, capability='view'):
    post_headers = {
        'X-Requested-By': 'Graylog API Browser',
        'X-Forwarded-User': params.admin_user
    }
    logger.debug(f'Share stream {stream_id} to user {user_id} with user {capability}')
    template_share_stream = common_vars.TEMPLATES_ENV.get_template("share-stream.json.j2")
    share_stream_json = template_share_stream.render(user_id=user_id,
                                                     capability=capability).replace("'", '"')
    share_stream_json_dict = json.loads(share_stream_json)
    url = params.url_stream_share(stream_id)
    resp_post = requests.post(url, headers=post_headers, json=share_stream_json_dict,
                              verify=params.verify, cert=params.cert, timeout=params.timeout)
    if resp_post.status_code != 200:
        logger.error(f'Error occurred during sharing stream with code {resp_post.status_code}')

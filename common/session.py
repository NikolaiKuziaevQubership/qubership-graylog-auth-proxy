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

sessions = dict()


def create_new_session(user):
    new_session_id = secrets.token_urlsafe(16)
    while sessions.get(new_session_id, None) is not None:
        new_session_id = secrets.token_urlsafe(16)
    session_id = new_session_id
    sessions[session_id] = user
    return session_id


def get_username_by_session_id(id):
    username = sessions.get(id, None)
    return username


def remove_existing_session(uname):
    for id, u in sessions.items():
        if u == uname:
            sessions.pop(id)
            return True
    return False


def get_session_id_by_username(uname):
    for id, u in sessions.items():
        if u == uname:
            return id
    return None

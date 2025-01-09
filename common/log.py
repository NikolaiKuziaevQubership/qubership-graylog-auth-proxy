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

import logging
import sys
FORMATTER = logging.Formatter("%(asctime)s — %(name)s — %(levelname)s — %(message)s")
DEFAULT_LOG_LEVEL = logging.INFO


def set_log_level(l: str):
    if l.upper() == "DEBUG":
        log_level = logging.DEBUG
    elif l.upper() == "INFO":
        log_level = logging.INFO
    elif l.upper() == "WARNING" or l.upper() == "WARN":
        log_level = logging.WARNING
    elif l.upper() == "ERROR":
        log_level = logging.ERROR
    elif l.upper() == "CRITICAL":
        log_level = logging.CRITICAL
    else:
        log_level = DEFAULT_LOG_LEVEL
    logging.basicConfig(level=log_level)


def get_console_handler():
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(FORMATTER)
    return console_handler


def get_logger(logger_name):
    logger = logging.getLogger(logger_name)
    logger.addHandler(get_console_handler())
    # with this pattern, it's rarely necessary to propagate the error up to parent
    logger.propagate = False
    return logger

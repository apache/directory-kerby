#!/usr/bin/env bash

# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CONF_DIR=$1
APP_MAIN=org.apache.kerby.kerberos.tool.admin.AdminRemoteTool

# Reset HAS_CONF_DIR if CONF_DIR not null
if [ "$CONF_DIR" != "" ]; then
  if [ ! -d "$CONF_DIR" ]; then
    echo "[ERROR] ${CONF_DIR} is not a directory"
    usage
  fi
else
  if [ "$HAS_CONF_DIR" != "" ] && [ -d "$HAS_CONF_DIR" ]; then
    CONF_DIR=${HAS_CONF_DIR}
  else
    echo "[ERROR] HAS_CONF_DIR is null or not a directory"
    exit
  fi
fi

# Load HAS environment variables
if [ -f "${CONF_DIR}/has-env.sh" ]; then
  . "${CONF_DIR}/has-env.sh"
fi

# Get HAS_HOME directory
bin=`dirname "$0"`
HAS_HOME=`cd ${bin}/..; pwd`
cd ${HAS_HOME}

for var in $*; do
  if [ X"$var" = X"-D" ]; then
    DEBUG="-Xdebug -Xrunjdwp:transport=dt_socket,address=8012,server=y,suspend=y"
  fi
done

echo "[INFO] conf_dir=$CONF_DIR"
HAS_OPTS="-DHAS_LOGFILE=admin-remote"

java ${DEBUG} -classpath target/lib/*:. ${HAS_OPTS} ${APP_MAIN} ${CONF_DIR}

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

usage()
{
  echo "Usage: sh bin/start-has.sh <conf_dir> <working_dir>"
  echo "    Example:"
  echo "        sh bin/start-has.sh conf work"
  exit
}

CONF_DIR=$1
WORK_DIR=$2
pid=/tmp/has.pid # Pid file to save pid numbers
APP_MAIN=org.apache.hadoop.has.server.HasServer

# Reset HAS_CONF_DIR and HAS_WORK_DIR if CONF_DIR or WORK_DIR not null
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

if [ "${WORK_DIR}" != "" ]; then
  if [ ! -d "$WORK_DIR" ]; then
    echo "[ERROR] ${WORK_DIR} is not a directory"
    usage
  fi
else
  if [ "$HAS_WORK_DIR" != "" ] && [ -d "$HAS_WORK_DIR" ]; then
    WORK_DIR=${HAS_WORK_DIR}
  else
    echo "[ERROR] HAS_WORK_DIR is null or not a directory"
    exit
  fi
fi

# Get HAS_HOME directory
bin=`dirname "$0"`
HAS_HOME=`cd ${bin}/..; pwd`
cd ${HAS_HOME}

for var in $*; do
  if [ X"$var" = X"-D" ]; then
    DEBUG="-Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=n"
  fi
done
args="$CONF_DIR $WORK_DIR"

echo "[INFO] conf_dir=$CONF_DIR"
echo "[INFO] work_dir=$WORK_DIR"

HAS_OPTS="$HAS_JVM_OPTS -DHAS_LOGFILE=has"

# Print a warning if has servers are already running
if [ -f ${pid} ]; then
  active=()
  while IFS='' read -r p || [ -n "$p" ]; do
    kill -0 ${p} >/dev/null 2>&1
    if [ $? -eq 0 ]; then
      active+=(${p})
    fi
  done < "$pid"

  count="${#active[@]}"

  if [ "$count" -gt 0 ]; then
    echo "[WARN] ${count} instance(s) of HAS server are already running."
  fi
fi

echo "Starting HAS server..."

# Start HAS server
java ${DEBUG} -classpath target/lib/*:. ${HAS_OPTS} ${APP_MAIN} -start ${args} > /dev/null 2>&1 &

mypid=$!

# Add mypid to pid file if start successfully
sleep 3
if [ "$mypid" -gt 0 ] && kill -0 "$mypid" > /dev/null 2>&1; then
  echo ${mypid} >> ${pid}
  echo "[SUCCESS] HAS server (pid: ${mypid}) has been started."
else
  echo "[ERROR] Failed to start HAS server."
  exit 1
fi

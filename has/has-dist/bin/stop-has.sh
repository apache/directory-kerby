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

OPERATION=$1
pid=/tmp/has.pid # Pid file

stop()
{
  if kill -0 ${to_stop} > /dev/null 2>&1; then
    echo "Stopping HAS server (pid: ${to_stop})..."
    kill ${to_stop}
    sleep 5
    if kill -0 ${pid} > /dev/null 2>&1; then
      echo "[WARN] HAS server still alive after 5 seconds, Trying to kill it by force."
      kill -9 ${to_stop}
    else
      echo "[SUCCESS] HAS server has been stopped."
    fi
  else
    echo "[INFO] Skipping HAS server (pid: ${to_stop}), because it is not running anymore."
  fi
}

case ${OPERATION} in

  (all)
    if [ -f "$pid" ]; then
      mv ${pid} ${pid}.tmp
      cat ${pid}.tmp | while read to_stop; do
        stop
      done < ${pid}.tmp
      rm ${pid}.tmp
    else
      echo "[INFO] No HAS server to stop."
    fi
  ;;

  (*)
    if [ -f "$pid" ]; then
      # Get latest pid number in pid file
      to_stop=$(tail -n 1 ${pid})

      if [ -z "$to_stop" ]; then
        rm ${pid} # If $to_stop is null, delete the pid file
        echo "[INFO] No HAS server to stop."
      else
        sed \$d ${pid} > ${pid}.tmp
        if [ $(wc -l < ${pid}.tmp) -eq 0 ]; then
          rm ${pid}.tmp ${pid} # If all stopped, clean up pid files
        else
          mv ${pid}.tmp ${pid}
        fi
        stop
      fi

    else
      echo "[INFO] No HAS server to stop."
    fi
  ;;
esac

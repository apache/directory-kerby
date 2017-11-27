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

BASE_DIR=$(cd `dirname $0`/..; pwd)

# 1. Start HAS server
echo "Start HAS server..."
sudo sh $BASE_DIR/bin/start-has.sh $BASE_DIR/conf $BASE_DIR/conf &
sleep 3s
cat nohup.log

# 2. Config Backend
echo "Config Backend..."
curl -X PUT "http://localhost:8091/has/v1/conf/configKdcBackend?backendType=json&dir=/tmp/has/jsonbackend"
sleep 2s

# 3. Set Realm
echo "Set Realm..."
curl -X PUT "http://localhost:8091/has/v1/conf/setKdcRealm?realm=EXAMPLE.COM"
sleep 2s

# 4. Start HAS
curl -X GET "http://localhost:8091/has/v1/kdcstart"
sleep 2s

# 5. Init HAS
echo "Init HAS..."
curl -o admin.keytab "http://host:8091/has/v1/kdcinit"
sleep 2s

# 6. Create Principals
echo "Create Principals..."
echo \
{\
    HOSTS: [\
        \{\"name\":\"nn\",\"hostRoles\":\"HDFS,YARN,HBASE,ZOOKEEPER\"\}, \
        \{\"name\":\"dn1\",\"hostRoles\":\"HDFS,YARN,HBASE,ZOOKEEPER\"\}, \
        \{\"name\":\"dn2\",\"hostRoles\":\"HDFS,YARN,HBASE,ZOOKEEPER\"\} \
    ] \
\} > hosts.txt
curl -T hosts.txt "http://localhost:8091/has/v1/admin/createprincipals"
sleep 2s

# 7. Get Host Roles List
echo "Get host roles list..."
curl -X GET "http://localhost:8091/has/v1/hostroles"
sleep 2s

# 8. Export keytab files
echo "Export keytab files..."
curl -o nn_keytab.zip "http://localhost:8091/has/v1/admin/exportkeytabs?host=nn"
curl -o dn1_keytab.zip "http://localhost:8091/has/v1/admin/exportkeytabs?host=dn1"
curl -o dn2_keytab.zip "http://localhost:8091/has/v1/admin/exportkeytabs?host=dn2"
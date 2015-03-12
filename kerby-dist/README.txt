# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

How to install kerby-server?

1. Set the absolute path of the directory:kerby-dist\kerby-server in kerby-dist\conf\wrapper.conf:
Change the value of wrapper.working.dir.(in the line 28)
e.g. 
wrapper.working.dir=C:\\Users\\hazel\\workspace\\directory-kerberos\\kerby-dist\\target\\
or
wrapper.working.dir=/home/hazel/workspace/directory-kerberos/kerby-dist/target

2.Every time you want to reinstall, just run:
mvn install

3.Then you can run or manage the service via the following scripts.
On windows:
bat/runConsole.bat,
bat/installService.bat,
bat/startService.bat,
bat/stopService.bat,
bat/uninstallService.bat in Windows.

On Linux:
bin/genConfig.sh
bin/installDaemonNoPriv.sh
bin/installDaemon.sh
bin/queryDaemon.sh
bin/runConsole.sh
bin/runHelloWorld.sh
bin/setenv.sh
bin/startDaemonNoPriv.sh
bin/startDaemon.sh
bin/stopDaemonNoPriv.sh
bin/stopDaemon.sh
bin/systemTrayIcon.sh
bin/uninstallDaemonNoPriv.sh
bin/uninstallDaemon.sh
bin/wrapper.sh


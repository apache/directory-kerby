/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.kerberos.tool.admin.remote.cmd;

import org.apache.kerby.has.client.HasAuthAdminClient;
import org.apache.kerby.kerberos.kerb.KrbException;

public class ExportKeytabsRemoteCmd extends AdminRemoteCmd {
    private static final String USAGE = "\nUsage: export_keytabs <host> [role]\n"
            + "\tExample:\n"
            + "\t\texport_keytabs host1 HDFS\n";

    public ExportKeytabsRemoteCmd(HasAuthAdminClient authHadmin) {
        super(authHadmin);
    }

    @Override
    public void execute(String[] items) throws KrbException {
        //TODO add save path option
        if (items.length < 2) {
            System.err.println(USAGE);
            return;
        }

        HasAuthAdminClient client = getAuthAdminClient();

        String host = items[1];
        String role = "";
        if (items.length >= 3) {
            role = items[2];
        }
        client.getKeytabByHostAndRole(host, role);
    }
}

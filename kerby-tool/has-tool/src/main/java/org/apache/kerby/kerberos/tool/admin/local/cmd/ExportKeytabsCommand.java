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
package org.apache.kerby.kerberos.tool.admin.local.cmd;

import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.server.admin.LocalHadmin;
import org.apache.kerby.has.server.web.HostRoleType;

public class ExportKeytabsCommand extends HadminCommand {
    private static final String USAGE = "\nUsage: export_keytabs <host> [role]\n"
            + "\tExample:\n"
            + "\t\texport_keytabs host1 HDFS\n";

    public ExportKeytabsCommand(LocalHadmin hadmin) {
        super(hadmin);
    }

    @Override
    public void execute(String[] items) throws HasException {
        if (items.length < 2) {
            System.err.println(USAGE);
            return;
        }
        String host = items[1];
        if (items.length >= 3) {
            exportKeytab(host, items[2]);
            return;
        }
        for (HostRoleType r : HostRoleType.values()) {
            exportKeytab(host, r.getName());
        }
    }

    public void exportKeytab(String host, String role) throws HasException {
        getHadmin().getKeytabByHostAndRole(host, role);
    }
}

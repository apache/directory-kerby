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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;

public class CreatePrincipalsRemoteCmd extends AdminRemoteCmd {
    private static final String USAGE = "\nUsage: create_principals [hostRoles-file]\n"
            + "\t'hostRoles-file' is a file with a hostRoles json string like:\n"
            + "\t\t{HOSTS: [ {\"name\":\"host1\",\"hostRoles\":\"HDFS\"}, "
            + "{\"name\":\"host2\",\"hostRoles\":\"HDFS,HBASE\"} ] }\n"
            + "\tExample:\n"
            + "\t\tcreate_principals hostroles.txt\n";

    public CreatePrincipalsRemoteCmd(HasAuthAdminClient authHadmin) {
        super(authHadmin);
    }

    @Override
    public void execute(String[] items) throws KrbException {
        //String param = items[0];
        if (items.length != 2) {
            System.err.println(USAGE);
            return;
        }

        File hostRoles = new File(items[1]);
        if (!hostRoles.exists()) {
            System.err.println("HostRoles file is not exists.");
            return;
        }

        HasAuthAdminClient client = getAuthAdminClient();

        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(hostRoles));
        } catch (FileNotFoundException e) {
            throw new KrbException("File not exist", e);
        }
        StringBuilder sb = new StringBuilder();
        String tempString;
        try {
            while ((tempString = reader.readLine()) != null) {
                sb.append(tempString);
            }
        } catch (IOException e) {
            throw new KrbException("Errors occurred when read line. ", e);
        }
        List<String> results = client.addPrincipalsByRole(sb.toString());
        if (results != null) {
            for (int i = 0; i < results.size(); i++) {
                System.out.println(results.get(i));
            }
        }
    }
}

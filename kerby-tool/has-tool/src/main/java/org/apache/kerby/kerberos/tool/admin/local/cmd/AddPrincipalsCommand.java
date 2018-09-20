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
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

public class AddPrincipalsCommand extends HadminCommand {

    private static final String USAGE = "\nUsage: create_principals [hostRoles-file]\n"
            + "\t'hostRoles-file' is a file with a hostRoles json string like:\n"
            + "\t\t{HOSTS: [ {\"name\":\"host1\",\"hostRoles\":\"HDFS\"}, "
            + "{\"name\":\"host2\",\"hostRoles\":\"HDFS,HBASE\"} ] }\n"
            + "\tExample:\n"
            + "\t\tcreate_principals hostroles.txt\n";

    public AddPrincipalsCommand(LocalHadmin hadmin) {
        super(hadmin);
    }

    @Override
    public void execute(String[] items) throws HasException {
        if (items.length != 2) {
            System.err.println(USAGE);
            return;
        }

        File hostRoles = new File(items[1]);
        if (!hostRoles.exists()) {
            throw new HasException("HostRoles file is not exists.");
        }
        try {
            StringBuilder sb;
            try (BufferedReader reader = new BufferedReader(new FileReader(hostRoles))) {
                sb = new StringBuilder();
                String tempString;
                while ((tempString = reader.readLine()) != null) {
                    sb.append(tempString);
                }
            }
            JSONArray hostArray = new JSONObject(sb.toString()).optJSONArray("HOSTS");
            if (hostArray == null) {
                throw new HasException("Failed to get HOSTS.");
            }
            for (int i = 0; i < hostArray.length(); i++) {
                JSONObject host = (JSONObject) hostArray.get(i);
                String[] roles = host.getString("hostRoles").split(",");
                for (String role : roles) {
                    System.out.println(getHadmin().addPrincByRole(host.getString("name"),
                            role.toUpperCase()));
                }
            }
        } catch (Exception e) {
            throw new HasException("Failed to execute creating principals, because : " + e.getMessage());
        }
    }
}

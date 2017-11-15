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
package org.apache.hadoop.has.tool.client.hadmin.remote.cmd;

import org.apache.hadoop.has.client.HasAdminClient;
import org.apache.hadoop.has.client.HasAuthAdminClient;
import org.apache.hadoop.has.common.HasException;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

public class HasRemoteCreatePrincipalsCmd extends HadminRemoteCmd {
    private static final String USAGE = "\nUsage: create_principals [hostRoles-file]\n"
            + "\t'hostRoles-file' is a file with a hostRoles json string like:\n"
            + "\t\t{HOSTS: [ {\"name\":\"host1\",\"hostRoles\":\"HDFS\"}, "
            + "{\"name\":\"host2\",\"hostRoles\":\"HDFS,HBASE\"} ] }\n"
            + "\tExample:\n"
            + "\t\tcreate_principals hostroles.txt\n";

    public HasRemoteCreatePrincipalsCmd(HasAdminClient hadmin, HasAuthAdminClient authHadmin) {
        super(hadmin, authHadmin);
    }

    @Override
    public void execute(String[] items) throws HasException {
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

        HasAdminClient hasAdminClient;
        if (getAuthHadmin() != null) {
            hasAdminClient = getAuthHadmin();
        } else {
            hasAdminClient = getHadmin();
        }

        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(hostRoles));
        } catch (FileNotFoundException e) {
            throw new HasException("File not exist", e);
        }
        StringBuilder sb = new StringBuilder();
        String tempString;
        try {
            while ((tempString = reader.readLine()) != null) {
                sb.append(tempString);
            }
        } catch (IOException e) {
            throw new HasException("Errors occurred when read line. ", e);
        }
        hasAdminClient.requestCreatePrincipals(sb.toString());
    }
}

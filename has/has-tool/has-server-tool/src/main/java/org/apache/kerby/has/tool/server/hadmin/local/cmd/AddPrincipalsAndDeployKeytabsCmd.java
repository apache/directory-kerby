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
package org.apache.kerby.has.tool.server.hadmin.local.cmd;


import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.server.admin.LocalHasAdmin;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class AddPrincipalsAndDeployKeytabsCmd extends HadminCmd {
    private static final String USAGE
        = "\nUsage: deploy_keytabs [HostRoles-File] [Where-to-Deploy] [SSH-Port] [UserName] [Password]\n"
        + "\tExample:\n"
        + "\t\tdeploy_keytabs hostroles.txt /etc/has/ 22 username password\n";

    public AddPrincipalsAndDeployKeytabsCmd(LocalHasAdmin hadmin) {
        super(hadmin);
    }

    @Override
    public void execute(String[] items) throws HasException {

        if (items.length < 5 || items.length > 6) {
            System.err.println(USAGE);
            return;
        }

        File hostfile = new File(items[1]);
        if (!hostfile.exists()) {
            throw new HasException("HostRoles file is not exists.");
        }
        String pathToDeploy = items[2];
        int port = Integer.valueOf(items[3]);
        String username = items[4];
        String password = "";
        if (items.length == 6) {
            password = items[5];
        }

        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(hostfile));
        } catch (FileNotFoundException e) {
            throw new HasException("The host roles file: " + hostfile + "is not exist. " + e.getMessage());
        }
        StringBuilder sb = new StringBuilder();
        String tempString;
        try {
            while ((tempString = reader.readLine()) != null) {
                sb.append(tempString);
            }
        } catch (IOException e) {
            throw new HasException("Failed to read file: " + e.getMessage());
        }
        JSONArray hostArray;
        try {
            hostArray = new JSONObject(sb.toString()).optJSONArray("HOSTS");
        } catch (JSONException e) {
            throw new HasException(e.getMessage());
        }
        for (int i = 0; i < hostArray.length(); i++) {
            JSONObject host;
            try {
                host = (JSONObject) hostArray.get(i);
            } catch (JSONException e) {
                throw new HasException(e.getMessage());
            }
            String hostname;
            try {
                hostname = host.getString("name");
            } catch (JSONException e) {
                throw new HasException(e.getMessage());
            }
            String[] roles;
            try {
                roles = host.getString("hostRoles").split(",");
            } catch (JSONException e) {
                throw new HasException(e.getMessage());
            }
            List<File> keytabs = new ArrayList<>();
            for (String role : roles) {
                // Add principal.
                System.out.println(getHadmin().addPrincByRole(hostname,
                    role.toUpperCase()));
                // Export keytab
                File keytab = new File(role + "-" + hostname + ".keytab");
                getHadmin().getKeytabByHostAndRole(hostname, role, keytab);

                keytabs.add(keytab);
            }

            JSch jsch = new JSch();
            Session session;
            try {
                session = jsch.getSession(username, hostname, port);
            } catch (JSchException e) {
                throw new HasException(e.getMessage());
            }
            session.setPassword(password);

            java.util.Properties config = new java.util.Properties();
            config.put("StrictHostKeyChecking", "no");
            session.setConfig(config);

            ChannelSftp channel;
            try {
                session.connect();
                channel = (ChannelSftp) session.openChannel("sftp");
                channel.connect();
            } catch (JSchException e) {
                throw new HasException("Failed to set the session: " + e.getMessage());
            }
            try {
                String path = "";
                String[] paths = pathToDeploy.split("/");
                for (i = 1; i < paths.length; i++) {
                    path = path + "/" + paths[i];

                    try {
                        channel.cd(path);
                    } catch (SftpException e) {
                        if (e.id == ChannelSftp.SSH_FX_NO_SUCH_FILE) {
                            channel.mkdir(path);
                        } else {
                            throw new HasException(e.getMessage());
                        }
                    }
                }
            } catch (SftpException e) {
                throw new HasException("Failed to mkdir path: " + e.getMessage());
            }

            for (File keytab : keytabs) {
                // Send the keytab to remote
                try {
                    channel.put(keytab.getAbsolutePath(), pathToDeploy + keytab.getName());
                } catch (SftpException e) {
                    throw new HasException("Failed to send the keytab file: " + keytab.getName());
                }
            }
            channel.disconnect();
        }
    }
}



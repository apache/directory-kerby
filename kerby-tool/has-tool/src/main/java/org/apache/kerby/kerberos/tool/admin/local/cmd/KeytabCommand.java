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


import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.server.admin.LocalHadmin;
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

public class KeytabCommand extends HadminCommand {
    private static final String KEYTAB_CREATE_USAGE
        = "\nUsage: keytab create [HostRoles-File]\n"
        + "\tAdd principals in backend.\n"
        + "\tExample:\n"
        + "\t\tkeytab create hostroles.txt\n";

    private static final String KEYTAB_DEPLOY_USAGE
        = "\nUsage: keytab deploy [HostRoles-File] [Where-to-Deploy] [SSH-Port] [UserName] [Password]\n"
        + "\tExport and deploy keytabs.\n"
        + "\tExample:\n"
        + "\t\tkeytab deploy hostroles.txt /etc/has/ 22 username password\n";

    private static final String KEYTAB_CREATE_DEPLOY_USAGE
        = "\nUsage: keytab create_deploy [HostRoles-File] [Where-to-Deploy] [SSH-Port] [UserName] [Password]\n"
        + "\tAdd principals, export and deploy keytabs.\n"
        + "\tExample:\n"
        + "\t\tkeytab create_deploy hostroles.txt /etc/has/ 22 username password\n";

    public KeytabCommand(LocalHadmin hadmin) {
        super(hadmin);
    }

    @Override
    public void execute(String[] items) throws HasException {

        if (items.length < 3) {
            System.err.println(KEYTAB_CREATE_USAGE);
            System.err.println(KEYTAB_DEPLOY_USAGE);
            System.err.println(KEYTAB_CREATE_DEPLOY_USAGE);
            return;
        }

        String cmd = items[1];

        File hostfile = new File(items[2]);
        if (!hostfile.exists()) {
            throw new HasException("Host roles file: " + items[2] + " is not exists.");
        }

        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(hostfile));
        } catch (FileNotFoundException e) {
            throw new HasException("The host roles file: " + hostfile
                + " is not exist. " + e.getMessage());
        }
        StringBuilder sb = new StringBuilder();
        String tempString;
        try {
            while ((tempString = reader.readLine()) != null) {
                sb.append(tempString);
            }
        } catch (IOException e) {
            throw new HasException("Failed to read file: " + e.getMessage());
        } finally {
            try {
                reader.close();
            } catch (IOException e) {
                throw new HasException(e.getMessage());
            }
        }
        JSONArray hostArray;
        try {
            hostArray = new JSONObject(sb.toString()).optJSONArray("HOSTS");
        } catch (JSONException e) {
            throw new HasException(e.getMessage());
        }
        if (hostArray == null) {
            throw new HasException("Failed to get HOSTS");
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

            if (cmd.equals("create")) {
                if (items.length != 3) {
                    System.err.println(KEYTAB_CREATE_USAGE);
                    return;
                }
                for (String role : roles) {
                    // Add principal.
                    System.out.println(getHadmin().addPrincByRole(hostname,
                        role.toUpperCase()));
                }
            } else if (cmd.equals("deploy") || cmd.equals("create_deploy")) {
                if (items.length < 6 || items.length > 7) {
                    if (cmd.equals("deploy")) {
                        System.err.println(KEYTAB_DEPLOY_USAGE);
                    } else {
                        System.err.println(KEYTAB_CREATE_DEPLOY_USAGE);
                    }
                    return;
                }
                String pathToDeploy = items[3];
                int port = Integer.parseInt(items[4]);
                String username = items[5];
                String password = "";
                if (items.length == 7) {
                    password = items[6];
                }
                List<File> keytabs = new ArrayList<>();
                for (String role : roles) {
                    if (cmd.equals("create_deploy")) {
                        // Add principal.
                        System.out.println(getHadmin().addPrincByRole(hostname,
                            role.toUpperCase()));
                    }

                    // Export keytab
                    File keytab = getHadmin().getKeytabByHostAndRole(hostname, role);

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
                    for (int j = 1; j < paths.length; j++) {
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
                    // Send the keytabs to remote
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
}



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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.has.client.HasAuthAdminClient;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

/**
 * Remote get principal cmd
 */
public class GetPrincipalRemoteCommand extends AdminRemoteCmd {
    private static final String USAGE = "Usage: getprinc principalName\n"
                                      + "\tExample:\n"
                                      + "\t\tgetprinc hello@TEST.COM\n";

    public GetPrincipalRemoteCommand(HasAuthAdminClient authHadmin) {
        super(authHadmin);
    }

    @Override
    public void execute(String[] items) throws KrbException {
        if (items.length < 2) {
            System.err.println(USAGE);
            return;
        }

        String clientPrincipalName = items[items.length - 1];
        String principalData = null;
        HasAuthAdminClient client = getAuthAdminClient();
        try {
            principalData = client.getPrincipal(clientPrincipalName);
        } catch (KrbException e) {
            System.err.println("Failed to get principal: " + clientPrincipalName + ". " + e.toString());
        }

        if (principalData == null) {
            return;
        } else {
            System.out.println("Principal is listed:");
            JSONObject principle;
            try {
                principle = new JSONObject(principalData);
            } catch (JSONException e) {
                throw new KrbException(e.getMessage());
            }
            try {
                System.out.println(
                        "Principal: " + principle.getString("Name") + "\n"
                                + "Expiration date: " + principle.getString("Expiration date") + "\n"
                                + "Created time: "
                                + principle.getString("Created time") + "\n"
                                + "KDC flags: " + String.valueOf(principle.getInt("KDC flags")) + "\n"
                                + "Key version: " + String.valueOf(principle.getInt("Key version")) + "\n"
                                + "Number of keys: " + String.valueOf(principle.getInt("Number of keys"))
                );
            } catch (JSONException e) {
                throw new KrbException(e.getMessage());
            }

            JSONObject keySet;
            try {
                keySet = principle.getJSONObject("Keys");
            } catch (JSONException e) {
                throw new KrbException(e.getMessage());
            }
            try {
                for (int keyCount = 0; keyCount < principle.getInt("Number of keys"); keyCount++) {
                    System.out.println("key: " + keySet.getString(String.valueOf(keyCount)));
                }
            } catch (JSONException e) {
                throw new KrbException(e.getMessage());
            }
        }
    }
}

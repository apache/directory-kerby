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
package org.apache.kerby.has.tool.client.hadmin.remote.cmd;

import org.apache.kerby.has.client.HasAdminClient;
import org.apache.kerby.has.client.HasAuthAdminClient;
import org.apache.kerby.has.common.HasException;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

public class HasRemoteGetHostRolesCmd extends HadminRemoteCmd {
    private static final String USAGE = "Usage: get_hostroles\n"
            + "\tExample:\n"
            + "\t\tget_hostroles\n";

    public HasRemoteGetHostRolesCmd(HasAdminClient hadmin, HasAuthAdminClient authHadmin) {
        super(hadmin, authHadmin);
    }

    @Override
    public void execute(String[] input) throws HasException {
        HasAdminClient hasAdminClient = getHadmin();
        String result = hasAdminClient.getHostRoles();

        if (result != null) {
            try {
                JSONArray hostRoles = new JSONArray(result);
                for (int i = 0; i < hostRoles.length(); i++) {
                    JSONObject hostRole = hostRoles.getJSONObject(i);
                    System.out.print("\tHostRole: " + hostRole.getString("HostRole")
                            + ", PrincipalNames: ");
                    JSONArray principalNames = hostRole.getJSONArray("PrincipalNames");
                    for (int j = 0; j < principalNames.length(); j++) {
                        System.out.print(principalNames.getString(j));
                        if (j == principalNames.length() - 1) {
                            System.out.println();
                        } else {
                            System.out.print(", ");
                        }
                    }
                }
            } catch (JSONException e) {
                throw new HasException("Errors occurred when getting the host roles.", e);
            }
        } else {
            throw new HasException("Could not get hostRoles.");
        }
    }

}

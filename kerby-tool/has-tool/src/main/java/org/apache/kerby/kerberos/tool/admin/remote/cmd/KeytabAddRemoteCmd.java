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

import java.io.File;

/**
 * Remote get principal cmd
 */
public class KeytabAddRemoteCmd extends AdminRemoteCmd {
    private static final String USAGE = "Usage: ktadd [-k[eytab] keytab] "
                                      + "[principal | -glob princ-exp] [...]\n"
                                      + "\tExample:\n"
                                      + "\t\tktadd hello@TEST.COM -k /keytab/location\n";
    private static final String DEFAULT_KEYTAB_FILE_LOCATION = "/etc/krb5.keytab";

    public KeytabAddRemoteCmd(HasAuthAdminClient authHadmin) {
        super(authHadmin);
    }

    @Override
    public void execute(String[] items) throws KrbException {
        if (items.length < 2) {
            System.err.println(USAGE);
            return;
        }

        String principal = null;
        String keytabFileLocation = null;
        boolean glob = false;

        int index = 1;
        while (index < items.length) {
            String command = items[index];
            if (command.equals("-k")) {
                index++;
                if (index >= items.length) {
                    System.err.println(USAGE);
                    return;
                }
                keytabFileLocation = items[index].trim();
            } else if (command.equals("-glob")) {
                glob = true;
            } else if (!command.startsWith("-")) {
                principal = command;
            }
            index++;
        }

        if (keytabFileLocation == null) {
            keytabFileLocation = DEFAULT_KEYTAB_FILE_LOCATION;
        }
        File keytabFile = new File(keytabFileLocation);

        if (principal == null) {
            System.out.println((glob ? "princ-exp" : "principal") + " not specified!");
            System.err.println(USAGE);
            return;
        }

        HasAuthAdminClient client = getAuthAdminClient();
        try {
            if (glob) {
                client.exportKeytabWithGlob(keytabFile, principal);
            } else {
                client.exportKeytab(keytabFile, principal);
            }
            System.out.println("Export Keytab to " + keytabFileLocation);
        } catch (KrbException e) {
            System.err.println("Principal \"" + principal + "\" fail to add entry to keytab."
                    + e.toString());
        }
    }
}

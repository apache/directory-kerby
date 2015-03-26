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
package org.apache.kerby.kerberos.tool.kadmin.executor;

import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.keytab.KeytabEntry;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;
import org.apache.kerby.kerberos.tool.kadmin.tool.KadminTool;

import java.io.File;
import java.io.IOException;

public class KeytabAddExecutor implements KadminCommandExecutor{
    private static final String USAGE =
            "Usage: ktadd [-k[eytab] keytab] [-q] [-e keysaltlist] [-norandkey] [principal | -glob princ-exp] [...]";

    private static final String DEFAULT_KEYTAB_FILE_LOCATION = "/etc/krb5.keytab";

    private Config backendConfig;

    public KeytabAddExecutor(Config backendConfig) {
        this.backendConfig = backendConfig;
    }

    @Override
    public void execute(String input) {
        String[] commands = input.split(" ");

        String principal = null;
        String keytabFileLocation = null;

        //Since commands[0] is ktadd, the initial index is 1.
        int index = 1;
        while (index < commands.length) {
            String command = commands[index];
            if (command.equals("-k")) {
                index++;
                if (index >= commands.length) {
                    System.err.println(USAGE);
                    return;
                }
                keytabFileLocation = commands[index].trim();

            } else if (!command.startsWith("-")){
                principal = command;
            }
            index++;
        }

        if (keytabFileLocation == null) {
            keytabFileLocation = DEFAULT_KEYTAB_FILE_LOCATION;
        }
        File keytabFile = new File(keytabFileLocation);

        addEntryToKeytab(keytabFile, principal);
    }

    private void addEntryToKeytab(File keytabFile, String principalName) {
        IdentityBackend backend = KadminTool.getBackend(backendConfig);

        //Get Identity
        KrbIdentity identity = backend.getIdentity(principalName);
        if (identity == null) {
            System.err.println("Can not find the identity for pincipal " +
                    principalName + ".");
            return;
        }

        StringBuffer resultSB = new StringBuffer();
        Keytab keytab = loadKeytab(keytabFile);

        //Add principal to keytab.
        PrincipalName principal = identity.getPrincipal();
        KerberosTime timestamp = new KerberosTime();
        for (EncryptionType encType : identity.getKeys().keySet()) {
            EncryptionKey ekey = identity.getKeys().get(encType);
            int keyVersion = ekey.getKvno();
            keytab.addEntry(new KeytabEntry(principal, timestamp, keyVersion, ekey));
            resultSB.append("Entry for principal " + principalName +
                    " with kvno " + keyVersion + ", encryption type " +
                    encType.getName() + " added to keytab " +
                    keytabFile.getAbsolutePath() + "\n");
        }

        //Store the keytab
        try {
            keytab.store(keytabFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(resultSB.toString());
    }

    private Keytab loadKeytab(File keytabFile) {
        try {
            if (!keytabFile.exists()) {
                keytabFile.createNewFile();
                return new Keytab();
            }

            return Keytab.loadKeytab(keytabFile);
        } catch (IOException e) {
            e.printStackTrace();
            return new Keytab();
        }
    }

}

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

import org.apache.kerby.KOptions;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;
import org.apache.kerby.kerberos.tool.kadmin.tool.KadminOption;
import org.apache.kerby.kerberos.tool.kadmin.tool.KadminTool;


public class RenamePrincipalExecutor implements KadminCommandExecutor{
    private static final String USAGE = "Usage: rename_principal [-force] old_principal new_principal\n";

    private KOptions kOptions;
    private Config backendConfig;
    private String oldPrincipalName;
    private String newPrincipalName;

    public RenamePrincipalExecutor(Config backendConfig) {
        this.backendConfig = backendConfig;
    }

    @Override
    public void execute(String input) {
        String[] commands = input.split("\\s+");
        if (commands.length < 3 || commands.length > 4) {
            System.err.println(USAGE);
            return;
        }

        kOptions = KadminTool.parseOptions(commands, 1, commands.length - 3);
        if(kOptions==null) {
            System.err.println(USAGE);
            return;
        }
        oldPrincipalName = commands[commands.length - 2];
        newPrincipalName = commands[commands.length - 1];

        if (kOptions.contains(KadminOption.FORCE)) {
            renamePrincipal();
        } else {
            String prompt = "Are you sure want to rename the principal? (yes/no, YES/NO, y/n, Y/N) ";
            String reply = KadminTool.getReplay(prompt);
            if (reply.equals("yes") || reply.equals("YES") || reply.equals("y") || reply.equals("Y")) {
                renamePrincipal();
            } else if (reply.equals("no") || reply.equals("NO") || reply.equals("n") || reply.equals("N")) {
                System.out.println("Principal \"" + oldPrincipalName + "\"  not renamed." );
            } else {
                System.err.println("Unknown response, fail to rename the principal.");
            }
        }
    }

    private void renamePrincipal() {
        IdentityBackend backend = KadminTool.getBackend(backendConfig);

        KrbIdentity verifyIdentity = backend.getIdentity(newPrincipalName);
        if(verifyIdentity != null) {
            System.err.println("Principal rename failed! Principal \"" + verifyIdentity.getPrincipalName() + "\" is already exist.");
            return;
        }

        try {
            KrbIdentity identity = backend.getIdentity(oldPrincipalName);
            if(identity == null) {
                System.err.println("Principal rename failed! Principal \"" + oldPrincipalName + "\" does not exist.");
                return;
            }
            backend.deleteIdentity(oldPrincipalName);

            identity.setPrincipalName(newPrincipalName);
            identity.setPrincipal(new PrincipalName(newPrincipalName));
            backend.addIdentity(identity);
            System.out.println("Principal \"" + oldPrincipalName + "\" renamed to \"" + newPrincipalName + "\".");
        } catch (Exception e) {
            System.err.println("Principal rename failed! Exception happened.");
        }
    }

}

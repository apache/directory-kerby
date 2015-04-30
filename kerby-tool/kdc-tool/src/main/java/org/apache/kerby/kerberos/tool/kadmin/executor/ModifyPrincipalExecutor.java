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

import org.apache.kerby.KOptionType;
import org.apache.kerby.KOptions;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.tool.kadmin.tool.KadminOption;
import org.apache.kerby.kerberos.tool.kadmin.tool.KadminTool;

import java.util.Date;

public class ModifyPrincipalExecutor implements KadminCommandExecutor {
    private static final String USAGE = "Usage: modify_principal [options] principal\n" +
        "\toptions are:\n" +
        "\t\t[-expire dd/MM/yy:HH:mm:ss]\n" +
        "\t\t[-disabled true/false]\n" +
        "\t\t[-locked true/false]\n" +
        "\tExample:\n" +
        "\t\tmodify_principal -expire 23/04/15:01:01:01 -disabled false -locked true test@EXAMPLE.COM";

    private Config backendConfig;
    private KOptions kOptions;
    private String principal;
    private KdcConfig kdcConfig; //NOPMD

    public ModifyPrincipalExecutor(KdcConfig kdcConfig, Config backendConfig) {
        this.backendConfig = backendConfig;
        this.kdcConfig = kdcConfig;
        kOptions = new KOptions();
    }

    @Override
    public void execute(String input) {
        String[] commands = input.split(" ");
        if (commands.length < 2) {
            KadminTool.printUsage("missing operand!", USAGE);
            return;
        }
        parseOptions(commands);
        modifyPrincipal(principal);
    }

    private void parseOptions(String[] commands) {
        KadminOption kOption;
        String opt, error, param;
        int i = 1;
        while (i < commands.length) {
            error = null;
            opt = commands[i++];
            if (opt.startsWith("-")) {
                kOption = KadminOption.fromName(opt);
                if (kOption == KadminOption.NONE) {
                    error = "Invalid option:" + opt;
                    break;
                }
            } else {
                principal = opt;
                kOption = KadminOption.NONE;
            }

            if (kOption.getType() != KOptionType.NOV) { // require a parameter
                param = null;
                if (i < commands.length) {
                    param = commands[i++];
                }
                if (param != null) {
                    KOptions.parseSetValue(kOption, param);
                } else {
                    error = "Option " + opt + " require a parameter";
                }
            }
            if (error != null) {
                KadminTool.printUsage(error, USAGE);
            }
            kOptions.add(kOption);
        }
        if(principal == null) {
            KadminTool.printUsage("missing principal name!", USAGE);
        }
    }

    private void modifyPrincipal(String principal) {
        IdentityBackend backend = KadminTool.getBackend(backendConfig);

        KrbIdentity originIdentity = backend.getIdentity(principal);
        KrbIdentity identity = createUpdatedIdentity(originIdentity);
        try {
            backend.updateIdentity(identity);
            System.out.println("Principal \"" + principal + "\" modified.");
        } catch (Exception e) {
            System.err.println("Principal \"" + principal + "\" fail to modify." + e.getMessage());
        }
    }

    protected KrbIdentity createUpdatedIdentity(KrbIdentity kid) {
        if (kOptions.contains(KadminOption.EXPIRE)) {
            Date date = kOptions.getDateOption(KadminOption.EXPIRE);
            kid.setExpireTime(new KerberosTime(date.getTime()));
        }
        if (kOptions.contains(KadminOption.DISABLED)) {
            kid.setDisabled(kOptions.getBooleanOption(KadminOption.DISABLED));
        }
        if (kOptions.contains(KadminOption.LOCKED)) {
            kid.setLocked(kOptions.getBooleanOption(KadminOption.LOCKED));
        }
        return kid;
    }
}

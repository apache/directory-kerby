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
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.tool.kadmin.tool.KadminOption;
import org.apache.kerby.kerberos.tool.kadmin.tool.KadminTool;

import java.io.Console;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

public class AddPrincipalExecutor implements KadminCommandExecutor{
    private static final String USAGE = "Usage: add_principal [options] principal\n" +
            "\toptions are:\n" +
            "\t\t[-randkey|-nokey] [-x db_princ_args]* [-expire expdate] [-pwexpire pwexpdate] [-maxlife maxtixlife]\n" +
            "\t\t[-kvno kvno] [-policy policy] [-clearpolicy]\n" +
            "\t\t[-pw password] [-maxrenewlife maxrenewlife]\n" +
            "\t\t[-e keysaltlist]\n" +
            "\t\t[{+|-}attribute]\n" +
            "\tattributes are:\n" +
            "\t\tallow_postdated allow_forwardable allow_tgs_req allow_renewable\n" +
            "\t\tallow_proxiable allow_dup_skey allow_tix requires_preauth\n" +
            "\t\trequires_hwauth needchange allow_svr password_changing_service\n" +
            "\t\tok_as_delegate ok_to_auth_as_delegate no_auth_data_required\n" +
            "\n" +
            "\twhere,\n" +
            "\t[-x db_princ_args]* - any number of database specific arguments.\n" +
            "\t\t\tLook at each database documentation for supported arguments.\n" +
            "\tExample:\n" +
            "\t\tadd_principal -expire 23/04/15:01:01:01 -kvno 1 -pw mypassword test@EXAMPLE.COM";

    private KdcConfig kdcConfig;
    private Config backendConfig;
    private KOptions kOptions;

    public AddPrincipalExecutor(KdcConfig kdcConfig, Config backendConfig) {
        this.kdcConfig = kdcConfig;
        this.backendConfig = backendConfig;
    }

    @Override
    public void execute(String input) {
        String[] commands = input.split("\\s+");
        if (commands.length < 2) {
            System.err.println(USAGE);
            return;
        }

        kOptions = KadminTool.parseOptions(commands, 1, commands.length - 2);
        if(kOptions == null) {
            System.err.println(USAGE);
            return;
        }
        String principal = commands[commands.length - 1];
        String password;
        if(kOptions.contains(KadminOption.PW)) {
            password = kOptions.getStringOption(KadminOption.PW);
        } else {
            password = getPassword(principal);
        }

        if (password == null) {
            return;
        }

        addPrincipal(principal, password);
    }

    /**
     * Get password for the input principal from console
     */
    private String getPassword(String principal) {
        String passwordOnce;
        String passwordTwice;

        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance, " +
                    "maybe you're running this from within an IDE. " +
                    "Use scanner to read password.");
            Scanner scanner = new Scanner(System.in);
            passwordOnce = getPassword(scanner,
                    "Enter password for principal \"" + principal + "\":");
            passwordTwice = getPassword(scanner,
                    "Re-enter password for principal \"" + principal + "\":");

        } else {
            passwordOnce = getPassword(console,
                    "Enter password for principal \"" + principal + "\":");
            passwordTwice = getPassword(console,
                    "Re-enter password for principal \"" + principal + "\":");
        }

        if (!passwordOnce.equals(passwordTwice)) {
            System.err.println("add_principal: Password mismatch while reading password for \"" + principal + "\".");
            return null;
        }
        return passwordOnce;
    }

    private String getPassword(Scanner scanner, String prompt) {
        System.out.println(prompt);
        return scanner.nextLine().trim();
    }

    private String getPassword(Console console, String prompt) {
        console.printf(prompt);
        char[] passwordChars = console.readPassword();
        String password = new String(passwordChars).trim();
        Arrays.fill(passwordChars, ' ');
        return password;
    }

    private void addPrincipal(String principal, String password) {
        IdentityBackend backend = KadminTool.getBackend(backendConfig);

        KrbIdentity identity = createIdentity(principal, password);
        try {
            backend.addIdentity(identity);
            System.out.println("Principal \"" + principal + "\" created.");
        } catch (Exception e) {
            System.err.println("Principal or policy already exists while creating \"" + principal + "\".");
        }
    }

    protected KrbIdentity createIdentity(String principal, String password) {
        KrbIdentity kid = new KrbIdentity(principal);
        kid.setCreatedTime(KerberosTime.now());
        if(kOptions.contains(KadminOption.EXPIRE)) {
            Date date = kOptions.getDateOption(KadminOption.EXPIRE);
            kid.setExpireTime(new KerberosTime(date.getTime()));
        } else {
            kid.setExpireTime(KerberosTime.NEVER);
        }
        if(kOptions.contains(KadminOption.KVNO)) {
            kid.setKeyVersion(kOptions.getIntegerOption(KadminOption.KVNO));
        } else {
            kid.setKeyVersion(1);
        }
        kid.setDisabled(false);
        kid.setLocked(false);

        kid.addKeys(generateKeys(kid.getPrincipalName(), password));

        return kid;
    }

    protected List<EncryptionKey> generateKeys(String principal, String password) {
        try {
            return EncryptionUtil.generateKeys(principal, password, kdcConfig.getEncryptionTypes());
        } catch (KrbException e) {
            throw new RuntimeException("Failed to create keys", e);
        }
    }
}

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
package org.apache.kerby.kerberos.tool.kinit;

import org.apache.kerby.KOption;
import org.apache.kerby.KOptionGroup;
import org.apache.kerby.KOptionInfo;
import org.apache.kerby.KOptionType;
import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbConstant;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbKdcOption;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.client.KrbOptionGroup;
import org.apache.kerby.kerberos.kerb.client.PkinitOption;
import org.apache.kerby.kerberos.kerb.client.TokenOption;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.apache.kerby.util.OSUtil;
import org.apache.kerby.util.SysUtil;

import java.io.Console;
import java.io.File;
import java.util.Arrays;
import java.util.Scanner;

/**
 * kinit like tool
 *
 * Ref. MIT kinit command tool usage.
 */
public class KinitTool {

    private static final String USAGE = (OSUtil.isWindows()
            ? "Usage: bin\\kinit.cmd" : "Usage: sh bin/kinit.sh")
            + " [-conf conf_dir] [-V] [-l lifetime] [-s start_time]\n"
            + "\t\t[-r renewable_life] [-f | -F] [-p | -P] -n [-a | -A] [-C] [-E]\n"
            + "\t\t[-v] [-R] [-k [-i|-t keytab_file]] [-c cachename]\n"
            + "\t\t[-S service_name] [-T ticket_armor_cache]\n"
            + "\t\t[-X <attribute>[=<value>]] <principal>\n\n"
            + "\tDESCRIPTION:\n"
            + "\t\tkinit obtains and caches an initial ticket-granting ticket for principal.\n\n"
            + "\tOPTIONS:\n"
            + "\t\t-V verbose\n"
            + "\t\t-l lifetime\n"
            + "\t\t--s start time\n"
            + "\t\t-r renewable lifetime\n"
            + "\t\t-f forwardable\n"
            + "\t\t-F not forwardable\n"
            + "\t\t-p proxiable\n"
            + "\t\t-P not proxiable\n"
            + "\t\t-n anonymous\n"
            + "\t\t-a include addresses\n"
            + "\t\t-A do not include addresses\n"
            + "\t\t-v validate\n"
            + "\t\t-R renew\n"
            + "\t\t-C canonicalize\n"
            + "\t\t-E client is enterprise principal name\n"
            + "\t\t-k use keytab\n"
            + "\t\t-i use default client keytab (with -k)\n"
            + "\t\t-t filename of keytab to use\n"
            + "\t\t-c Kerberos 5 cache name\n"
            + "\t\t-S service\n"
            + "\t\t-T armor credential cache\n"
            + "\t\t-X <attribute>[=<value>]\n"
            + "\n";


    private static void printUsage(String error) {
        System.err.println(error + "\n");
        System.err.println(USAGE);
        System.exit(-1);
    }

    /**
     * Get password for the input principal from console
     */
    private static String getPassword(String principal) {
        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance, "
                    + "maybe you're running this from within an IDE. "
                    + "Use scanner to read password.");
            System.out.println("Password for " + principal + ":");
            try (Scanner scanner = new Scanner(System.in, "UTF-8")) {
                return scanner.nextLine().trim();
            }
        }
        console.printf("Password for " + principal + ":");
        char[] passwordChars = console.readPassword();
        String password = new String(passwordChars).trim();
        Arrays.fill(passwordChars, ' ');

        return password;
    }

    private static void requestTicket(String principal,
                                      KOptions ktOptions) throws KrbException {
        ktOptions.add(KinitOption.CLIENT_PRINCIPAL, principal);

        File confDir = null;
        if (ktOptions.contains(KinitOption.CONF_DIR)) {
            confDir = ktOptions.getDirOption(KinitOption.CONF_DIR);
        }

        if (ktOptions.contains(KinitOption.ANONYMOUS)) {
            ktOptions.add(PkinitOption.USE_ANONYMOUS);
            ktOptions.add(PkinitOption.X509_ANCHORS);
        } else if (!ktOptions.contains(KinitOption.USE_KEYTAB)) {
            //If not request tickets by keytab than by password.
            ktOptions.add(KinitOption.USE_PASSWD);
            String password = getPassword(principal);
            ktOptions.add(KinitOption.USER_PASSWD, password);
        }

        KrbClient krbClient = null;
        try {
            krbClient = getClient(confDir);
        } catch (KrbException e) {
            System.err.println("Create krbClient failed: " + e.getMessage());
            System.exit(1);
        }

        TgtTicket tgt = null;
        try {
            tgt = krbClient.requestTgt(convertOptions(ktOptions));
        } catch (KrbException e) {
            System.err.println("Authentication failed: " + e.getMessage());
            System.exit(1);
        }

        File ccacheFile;
        if (ktOptions.contains(KrbOption.KRB5_CACHE)) {
            String ccacheName = ktOptions.getStringOption(KrbOption.KRB5_CACHE);
            ccacheFile = new File(ccacheName);
        } else {
            String ccacheName = principal.replaceAll("/", "_");
            ccacheName = "krb5_" + ccacheName + ".cc";
            ccacheFile = new File(SysUtil.getTempDir(), ccacheName);
        }

        try {
            krbClient.storeTicket(tgt, ccacheFile);
        } catch (KrbException e) {
            System.err.println("Store ticket failed: " + e.getMessage());
            System.exit(1);
        }

        System.out.println("Successfully requested and stored ticket in "
            + ccacheFile.getAbsolutePath());
        if (ktOptions.contains(KinitOption.SERVICE)) {
            String servicePrincipal = ktOptions.getStringOption(KinitOption.SERVICE);
            SgtTicket sgtTicket =
                    krbClient.requestSgt(tgt, servicePrincipal);
            System.out.println("Successfully requested the service ticket for " + servicePrincipal
            + "\nKey version: " + sgtTicket.getTicket().getTktvno());
        }
    }

    /**
     * Init the client.
     */
    private static KrbClient getClient(File confDir) throws KrbException {
        KrbClient krbClient;

        if (confDir != null) {
            krbClient = new KrbClient(confDir);
        } else {
            krbClient = new KrbClient();
        }

        krbClient.init();
        return krbClient;
    }

    public static void main(String[] args) throws Exception {
        KOptions ktOptions = new KOptions();
        KinitOption kto;
        String principal = null;

        int i = 0;
        String opt, param, error;
        while (i < args.length) {
            error = null;

            opt = args[i++];
            if (opt.startsWith("-")) {
                kto = KinitOption.fromName(opt);
                if (kto == KinitOption.NONE) {
                    error = "Invalid option:" + opt;
                    System.err.println(error);
                    break;
                }
            } else {
                principal = opt;
                kto = KinitOption.NONE;
            }

            if (kto != KinitOption.NONE && kto.getOptionInfo().getType() != KOptionType.NOV) {
                // require a parameter
                param = null;
                if (i < args.length) {
                    param = args[i++];
                }
                if (param != null) {
                    KOptions.parseSetValue(kto.getOptionInfo(), param);
                } else {
                    error = "Option " + opt + " require a parameter";
                }
            }

            if (error != null) {
                printUsage(error);
            }
            if (kto != KinitOption.NONE) {
                ktOptions.add(kto);
            }
        }

        if (principal == null) {
            if (ktOptions.contains(KinitOption.ANONYMOUS)) {
                principal = KrbConstant.ANONYMOUS_PRINCIPAL;
            } else {
                printUsage("No principal is specified");
            }
        }

        requestTicket(principal, ktOptions);
        System.exit(0);
    }

    /**
     * Convert kinit tool options to KOptions.
     * @param toolOptions
     * @return KOptions
     */
    static KOptions convertOptions(KOptions toolOptions) {
        KOptions results = new KOptions();

        for (KOption toolOpt : toolOptions.getOptions()) {
            KOptionInfo kOptionInfo = toolOpt.getOptionInfo();
            KOptionGroup group = kOptionInfo.getGroup();
            KOption kOpt = null;

            if (group == KrbOptionGroup.KRB) {
                kOpt = KrbOption.fromOptionName(kOptionInfo.getName());
            } else if (group == KrbOptionGroup.PKINIT) {
                kOpt = PkinitOption.fromOptionName(kOptionInfo.getName());
            } else if (group == KrbOptionGroup.TOKEN) {
                kOpt = TokenOption.fromOptionName(kOptionInfo.getName());
            } else if (group == KrbOptionGroup.KDC_FLAGS) {
                kOpt = KrbKdcOption.fromOptionName(kOptionInfo.getName());
            }
            if (kOpt != null && kOpt.getOptionInfo() != KrbOption.NONE.getOptionInfo()) {
                kOpt.getOptionInfo().setValue(toolOpt.getOptionInfo().getValue());
                results.add(kOpt);
            }
        }

        return results;
    }
}

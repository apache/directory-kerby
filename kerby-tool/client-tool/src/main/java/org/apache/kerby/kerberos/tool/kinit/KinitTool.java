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
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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
            + " <-conf conf_dir> [-V] [-l lifetime] [-s start_time]\n"
            + "\t\t[-r renewable_life] [-f | -F] [-p | -P] -n [-a | -A] [-C] [-E]\n"
            + "\t\t[-v] [-R] [-k [-i|-t keytab_file]] [-c cachename]\n"
            + "\t\t[-S service_name] [-T ticket_armor_cache]\n"
            + "\t\t[-X <attribute>[=<value>]] <principal>\n\n"
            + "\tDESCRIPTION:\n"
            + "\t\tkinit obtains and caches an initial ticket-granting ticket for principal.\n\n"
            + "\tOPTIONS:\n"
            + "\t\t-V verbose\n"
            + "\t\t-l lifetime\n"
            + "\t\t-s start time\n"
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

    private static final String KVNO_USAGE = (OSUtil.isWindows()
        ? "Usage: bin\\kinit.cmd" : "Usage: sh bin/kinit.sh")
        + " <-conf conf_dir> <-c cachename> <-S service_name>\n\n"
        + "\tDESCRIPTION:\n"
        + "\t\tkinit obtains a service ticket for the specified principal and prints out the key version number.\n"
        + "\n";

    private static void printKvnoUsage(String error) {
        System.err.println(error + "\n");
        System.err.println(KVNO_USAGE);
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
            try (Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8.name())) {
                return scanner.nextLine().trim();
            }
        }
        console.printf("Password for " + principal + ":");
        char[] passwordChars = console.readPassword();
        String password = new String(passwordChars).trim();
        Arrays.fill(passwordChars, ' ');

        return password;
    }

    private static void requestTicket(String principal, KOptions ktOptions) {
        ktOptions.add(KinitOption.CLIENT_PRINCIPAL, principal);

        File confDir = null;
        if (ktOptions.contains(KinitOption.CONF_DIR)) {
            confDir = ktOptions.getDirOption(KinitOption.CONF_DIR);
        }

        KrbClient krbClient = null;
        try {
            krbClient = getClient(confDir);
        } catch (KrbException e) {
            System.err.println("Create krbClient failed: " + e.getMessage());
            System.exit(1);
        }

        if (ktOptions.contains(KinitOption.RENEW)) {
            if (ktOptions.contains(KinitOption.KRB5_CACHE)) {
                String ccName = ktOptions.getStringOption(KinitOption.KRB5_CACHE);
                File ccFile = new File(ccName);

                SgtTicket sgtTicket = null;
                try {
                    sgtTicket = krbClient.requestSgt(ccFile, null);
                } catch (KrbException e) {
                    System.err.println("kinit: " + e.getKrbErrorCode().getMessage());
                }

                try {
                    krbClient.renewTicket(sgtTicket, ccFile);
                } catch (KrbException e) {
                    System.err.println("kinit: " + e.getKrbErrorCode().getMessage());
                }

                System.out.println("Successfully renewed.");
            }
            return;
        }

        if (ktOptions.contains(KinitOption.SERVICE) && ktOptions.contains(KinitOption.KRB5_CACHE)) {
            String ccName = ktOptions.getStringOption(KinitOption.KRB5_CACHE);
            File ccFile = new File(ccName);
            if (ccFile.exists()) {
                System.out.println("Use credential cache to request a service ticket.");
                String servicePrincipal = ktOptions.getStringOption(KinitOption.SERVICE);
                SgtTicket sgtTicket = null;
                try {
                    sgtTicket = krbClient.requestSgt(ccFile, servicePrincipal);
                } catch (KrbException e) {
                    System.err.println("Kinit: get service ticket failed: " + e.getMessage());
                    System.exit(1);
                }

                try {
                    krbClient.storeTicket(sgtTicket, ccFile);
                } catch (KrbException e) {
                    System.err.println("Kinit: store ticket failed: " + e.getMessage());
                    System.exit(1);
                }

                System.out.println(sgtTicket.getEncKdcRepPart().getSname().getName() + ": knvo = "
                    + sgtTicket.getTicket().getEncryptedEncPart().getKvno());
                return;
            }
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

        TgtTicket tgt = null;
        try {
            tgt = krbClient.requestTgt(convertOptions(ktOptions));
        } catch (KrbException e) {
            System.err.println("Authentication failed: " + e.getMessage());
            System.exit(1);
        }

        File ccacheFile;
        if (ktOptions.contains(KinitOption.KRB5_CACHE)) {
            String ccacheName = ktOptions.getStringOption(KinitOption.KRB5_CACHE);
            ccacheFile = new File(ccacheName);
        } else {
            String ccacheName = getCcacheName(krbClient);
            ccacheFile = new File(ccacheName);
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
            System.out.println("Use tgt to request a service ticket.");
            String servicePrincipal = ktOptions.getStringOption(KinitOption.SERVICE);
            SgtTicket sgtTicket;
            try {
                sgtTicket = krbClient.requestSgt(tgt, servicePrincipal);
            } catch (KrbException e) {
                System.err.println("kinit: " + e.getKrbErrorCode().getMessage());
                return;
            }

            System.out.println(sgtTicket.getEncKdcRepPart().getSname().getName() + ": knvo = "
                + sgtTicket.getTicket().getEncryptedEncPart().getKvno());
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

    /**
     * Get credential cache file name if not specified.
     */
    private static String getCcacheName(KrbClient krbClient) {
        final String ccacheNameEnv = System.getenv("KRB5CCNAME");
        final String ccacheNameConf = krbClient.getSetting().getKrbConfig().getString("default_ccache_name");
        String ccacheName;
        if (ccacheNameEnv != null) {
            ccacheName = ccacheNameEnv;
        } else if (ccacheNameConf != null) {
            ccacheName = ccacheNameConf;
        } else {
            StringBuilder uid = new StringBuilder();
            try {
                //Get UID through "id -u" command
                String command = "id -u";
                Process child = Runtime.getRuntime().exec(command);
                InputStream in = child.getInputStream();
                int c;
                while ((c = in.read()) != -1) {
                    uid.append((char) c);
                }
                in.close();
            } catch (IOException e) {
                System.err.println("Failed to get UID.");
                System.exit(1);
            }
            ccacheName = "krb5cc_" + uid.toString().trim();
            ccacheName = SysUtil.getTempDir().toString() + "/" + ccacheName;
        }

        return ccacheName;
    }

    public static void main(String[] args) {
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

        if (!ktOptions.contains(KinitOption.CONF_DIR)) {
            printUsage("No conf dir given.");
        }

        if (principal == null) {
            if (ktOptions.contains(KinitOption.ANONYMOUS)) {
                principal = KrbConstant.ANONYMOUS_PRINCIPAL;
            } else if (!ktOptions.contains(KinitOption.SERVICE) && !ktOptions.contains(KinitOption.KRB5_CACHE)) {
                printUsage("No principal is specified");
            } else if (ktOptions.contains(KinitOption.SERVICE) && !ktOptions.contains(KinitOption.KRB5_CACHE)) {
                printKvnoUsage("No credential cache file given.");
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

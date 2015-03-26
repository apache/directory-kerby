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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.ccache.Credential;
import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerby.kerberos.kerb.client.KOptionType;
import org.apache.kerby.kerberos.kerb.client.KOptions;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.apache.kerby.kerberos.tool.ToolUtil;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Scanner;

/**
 * kinit like tool
 */
public class Kinit {

    private static final String USAGE =
            "Usage: kinit [-V] [-l lifetime] [-s start_time]\n" +
                    "\t\t[-r renewable_life] [-f | -F] [-p | -P] -n [-a | -A] [-C] [-E]\n" +
                    "\t\t[-v] [-R] [-k [-i|-t keytab_file]] [-c cachename]\n" +
                    "\t\t[-S service_name] [-T ticket_armor_cache]\n" +
                    "\t\t[-X <attribute>[=<value>]] <principal>\n\n" +
                    "\tDESCRIPTION:\n" +
                    "\t\tkinit obtains and caches an initial ticket-granting ticket for principal.\n\n" +
                    "\tOPTIONS:\n" +
                    "\t\t-V verbose\n" +
                    "\t\t-l lifetime\n" +
                    "\t\t--s start time\n" +
                    "\t\t-r renewable lifetime\n" +
                    "\t\t-f forwardable\n" +
                    "\t\t-F not forwardable\n" +
                    "\t\t-p proxiable\n" +
                    "\t\t-P not proxiable\n" +
                    "\t\t-n anonymous\n" +
                    "\t\t-a include addresses\n" +
                    "\t\t-A do not include addresses\n" +
                    "\t\t-v validate\n" +
                    "\t\t-R renew\n" +
                    "\t\t-C canonicalize\n" +
                    "\t\t-E client is enterprise principal name\n" +
                    "\t\t-k use keytab\n" +
                    "\t\t-i use default client keytab (with -k)\n" +
                    "\t\t-t filename of keytab to use\n" +
                    "\t\t-c Kerberos 5 cache name\n" +
                    "\t\t-S service\n" +
                    "\t\t-T armor credential cache\n" +
                    "\t\t-X <attribute>[=<value>]\n" +
                    "\n";


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
            System.out.println("Couldn't get Console instance, " +
                    "maybe you're running this from within an IDE. " +
                    "Use scanner to read password.");
            System.out.println("Password for " + principal + ":");
            Scanner scanner = new Scanner(System.in);
            return scanner.nextLine().trim();
        }
        console.printf("Password for " + principal + ":");
        char[] passwordChars = console.readPassword();
        String password = new String(passwordChars).trim();
        Arrays.fill(passwordChars, ' ');

        return password;
    }

    private static void requestTicket(String principal, KOptions krbOptions) throws KrbException, IOException {
        KrbClient krbClient = getClient();
        TgtTicket tgt;

        if (krbOptions.contains(KrbOption.USE_KEYTAB)) {
            tgt = krbClient.requestTgtTicket(principal, krbOptions);
        } else {
            String password = getPassword(principal);
            tgt = krbClient.requestTgtTicket(principal, password,
                    krbOptions);
        }

        writeTgtToCache(tgt, principal, krbOptions);
    }

    /**
     * Init the client.
     */
    private static KrbClient getClient() {
        KrbClient krbClient = new KrbClient();
        krbClient.init();
        return krbClient;
    }

    /**
     * Write tgt into credentials cache.
     */
    private static void writeTgtToCache(TgtTicket tgt, String principal, KOptions kinitOptions)
            throws IOException {
        Credential credential = new Credential(tgt);
        CredentialCache cCache = new CredentialCache();
        cCache.addCredential(credential);
        cCache.setPrimaryPrincipal(tgt.getClientPrincipal());

        String fileName;
        if (kinitOptions.contains(KrbOption.KRB5_CACHE)) {
            fileName = kinitOptions.getStringOption(KrbOption.KRB5_CACHE);
        } else {
            fileName = "krb5_" + principal + ".cc";
        }
        File cCacheFile = new File("/tmp/", fileName);
        cCache.store(cCacheFile);
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
                    break;
                }
            } else {
                principal = opt;
                kto = KinitOption.NONE;
            }

            if (kto.getType() != KOptionType.NOV) { // require a parameter
                param = null;
                if (i < args.length) {
                    param = args[i++];
                }
                if (param != null) {
                    ToolUtil.parseSetValue(kto, param);
                } else {
                    error = "Option " + opt + " require a parameter";
                }
            }

            if (error != null) {
                printUsage(error);
            }
            ktOptions.add(kto);
        }

        if (principal == null) {
            printUsage("No principal is specified");
        }

        Kinit.requestTicket(principal, ToolUtil.convertOptions(ktOptions));
        System.exit(0);
    }

}

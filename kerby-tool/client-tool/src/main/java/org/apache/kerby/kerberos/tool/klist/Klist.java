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
package org.apache.kerby.kerberos.tool.klist;

import org.apache.kerby.KOptionType;
import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.ccache.Credential;
import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.List;

/**
 * klist like tool
 */
public class Klist {

    private static  final String USAGE =
            "Usage: klist [-e] [-V] [[-c] [-l] [-A] [-d] [-f] [-s] " +
                    "[-a [-n]]] [-k [-t] [-K]] [name]\n" +
                    "\t-c specifies credentials cache\n" +
                    "\t-k specifies keytab\n" +
                    "\t   (Default is credentials cache)\n" +
                    "\t-i uses default client keytab if no name given\n" +
                    "\t-l lists credential caches in collection\n" +
                    "\t-A shows content of all credential caches\n" +
                    "\t-e shows the encryption type\n" +
                    "\t-V shows the Kerberos version and exits\n" +
                    "\toptions for credential caches:\n" +
                    "\t\t-d shows the submitted authorization data types\n" +
                    "\t\t-f shows credentials flags\n" +
                    "\t\t-s sets exit status based on valid tgt existence\n" +
                    "\t\t-a displays the address list\n" +
                    "\t\t\t-n do not reverse-resolve\n" +
                    "\toptions for keytabs:\n" +
                    "\t\t-t shows keytab entry timestamps\n" +
                    "\t\t-K shows keytab entry keys\n";



    private static void printUsage(String error) {
        System.err.println(error + "\n");
        System.err.println(USAGE);
        System.exit(-1);
    }

    private static int printInfo(String name, KOptions klOptions) {
        CredentialCache cc = new CredentialCache();
        List<Credential> credentials;
        InputStream cis = null ;
        String error;
        String fileName = null;

        if (!klOptions.contains(KlistOption.CREDENTIALS_CACHE)) {
            error = "No credential cache path given.";
            printUsage(error);
        } else {
            fileName = klOptions.getStringOption(KlistOption.CREDENTIALS_CACHE);
            try {
                cis = new FileInputStream(fileName);
                cc.load(cis);
            } catch (IOException e) {
                System.err.println("Failed to open CredentialCache from file: " + fileName);
                e.printStackTrace();
            }

        }

        if (cc != null) {
            credentials = cc.getCredentials();

            System.out.println("Ticket cache: " + fileName);
            System.out.println("Default principal: " + cc.getPrimaryPrincipal().getName());

            if (credentials.isEmpty()) {
                System.out.println("No credential has been cached.");
            } else {
                DateFormat df = new SimpleDateFormat("dd/MM/yy HH:mm:ss");

                System.out.println("Valid starting\t\tExpires\t\t\tService principal");

                for (Credential crd : credentials) {
                    System.out.println( df.format(crd.getStartTime().getTime()) + "\t" +
                                        df.format(crd.getEndTime().getTime()) + "\t" +
                                        crd.getServerName());
                }
            }

        }

        return 0;
    }

    public static void main(String[] args) throws Exception {
        KOptions klOptions = new KOptions();
        KlistOption klopt;
        String name = null;

        int i = 0;
        String opt, value, error;
        while (i < args.length) {
            error = null;
            opt = args[i++];

            if (opt.startsWith("-")) {
                klopt = KlistOption.fromName(opt);
                if (klopt == KlistOption.NONE) {
                    error = "Invalid option:" + opt;
                    break;
                }
            } else {
                name = opt;
                break;
            }

            if (klopt.getType() != KOptionType.NOV) { //needs value for this parameter
                value = null;
                if (i < args.length) {
                    value = args[i++];
                }
                if (value != null) {
                    KOptions.parseSetValue(klopt, value);
                } else {
                    error = "Option" + klopt + "requires a following value";
                }
            }

            if ( error != null ) {
                printUsage(error);
            }

            klOptions.add(klopt);
        }

        int errNo = Klist.printInfo(name, klOptions);
        System.exit(errNo);
    }
}

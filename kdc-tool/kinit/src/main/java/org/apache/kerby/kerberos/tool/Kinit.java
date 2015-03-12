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
package org.apache.kerby.kerberos.tool;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbClient;

import java.io.Console;
import java.util.Arrays;
import java.util.Scanner;

/**
 * kinit like tool
 */
public class Kinit {

    private static final String COMMON_USAGE = "Usage: " + Kinit.class.getSimpleName() + " [-l lifetime] [-f | -F] principal\n" +
            "\n" +
            "    options:\t-l lifetime\n" +
            "\t-f forwardable\n" +
            "\t-F not forwardable";

    private void printUsage(String cmd) {
        if ("-l".equals(cmd)) {
            System.err.println("Usage: " + Kinit.class.getSimpleName() + " -l lifetime principal");
        } else if ("-f".equals(cmd)) {
            System.err.println("Usage: " + Kinit.class.getSimpleName() + " -f principal");
        } else if ("-F".equals(cmd)) {
            System.err.println("Usage: " + Kinit.class.getSimpleName() + " -F principal");
        } else {
            System.err.println(COMMON_USAGE);
        }
    }

    private int execute(String[] args) {
        if (args.length < 1 || args.length > 3) {
            printUsage("");
            return -1;
        }

        //no options
        if (args.length == 1) {
            return requestTicket(args, 0);
        }

        int exitCode = -1;
        int i = 0;
        String cmd = args[i];

        //
        // verify that we have enough option parameters
        //
        if ("-l".equals(cmd)) {
            if (args.length != 3) {
                printUsage(cmd);
                return exitCode;
            }
        } else if ("-f".equals(cmd)) {
            if (args.length != 2) {
                printUsage(cmd);
                return exitCode;
            }
        } else if ("-F".equals(cmd)) {
            if (args.length != 2) {
                printUsage(cmd);
                return exitCode;
            }
        }

        //
        //execute the command
        //
        if ("-l".equals(cmd)) {
            exitCode = ticketWithLifetime(args, i);
        } else if ("-f".equals(cmd)) {
            exitCode = ticketForwardable(args, i);
        } else if ("-F".equals(cmd)) {
            exitCode = ticketNonForwardable(args, i);
        }

        return exitCode;
    }

    /**
     * Init the KrbClient
     */
    private KrbClient getClient() {
        KrbClient krbClient = new KrbClient();
        krbClient.init();
        //TODO should be read from configuration
        krbClient.setKdcRealm("TEST.COM");
        return krbClient;
    }

    /**
     * Get password for the input principal from console
     */
    private String getPassword(String principal) {
        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance, maybe you're running this from within an IDE. Use scanner to read password.");
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

    private int requestTicket(String[] args, int i) {
        String principal = args[i];
        KrbClient client = getClient();
        String password = getPassword(principal);

        try {
            client.requestTgtTicket(principal, password, null);
            return 0;
        } catch (KrbException e) {
            System.err.println("Something error.");
            return -1;
        }
    }

    private int ticketWithLifetime(String[] args, int i) {
        String lifetime = args[i];
        String principal = args[i];
        KrbClient client = getClient();
        String password = getPassword(principal);
        try {
            //TODO
            return 0;
        } catch (Exception e) {
            System.err.println("Something error.");
            return -1;
        }
    }

    private int ticketForwardable(String[] args, int i) {
        String principal = args[i];
        KrbClient client = getClient();
        String password = getPassword(principal);
        try {
            //TODO
            return 0;
        } catch (Exception e) {
            System.err.println("Something error.");
            return -1;
        }
    }

    private int ticketNonForwardable(String[] args, int i) {
        String principal = args[i];
        KrbClient client = getClient();
        String password = getPassword(principal);
        try {
            //TODO
            return 0;
        } catch (Exception e) {
            System.err.println("Something error.");
            return -1;
        }
    }

    public static void main(String[] args) throws Exception {
        Kinit kinit = new Kinit();
        int exitCode = kinit.execute(args);
        System.exit(exitCode);
    }

}

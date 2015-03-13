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

import org.apache.kerby.config.Conf;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;

import java.io.Console;
import java.io.File;
import java.io.IOException;
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

    /**
     * args[0] is the configuration directory written in script.
     * args[length - 1] is principal
     */
    private int execute(String[] args) {
        if (args.length < 2 || args.length > 4) {
            printUsage("");
            return -1;
        }

        //no options
        if (args.length == 2) {
            return requestTicket(args, 1);
        }

        int exitCode = -1;
        int i = 1;
        String cmd = args[i];

        //
        // verify that we have enough option parameters
        //
        if ("-l".equals(cmd)) {
            if (args.length != 4) {
                printUsage(cmd);
                return exitCode;
            }
        } else if ("-f".equals(cmd)) {
            if (args.length != 3) {
                printUsage(cmd);
                return exitCode;
            }
        } else if ("-F".equals(cmd)) {
            if (args.length != 3) {
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
    private KrbClient createClient(String confDirString) {
        KrbConfig krbConfig = new KrbConfig();
        Conf conf = krbConfig.getConf();

        try {
            File confDir = new File(confDirString);
            File[] files = confDir.listFiles();
            if (files == null) {
                throw new IOException("There are no file in configuration directory: " + confDirString);
            }

            for (File file : files) {
                conf.addIniConfig(file);
            }
        } catch (IOException e) {
            System.err.println("Something wrong with krb configuration.");
            e.printStackTrace();
        }

        KrbClient krbClient = new KrbClient(krbConfig);
        krbClient.init();
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
        KrbClient client = createClient(args[0]);
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
        KrbClient client = createClient(args[0]);
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
        KrbClient client = createClient(args[0]);
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
        KrbClient client = createClient(args[0]);
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

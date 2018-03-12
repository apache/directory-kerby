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
package org.apache.kerby.kerberos.tool.init;

import org.apache.kerby.has.client.HasInitClient;
import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.common.util.HasUtil;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.tool.init.cmd.InitCmd;
import org.apache.kerby.kerberos.tool.init.cmd.InitKdcCmd;
import org.apache.kerby.kerberos.tool.init.cmd.StartKdcCmd;
import org.apache.kerby.util.OSUtil;

import java.io.File;
import java.util.Scanner;

public class HasInitTool {
    private static final String PROMPT = HasInitTool.class.getSimpleName();
    private static final String USAGE = (OSUtil.isWindows()
            ? "Usage: bin\\hasinit.cmd" : "Usage: sh bin/hasinit.sh")
            + " <conf-file>\n"
            + "\tExample:\n"
            + "\t\t"
            + (OSUtil.isWindows()
            ? "bin\\hasinit.cmd" : "sh bin/hasinit.sh")
            + " conf\n";

    private static final String LEGAL_COMMANDS = "Available commands are: "
            + "\n"
            + "start_kdc, start\n"
            + "                         Start kdc\n"
            + "init_kdc, init\n"
            + "                         Init kdc\n";

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println(USAGE);
            System.exit(1);
        }
        String confDirPath = args[0];
        File confFile = new File(confDirPath, "admin.conf");
        HasConfig hasConfig;
        try {
            hasConfig = HasUtil.getHasConfig(confFile);
        } catch (HasException e) {
            System.err.println(e.getMessage());
            return;
        }

        System.out.println(LEGAL_COMMANDS);
        System.out.println("enter \"<cmd> [?][-help]\" to get cmd help.");
        Scanner scanner = new Scanner(System.in, "UTF-8");
        System.out.print(PROMPT + ": ");
        String input = scanner.nextLine();

        HasInitClient hasInitClient = new HasInitClient(hasConfig, new File(confDirPath));
        while (!(input.equals("quit") || input.equals("exit") || input.equals("q"))) {
            try {
                execute(hasInitClient, input);
            } catch (KrbException e) {
                System.err.println(e.getMessage());
            }
            System.out.print(PROMPT + ": ");
            input = scanner.nextLine();
        }
    }

    private static void execute(HasInitClient hasInitClient, String input) throws KrbException {
        input = input.trim();
        if (input.startsWith("cmd")) {
            System.out.println(LEGAL_COMMANDS);
            return;
        }
        String[] items = input.split("\\s+");
        String cmd = items[0];

        InitCmd executor;
        if (cmd.equals("start_kdc")
            || cmd.equals("start")) {
            executor = new StartKdcCmd(hasInitClient);
        } else if (cmd.equals("init_kdc")
            || cmd.equals("init")) {
            executor = new InitKdcCmd(hasInitClient);
        } else {
            System.out.println(LEGAL_COMMANDS);
            return;
        }
        executor.execute(items);
    }
}

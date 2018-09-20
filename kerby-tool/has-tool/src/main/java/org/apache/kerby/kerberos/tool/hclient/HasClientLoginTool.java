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
package org.apache.kerby.kerberos.tool.hclient;

import org.apache.kerby.has.client.HasAuthAdminClient;
import org.apache.kerby.has.client.HasClient;
import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.common.util.HasJaasLoginUtil;
import org.apache.kerby.has.common.util.HasUtil;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.JaasKrbUtil;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcUtil;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.apache.kerby.util.OSUtil;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class HasClientLoginTool {
    private static List<String> principalList = new ArrayList<String>();
    private static List<File>  keytabList = new ArrayList<File>();

    private static final String KEYTAB_USAGE = (OSUtil.isWindows()
        ? "Usage: bin\\k=login-test.cmd" : "Usage: sh bin/login-test.sh")
        + " [add|run|delete] [conf_dir] [work_dir] [number]\n"
        + "\n";

    private static final String TGT_USAGE = (OSUtil.isWindows()
        ? "Usage: bin\\k=login-test.cmd" : "Usage: sh bin/login-test.sh")
        + " tgt [conf_dir] [plugin_type]\n"
        + "\n";

    private static void printKeytabUsage(String error) {
        System.err.println(error + "\n");
        System.err.println(KEYTAB_USAGE);
        System.exit(-1);
    }

    private static void printTgtUsage(String error) {
        System.err.println(error + "\n");
        System.err.println(TGT_USAGE);
        System.exit(-1);
    }

    public static class Task implements Runnable {
        private int index;

        Task(int index) {
            this.index = index;
        }

        @Override
        public void run() {
            Subject subject = null;
            try {
                subject = JaasKrbUtil.loginUsingKeytab(principalList.get(index),
                    keytabList.get(index));
            } catch (LoginException e) {
                System.err.println("Failed to login using keytab. " + e);
            }
            if (subject != null) {
                System.out.println("Login succeeded for user: "
                    + subject.getPrincipals().iterator().next());
            }
        }
    }

    public static void main(String[] args) {

        if (args.length < 3) {
            System.err.println(TGT_USAGE);
            System.err.println(KEYTAB_USAGE);
            return;
        }

        String cmd = args[0];
        File confDir;
        File workDir;

        if (cmd.equals("tgt")) {
            if (args.length != 3) {
                printTgtUsage("Need 3 args.");
                return;
            }

            confDir = new File(args[1]);
            if (!confDir.exists()) {
                printTgtUsage("Need the valid conf dir.");
                return;
            }
            File confFile = new File(confDir, "admin.conf");
            HasConfig hasConfig;
            try {
                hasConfig = HasUtil.getHasConfig(confFile);
            } catch (HasException e) {
                System.err.println(e.getMessage());
                return;
            }
            if (hasConfig == null) {
                System.err.println("admin.conf not exist in " + confDir.getAbsolutePath());
                return;
            }
            String host = hasConfig.getHttpsHost();
            String port = hasConfig.getHttpsPort();
            String type = args[2];

            HasClient hasClient = new HasClient();
            TgtTicket tgtTicket;
            try {
                tgtTicket = hasClient.requestTgt();
            } catch (HasException e) {
                System.err.println("Errors occurred when getting TGT. " + e.getMessage());
                return;
            }

            System.out.println("Get the tgt ticket successfully!");
            System.out.println("The client principal of tgt ticket: " + tgtTicket.getClientPrincipal());

            Subject subject = null;
            try {
                subject = HasJaasLoginUtil.loginUserFromTgtTicket(
                    "https://" + host + ":" + port + "/has/v1?auth_type=" + type);
            } catch (IOException e) {
                System.err.println("Errors occurred when login user with TGT. " + e.getMessage());
                return;
            }

            System.out.println("Principal: " + subject.getPrincipals().iterator().next());
        } else {
            if (args.length != 4) {
                printKeytabUsage("Need 4 args.");
                return;
            }

            confDir = new File(args[1]);
            workDir = new File(args[2]);

            if (!confDir.exists()) {
                printKeytabUsage("Need the valid conf dir.");
                return;
            }
            if (!workDir.exists()) {
                printKeytabUsage("Need the valid work dir.");
                return;
            }

            int taskNum = Integer.parseInt(args[3]);

            System.out.println("The task num is: " + taskNum);

            if (taskNum <= 0) {
                printKeytabUsage("The task num must be greater than zero");
                System.exit(-1);
            }

            HasAuthAdminClient authHasAdminClient = null;
            File confFile = new File(confDir, "admin.conf");
            HasConfig hasConfig;
            try {
                hasConfig = HasUtil.getHasConfig(confFile);
            } catch (HasException e) {
                System.err.println(e.getMessage());
                return;
            }

            if (hasConfig == null) {
                System.err.println("admin.conf not exist in " + confDir.getAbsolutePath());
                return;
            }

            if (hasConfig.getFilterAuthType().equals("kerberos")) {
                authHasAdminClient = new HasAuthAdminClient(hasConfig);
            }

            String realm = null;
            try {
                KdcConfig kdcConfig = KdcUtil.getKdcConfig(confDir);
                if (kdcConfig == null) {
                    printKeytabUsage("Please set the right conf dir.");
                }
                realm = kdcConfig.getKdcRealm();
            } catch (KrbException e) {
                printKeytabUsage(e.getMessage());
            }

            if (cmd.equals("add")) {
                for (int i = 0; i < taskNum; i++) {
                    String principal = "test" + i + "@" + realm;
                    try {
                        authHasAdminClient.addPrincipal(principal);
                    } catch (KrbException e) {
                        System.err.println("Errors occurred when adding principal. "
                            + e.getMessage());
                        return;
                    }
                    File keytabFile = new File(workDir, i + ".keytab");
                    try {
                        authHasAdminClient.exportKeytab(keytabFile, principal);
                    } catch (KrbException e) {
                        System.err.println("Errors occurred when exporting the keytabs. "
                            + e.getMessage());
                        return;
                    }
                    System.out.println("Add principals and keytabs successfully.");
                }
            } else if (cmd.equals("run")) {
                ExecutorService exec;
                for (int i = 0; i < taskNum; i++) {
                    String principal = "test" + i + "@" + realm;
                    principalList.add(i, principal);
                    File file = new File(workDir, i + ".keytab");
                    keytabList.add(i, file);
                }
                System.out.println("Start the login test.");
                Long startTime = System.currentTimeMillis();
                exec = Executors.newFixedThreadPool(5);
                for (int i = 0; i < taskNum; ++i) {
                    exec.submit(new Task(i));
                }
                exec.shutdown();
                try {
                    exec.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
                } catch (InterruptedException e) {
                    System.err.println(e.getMessage());
                    return;
                }
                Long endTime = System.currentTimeMillis();
                System.out.println("Finish the login test.");
                System.out.println("Cost time: " + (endTime - startTime) + "ms");
            } else if (cmd.equals("delete")) {
                for (int i = 0; i < taskNum; i++) {
                    String principal = "test" + i + "@" + realm;
                    try {
                        authHasAdminClient.deletePrincipal(principal);
                    } catch (KrbException e) {
                        System.err.println("Errors occurred when deleting the principal. "
                            + e.getMessage());
                        continue;
                    }
                    File file = new File(workDir, i + ".keytab");
                    if (!file.delete()) {
                        System.err.println("Failed to delete " + i + ".keytab.");
                    }
                }
                System.out.println("Delete principals and keytabs successfully.");
            } else {
                printKeytabUsage("Need the cmd with add, run or delete.");
            }
        }
    }
}

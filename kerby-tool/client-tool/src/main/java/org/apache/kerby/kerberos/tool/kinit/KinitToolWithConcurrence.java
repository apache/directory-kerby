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
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbKdcOption;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.client.KrbOptionGroup;
import org.apache.kerby.kerberos.kerb.client.PkinitOption;
import org.apache.kerby.kerberos.kerb.client.TokenOption;
import org.apache.kerby.util.OSUtil;
import java.io.File;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * kinit like tool with concurrence
 *
 * Ref. MIT kinit command tool usage.aa
 */
public class KinitToolWithConcurrence {
    /**
     * control the number of request
     */
    private static int[] reList = new int[100000];
    private static String[] prList = new String[10000];
    private static KOptions ktOptions = new KOptions();
    private static int thFlag = 0;
    private static Long startTime = 0L;
    private static Lock lock = new ReentrantLock();
    private static int tmpTotals = 0;
    private static final int INTERVAL = 16;

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

    private static void requestTicket(String principal,
                                      KOptions ktOptions, int flag) throws KrbException {
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
            String password = "12";
            ktOptions.add(KinitOption.USER_PASSWD, password);
        }

        KrbClient krbClient = null;
        try {
            krbClient = getClient(confDir);
        } catch (KrbException e) {
            System.err.println("Create krbClient failed: " + e.getMessage());
            System.exit(1);
        }

        KOptions results =  convertOptions(ktOptions);
        try {
            flag *= INTERVAL;
            while (true) {
                krbClient.requestTgt(results);
                reList[flag] += 1;
            }
        } catch (KrbException e) {
            System.err.println("Authentication failed: " + e.getMessage());
            System.exit(1);
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
        KinitOption kto;
        String principalNumbers = null;
        String startIndex = null;

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
                principalNumbers = opt;
                kto = KinitOption.NONE;
                // require a parameter
                startIndex = args[i++];
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

        int threadNumbers = Integer.parseInt(principalNumbers);
        int stIndex = Integer.parseInt(startIndex);

        if (threadNumbers <= 0) {
            printUsage("principal must be greater than zero");
            System.exit(-1);
        }

        for (int j = 0; j < threadNumbers; j++) {
            int tmpIndex = j + stIndex;
            String tempName = "E" + tmpIndex + "@EXAMPLE.COM";
            prList[j] = tempName;
        }

        for (int j = 0; j < threadNumbers; j++) {
            Thread th = new Thread(new PreThread());
            th.start();
        }

        // statistical
        int[] tempDelayNumbers = new int[threadNumbers];
        int[] delayNumbers = new int[threadNumbers];
        startTime = System.currentTimeMillis();
        Long timeStamp = System.currentTimeMillis();

        int max = 0;
        int min = 0;

        System.out.println("Time stamp (sec),Throughput (sec),"
                + "avgDelay (ms),maxDelay (ms),minDelay (ms)");

        while (true) {
            Thread.sleep(2000);
            int temp = 0;
            Long now = System.currentTimeMillis();

            for (int j = 0; j < threadNumbers; j++) {
                delayNumbers[j] = reList[j * INTERVAL] - tempDelayNumbers[j];
                tempDelayNumbers[j] =  reList[j * INTERVAL];
            }

            for (int j = 0; j < threadNumbers; j++) {
                temp += reList[j * INTERVAL];
            }
            float res = (now - startTime) / 1000;

            double totalDelay = 0.0;
            int cutThreads = 0;
            for (int j = 0; j < threadNumbers; j++) {
                if (delayNumbers[j] != 0) {
                    if (delayNumbers[max] < delayNumbers[j]) {
                        max = j;
                    }
                    if (delayNumbers[min] == 0 || delayNumbers[min] > delayNumbers[j]) {
                        min = j;
                    }
                    totalDelay += (now - startTime) * 1.0 / delayNumbers[j];
                } else {
                    cutThreads += 1;
                }
            }
            if (delayNumbers[min] != 0 && delayNumbers[max] != 0) {
                System.out.println((now - timeStamp) / 1000 + "," + (temp - tmpTotals) / res
                        + "," + (int) (totalDelay / (threadNumbers - cutThreads))
                        + "," + (now - startTime) / delayNumbers[min] + "," + (now - startTime) / delayNumbers[max]);
            }

            tmpTotals = temp;
            startTime = now;
        }

    }

    public static class PreThread implements Runnable {
        @Override
        public void run() {
            try {
                request();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void request() throws Exception {
        int tempFlag = 0;
        lock.lock();
        try {
            tempFlag = thFlag;
            thFlag++;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            lock.unlock();
        }
        requestTicket(prList[tempFlag], ktOptions, tempFlag);
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
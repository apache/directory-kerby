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
package org.apache.kerby.kerberos.tool.kadmin.tool;

import org.apache.kerby.KOptionType;
import org.apache.kerby.KOptions;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;

import java.util.Scanner;

public class KadminTool {

    /**
     * Init the identity backend from backend configuration.
     */
    public static IdentityBackend getBackend(Config backendConfig) {
        String backendClassName = backendConfig.getString(
                KdcConfigKey.KDC_IDENTITY_BACKEND);
        if (backendClassName == null) {
            throw new RuntimeException("Can not find the IdentityBackend class");
        }

        Class<?> backendClass = null;
        try {
            backendClass = Class.forName(backendClassName);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("Failed to load backend class: "
                    + backendClassName);
        }

        IdentityBackend backend;
        try {
            backend = (IdentityBackend) backendClass.newInstance();
        } catch (InstantiationException | IllegalAccessException e) {
            throw new RuntimeException("Failed to create backend: "
                    + backendClassName);
        }

        backend.setConfig(backendConfig);
        backend.initialize();
        return backend;
    }

    public static void printUsage(String error, String USAGE) {
        System.err.println(error + "\n");
        System.err.println(USAGE);
    }

    public static KOptions parseOptions(String[] commands, int beginIndex, int endIndex) {
        KadminOption kOption;
        String opt, error, param;

        if(beginIndex < 0) {
            System.out.println("Invalid function parameter(s).");
            return null;
        }

        KOptions kOptions = new KOptions();
        int i = beginIndex;
        while (i <= endIndex) {
            error = null;
            opt = commands[i++];
            if (opt.startsWith("-")) {
                kOption = KadminOption.fromName(opt);
                if (kOption == KadminOption.NONE) {
                    error = "Invalid option:" + opt;
                }
            } else {
                kOption = KadminOption.NONE;
                error = "Invalid parameter:" + opt + " , it does not belong to any option.";
            }

            if (kOption.getType() != KOptionType.NOV) { // require a parameter
                param = null;
                if (i <= endIndex) {
                    param = commands[i++];
                }
                if (param != null) {
                    kOptions.parseSetValue(kOption, param);
                } else {
                    error = "Option " + opt + " require a parameter";
                }
            }
            if (error != null) {
                System.out.println(error);
                return null;
            }
            kOptions.add(kOption);
        }
        return kOptions;
    }

    public static String getReplay(String prompt) {
        Scanner scanner = new Scanner(System.in);
        System.out.println(prompt);
        return scanner.nextLine().trim();
    }
}

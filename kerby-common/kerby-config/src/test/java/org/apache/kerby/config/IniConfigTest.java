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
package org.apache.kerby.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

import static org.assertj.core.api.Assertions.assertThat;

public class IniConfigTest {

    private static final File TEST_DIR = new File(System.getProperty("test.dir", "target"));
    private static final File TEST_FILE = new File(TEST_DIR, "test-ini-config");

    @BeforeEach
    public void setUp() throws IOException {
        if (TEST_FILE.exists()) {
            TEST_FILE.delete();
        }
        buildFile();
    }

    /**
     * Build a INI format configuration file.
     */
    private void buildFile() throws IOException {
        PrintWriter out = new PrintWriter(new FileWriter(TEST_FILE));
        out.println("#note = notenote");
        out.println("default = FILE:/var/log/krb5libs.log");
        out.println("kdc = FILE:/var/log/krb5kdc.log");
        out.println("admin_server = FILE:/var/log/kadmind.log");
        out.println("[libdefaults]");
        out.println("default_realm = EXAMPLE.COM");
        out.println("dns_lookup_realm = false");
        out.println("dns_lookup_kdc = false");
        out.println("ticket_lifetime = 24h");
        out.println("renew_lifetime = 7d");
        out.println("forwardable = true");
        out.println("[lib1]");
        out.println("default_realm = EXAMPLE.COM1");
        out.println("dns_lookup_realm = true");
        out.close();
    }

    @Test
    public void testIniConfig() throws IOException {
        Conf conf = new Conf();
        conf.addIniConfig(TEST_FILE);

        assertThat(conf.getString("default")).isEqualTo("FILE:/var/log/krb5libs.log");
        assertThat(conf.getString("#note")).isNull(); //Comments should be ignored when loading.

        Config config = conf.getConfig("libdefaults");
        assertThat(config.getBoolean("dns_lookup_realm")).isFalse();
        assertThat(config.getBoolean("forwardable")).isTrue();

        Config config1 = conf.getConfig("lib1");
        assertThat(config1.getBoolean("dns_lookup_realm")).isTrue();
    }

    @AfterEach
    public void tearDown() {
        TEST_FILE.delete();
    }
}

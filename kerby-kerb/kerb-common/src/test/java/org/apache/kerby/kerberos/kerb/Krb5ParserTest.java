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
package org.apache.kerby.kerberos.kerb;

import org.apache.kerby.kerberos.kerb.common.Krb5Parser;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A unit test for Krb5Parser.
 * Checked the number of sections, the name of
 * sections, and contents of a section.
 */
public class Krb5ParserTest {

    @Test
    public void test() throws IOException {
        URL url = Krb5ParserTest.class.getResource("/krb5.conf");
        Krb5Parser k = new Krb5Parser(new File(url.getFile()));
        k.load();

        assertThat(k.getSections()).hasSize(5);
        assertThat(k.getSections()).containsOnly("include", "libdefaults", "realms", "domain_realm", "logging");

        // include
        assertThat(k.getSection("include")).isEqualTo("/etc");

        // [libdefaults] section
        assertThat(k.getSection("libdefaults")).isInstanceOf(Map.class);
        assertThat((Map<String, Object>) k.getSection("libdefaults")).hasSize(14);
        assertThat(k.getSection("libdefaults", "default_realm")).isEqualTo("KRB.COM");
        assertThat(k.getSection("libdefaults", "dns_lookup_kdc")).isEqualTo("false");
        assertThat(k.getSection("libdefaults", "default_tkt_enctypes")).isEqualTo("des-cbc-crc");

        // [realms] section
        assertThat(k.getSection("realms")).isInstanceOf(Map.class);
        assertThat((Map<String, Object>) k.getSection("realms")).hasSize(3);

        assertThat(k.getSection("realms", "ATHENA.MIT.EDU")).isInstanceOf(Map.class);
        assertThat((Map<String, Object>) k.getSection("realms", "ATHENA.MIT.EDU")).hasSize(4);
        assertThat(k.getSection("realms", "ATHENA.MIT.EDU", "admin_server")).isEqualTo("KERBEROS.MIT.EDU");
        assertThat(k.getSection("realms", "ATHENA.MIT.EDU", "v4_instance_convert")).isInstanceOf(Map.class);
        assertThat(k.getSection("realms", "ATHENA.MIT.EDU", "v4_instance_convert", "mit")).isEqualTo("mit.edu");
        assertThat(k.getSection("realms", "ATHENA.MIT.EDU", "auth_to_local")).isInstanceOf(List.class);
        assertThat((List) k.getSection("realms", "ATHENA.MIT.EDU", "auth_to_local")).hasSize(4);

        assertThat(k.getSection("realms", "ANDREW.CMU.EDU")).isInstanceOf(Map.class);
        assertThat((Map<String, Object>) k.getSection("realms", "ANDREW.CMU.EDU")).hasSize(1);
        assertThat(k.getSection("realms", "ANDREW.CMU.EDU", "admin_server")).isEqualTo("vice28.fs.andrew.cmu.edu");

        assertThat(k.getSection("realms", "GNU.ORG")).isInstanceOf(Map.class);
        assertThat((Map<String, Object>) k.getSection("realms", "GNU.ORG")).hasSize(3);
        assertThat(k.getSection("realms", "GNU.ORG", "admin_server")).isEqualTo("kerberos.gnu.org");

        // [domain_realm] section
        assertThat(k.getSection("domain_realm")).isInstanceOf(Map.class);
        assertThat((Map<String, Object>) k.getSection("domain_realm")).hasSize(5);
        assertThat(k.getSection("domain_realm", ".mit.edu")).isEqualTo("ATHENA.MIT.EDU");
        assertThat(k.getSection("domain_realm", "mit.edu")).isEqualTo("ATHENA.MIT.EDU");

        // [logging] section
        assertThat(k.getSection("logging")).isInstanceOf(Map.class);
        assertThat((Map<String, Object>) k.getSection("logging")).hasSize(3);
        assertThat(k.getSection("logging", "default")).isEqualTo("FILE:/var/log/krb5libs.log");

    }
}

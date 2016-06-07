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

        assertThat(k.getSections().size()).isEqualTo(4);
        assertThat(k.getSections().contains("libdefaults")).isTrue();

        assertThat(k.getSection("libdefaults", "dns_lookup_kdc")).isEqualTo("false");
        assertThat(k.getSection("realms", "ATHENA.MIT.EDU") instanceof Map).isTrue();
        assertThat(k.getSection("realms", "ATHENA.MIT.EDU", "v4_instance_convert") instanceof  Map).isTrue();
        assertThat(k.getSection("realms", "ATHENA.MIT.EDU", "v4_instance_convert", "mit").equals("mit.edu"));
    }
}

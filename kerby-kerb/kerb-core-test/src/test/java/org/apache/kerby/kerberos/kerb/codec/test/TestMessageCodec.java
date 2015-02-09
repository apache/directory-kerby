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
package org.apache.kerby.kerberos.kerb.codec.test;

import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.junit.Before;

import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;

public class TestMessageCodec {
    private Keytab defaultKeytab;

    @Before
    public void initDefaultKeytab() throws IOException {
        InputStream inputStream = TestMessageCodec.class.getResourceAsStream("/test-enc.keytab");
        defaultKeytab = Keytab.loadKeytab(inputStream);
        inputStream.close();
    }

    protected byte[] readBinaryFile(String path) throws IOException {
        InputStream is = TestMessageCodec.class.getResourceAsStream(path);
        byte[] bytes = new byte[is.available()];
        is.read(bytes);
        is.close();
        return bytes;
    }

    protected Keytab getDefaultKeytab() {
        return defaultKeytab;
    }

    protected long parseDateByDefaultFormat(String dateString) throws ParseException {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
        sdf.setTimeZone(new SimpleTimeZone(0, "Z"));
        Date date = sdf.parse(dateString);
        return date.getTime();
    }
}

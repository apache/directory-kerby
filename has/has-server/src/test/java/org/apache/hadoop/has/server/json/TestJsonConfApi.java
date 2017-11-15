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
package org.apache.hadoop.has.server.json;

import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.core.util.MultivaluedMapImpl;
import org.apache.hadoop.has.server.TestRestApiBase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.io.File;
import java.io.IOException;
import javax.ws.rs.core.MultivaluedMap;

import static org.junit.Assert.assertEquals;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class TestJsonConfApi extends TestRestApiBase {

    @Test
    public void testSetPlugin() {
        WebResource webResource = getWebResource("conf/setplugin");
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("plugin", "RAM");
        String response = webResource.queryParams(params).put(String.class);
        assertEquals("HAS plugin set successfully.\n", response);
    }

    @Test
    public void testConfigKdcBackend() {
        WebResource webResource = getWebResource("conf/configkdcbackend");
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("backendType", "json");
        String backend = null;
        try {
            backend = new File(testDir, "json-backend").getCanonicalPath();
        } catch (IOException e) {
            e.printStackTrace();
        }
        params.add("dir", backend);
        String response = webResource.queryParams(params).put(String.class);
        assertEquals("Json backend set successfully.\n", response);
    }

    @Test
    public void testConfigXJsonKdc() {
        WebResource webResource = getWebResource("conf/configkdc");
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("realm", "HADOOP.COM");
        params.add("host", "localhost");
        params.add("port", "8866");
        String response = webResource.queryParams(params).put(String.class);
        assertEquals("HAS server KDC set successfully.\n", response);
    }

    @Test
    public void testGetKrb5Conf() {
        getKrb5Conf();
    }

    @Test
    public void testGetHasConf() {
        getHasConf();
    }
}

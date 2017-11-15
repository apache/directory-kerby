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

import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.core.util.MultivaluedMapImpl;
import org.apache.hadoop.has.server.TestRestApiBase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import javax.ws.rs.core.MultivaluedMap;

import static org.junit.Assert.assertEquals;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class TestJsonHadminApi extends TestRestApiBase {

    @Test
    public void testCreatePrincipals() {
        createPrincipals();
    }

    @Test
    public void testExportKeytabs() {
        exportKeytabs();
    }

    @Test
    public void testExportKeytab() {
        exportKeytab();
    }

    @Test
    public void testAddPrincipal() {
        addPrincipal();
    }

    @Test
    public void testGetPrincipals() {
        getPrincipals();
    }

    @Test
    public void testRenamePrincipal() {
        renamePrincipal();
    }

    @Test
    public void testXDeletePrincipal() {
        deletePrincipal();
    }

    @Test
    public void testSetConf() {
        WebResource webResource = getWebResource("admin/setconf");
        MultivaluedMap<String, String> params = new MultivaluedMapImpl();
        params.add("isEnable", "true");
        ClientResponse response = webResource.queryParams(params).put(ClientResponse.class);
        assertEquals(200, response.getStatus());
    }
}

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
package org.apache.kerby.has.server.mysql;

import org.apache.hadoop.fs.FileUtil;
import org.apache.kerby.has.server.TestRestApiBase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.io.File;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class TestMySQLHasApi extends TestRestApiBase {

    @Test
    public void testKdcStart() {
        kdcStart();
        File backendDir = new File(testDir, "mysql-backend");
        if (backendDir.exists()) {
            FileUtil.fullyDelete(backendDir);
        }
    }

    @Test
    public void testKdcInit() {
        kdcInit();
    }
}

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
package org.apache.kerby.kerberos.kerb.identity.backend;

import org.apache.kerby.config.Conf;
import org.apache.kerby.kerberos.kdc.identitybackend.ZKConfKey;
import org.apache.kerby.kerberos.kdc.identitybackend.ZookeeperIdentityBackend;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.junit.AfterClass;
import org.junit.BeforeClass;

import java.io.File;

/**
 * Zookeeper backend test
 */
public class ZookeeperBackendTest extends BackendTestBase {
    private static File instanceDir;
    private static File dataDir;

    @BeforeClass
    public static void setup() throws KrbException {
        Conf config = new Conf();
        File testdir = new File(System.getProperty("test.dir", "target"));
        instanceDir = new File(testdir, "zookeeper");
        instanceDir.mkdirs();
        dataDir = new File(instanceDir, "data");
        dataDir.mkdirs();
        config.setString(ZKConfKey.DATA_DIR.getPropertyKey(), dataDir.getAbsolutePath());

        backend = new ZookeeperIdentityBackend(config);
        backend.initialize();
        backend.start();
    }

    @AfterClass
    public static void tearDown() throws KrbException {
        if (dataDir.exists()) {
            dataDir.delete();
        }
        if (instanceDir.exists()) {
            instanceDir.delete();
        }
        if (backend != null) {
            backend.stop();
            backend.release();
        }
    }
}

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
import org.apache.kerby.kerberos.kdc.identitybackend.MySQLConfKey;
import org.apache.kerby.kerberos.kdc.identitybackend.MySQLIdentityBackend;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

import java.io.File;
import java.io.IOException;

public class MySQLBackendTest extends BackendTestBase {
    private static File testDir = new File(System.getProperty("test.dir", "target"));
    private static File dbFile = new File(testDir, "mysqlbackend.mv.db");

    @BeforeAll
    public static void setup() throws KrbException, IOException {
        Conf config = new Conf();
        config.setString(MySQLConfKey.MYSQL_DRIVER, "org.h2.Driver");
        config.setString(MySQLConfKey.MYSQL_URL,
                "jdbc:h2:" + testDir.getCanonicalPath() + "/mysqlbackend;MODE=MySQL");
        config.setString(MySQLConfKey.MYSQL_USER, "root");
        config.setString(MySQLConfKey.MYSQL_PASSWORD, "123456");
        backend = new MySQLIdentityBackend(config);
        backend.initialize();
    }

    @AfterAll
    public static void tearDown() throws KrbException {
        if (backend != null) {
            backend.stop();
        }
        if (dbFile.exists() && !dbFile.delete()) {
            System.err.println("Failed to delete the test database file.");
        }
    }
}

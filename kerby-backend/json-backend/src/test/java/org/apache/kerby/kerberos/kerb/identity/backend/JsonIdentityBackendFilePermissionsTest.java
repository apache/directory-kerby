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
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kdc.identitybackend.JsonIdentityBackend;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

import static java.nio.file.attribute.PosixFilePermission.OWNER_READ;
import static java.nio.file.attribute.PosixFilePermission.OWNER_WRITE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class JsonIdentityBackendFilePermissionsTest {

    @TempDir
    Path tempDir;

    @Test
    public void testKdbFileHasOwnerOnlyPermissions() throws KrbException, Exception {
        assumeTrue(tempDir.getFileSystem().supportedFileAttributeViews().contains("posix"),
                "Skipping: POSIX file permissions not supported on this OS");

        Config backendConfig = new Conf();
        backendConfig.setString(JsonIdentityBackend.JSON_IDENTITY_BACKEND_DIR,
                tempDir.toString());
        JsonIdentityBackend backend = new JsonIdentityBackend(backendConfig);
        backend.initialize();

        Path kdbFile = tempDir.resolve("json-backend.json");
        assertThat(kdbFile).exists();

        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(kdbFile);
        assertThat(perms)
                .as("KDB file should be readable and writable by owner only")
                .containsExactlyInAnyOrder(OWNER_READ, OWNER_WRITE);
    }
}

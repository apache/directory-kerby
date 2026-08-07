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
package org.apache.kerby.kerberos.kerb.admin.kadmin.local;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

import static java.nio.file.attribute.PosixFilePermission.OWNER_READ;
import static java.nio.file.attribute.PosixFilePermission.OWNER_WRITE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class AdminHelperFilePermissionsTest {

    @TempDir
    Path tempDir;

    @Test
    public void testNewKeytabFileHasOwnerOnlyPermissions() throws Exception {
        assumeTrue(tempDir.getFileSystem().supportedFileAttributeViews().contains("posix"),
                "Skipping: POSIX file permissions not supported on this OS");

        File keytabFile = tempDir.resolve("test.keytab").toFile();
        AdminHelper.createOrLoadKeytab(keytabFile);

        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(keytabFile.toPath());
        assertThat(perms)
                .as("keytab file should be readable and writable by owner only")
                .containsExactlyInAnyOrder(OWNER_READ, OWNER_WRITE);
    }

    @Test
    public void testExistingKeytabLoadDoesNotBroadenPermissions() throws Exception {
        assumeTrue(tempDir.getFileSystem().supportedFileAttributeViews().contains("posix"),
                "Skipping: POSIX file permissions not supported on this OS");

        File keytabFile = tempDir.resolve("existing.keytab").toFile();
        // Create the file with restricted permissions first, then reload it
        AdminHelper.createOrLoadKeytab(keytabFile);
        AdminHelper.createOrLoadKeytab(keytabFile);

        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(keytabFile.toPath());
        assertThat(perms)
                .as("loading an existing keytab should not introduce group/other read permissions")
                .doesNotContain(
                        PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE,
                        PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE);
    }
}

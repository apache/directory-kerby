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
package org.apache.kerby.benchmark;

import org.apache.kerby.config.Conf;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kdc.identitybackend.JsonIdentityBackend;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendTestUtil;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;

import java.io.File;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
public class JsonBackendBenchmark {

    private IdentityBackend backend;

    private File jsonBackendFile;

    @Setup
    public void setup() throws KrbException {
        prepareBackend();
        prepareIdentities();
    }

    private void prepareBackend() throws KrbException {
        File testDir = new File(System.getProperty("test.dir", "target"));
        jsonBackendFile = new File(testDir, "json-identity-backend-file");
        String jsonBackendFileString = jsonBackendFile.getAbsolutePath();

        Config backendConfig = new Conf();
        backendConfig.setString(JsonIdentityBackend.JSON_IDENTITY_BACKEND_DIR,
                jsonBackendFileString);
        backend = new JsonIdentityBackend(backendConfig);
        backend.initialize();
    }

    private void prepareIdentities() throws KrbException {
        BackendTestUtil.createManyIdentities(backend, 100);
        BackendTestUtil.createTheTestIdentity(backend);
    }

    @Benchmark
    @Fork(1)
    public void queryTest() throws Exception {
        BackendTestUtil.getTheTestIdentity(backend);
    }

    @TearDown
    public void cleanup() throws KrbException {
        if (backend != null) {
            backend.stop();
            backend.release();
        }

        if (jsonBackendFile.exists()) {
            jsonBackendFile.delete();
        }
    }
}

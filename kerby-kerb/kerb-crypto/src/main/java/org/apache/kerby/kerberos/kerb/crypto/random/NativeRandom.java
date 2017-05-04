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
package org.apache.kerby.kerberos.kerb.crypto.random;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * use "/dev/urandom", which is on linux, to implement RandomProvider, so it should be used on linux.
 */
public class NativeRandom implements RandomProvider {
    private static final Logger LOG = LoggerFactory
            .getLogger(NativeRandom.class);

    private InputStream input;
    private String randFile = "/dev/urandom";

    @Override
    public void init() {
        try {
            input = Files.newInputStream(Paths.get(randFile));
        } catch (IOException e) {
            LOG.error("Failed to init from file: " + randFile + ". " + e.toString());
        }
    }

    @Override
    public void setSeed(byte[] seed) {
        OutputStream output = null;
        try {
            output = Files.newOutputStream(Paths.get(randFile));
            output.write(seed);
            output.flush();
        } catch (IOException e) {
            LOG.error("Failed to write seed to the file: " + randFile + ". " + e.toString());
        } finally {
            if (output != null) {
                try {
                    output.close();
                } catch (IOException e) {
                    LOG.error("Failed to close output stream. " + e.toString());
                }
            }
        }
    }

    @Override
    public void nextBytes(byte[] bytes) {
        try {
            if (input.read(bytes) == -1) {
                throw new IOException();
            }
        } catch (IOException e) {
            LOG.error("Failed to read nextBytes. " + e.toString());
        }
    }

    @Override
    public void destroy() {
        try {
            input.close();
        } catch (IOException e) {
            LOG.error("Failed to close input stream. " + e.toString());
        }
    }
}

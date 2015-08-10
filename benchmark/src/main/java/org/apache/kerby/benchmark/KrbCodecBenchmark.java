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

import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.shared.kerberos.codec.apReq.ApReqContainer;
import org.apache.kerby.kerberos.kerb.spec.ap.ApReq;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Warmup;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class KrbCodecBenchmark {

    private static ByteBuffer apreqToken;

    static {
        InputStream is = KrbCodecBenchmark.class.getResourceAsStream("/apreq.token");
        try {
            byte[] bytes = new byte[is.available()];
            is.read(bytes);
            apreqToken = ByteBuffer.wrap(bytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Benchmark
    @Fork(1)
    @Warmup(iterations = 5)
    public void decodeWithKerby() throws Exception {
        ApReq apReq = new ApReq();
        apReq.decode(apreqToken.duplicate());
        String serverName = apReq.getTicket().getSname().toString();
        if (serverName == null) {
            throw new RuntimeException("Decoding test failed");
        }
    }

    @Benchmark
    @Fork(1)
    @Warmup(iterations = 5)
    public void decodeWithApacheDS() throws Exception {
        ByteBuffer content = apreqToken.duplicate();
        Asn1Decoder krbDecoder = new Asn1Decoder();
        ApReqContainer apreqContainer = new ApReqContainer(content);
        krbDecoder.decode(content, apreqContainer);
        String serverName = apreqContainer.getApReq().getTicket().getSName().toString();
        if (serverName == null) {
            throw new RuntimeException("Decoding test failed");
        }
    }
}

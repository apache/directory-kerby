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
package org.apache.kerby.kerberos.kerb.type.ad;

import java.io.IOException;
import java.util.List;

import org.apache.kerby.asn1.Asn1Dumper;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceOfType;

/**
 * Contributed to the Apache Kerby Project by: Prodentity - Corrales, NM
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache DirectoryProject</a>
 */
public class ADEnctypeNegotiation extends AuthorizationDataEntry {

    private KrbSequenceOfType<Asn1Integer> myEnctypeNeg;

    public ADEnctypeNegotiation() {
        super(AuthorizationType.AD_ETYPE_NEGOTIATION);
        myEnctypeNeg = new KrbSequenceOfType<Asn1Integer>();
        myEnctypeNeg.outerEncodeable = this;
    }

    public ADEnctypeNegotiation(byte[] encoded) throws IOException {
        this();
        myEnctypeNeg.decode(encoded);
    }

    public ADEnctypeNegotiation(List<Asn1Integer> enctypeNeg) throws IOException {
        this();
        for (Asn1Integer element : enctypeNeg) {
            myEnctypeNeg.add(element);
        }
    }

    public List<Asn1Integer> getEnctypeNegotiation() {
        return myEnctypeNeg.getElements();
    }

    public void add(Asn1Integer element) {
        myEnctypeNeg.add(element);
    }

    public void clear() {
        myEnctypeNeg.clear();
    }

    @Override
    protected int encodingBodyLength() throws IOException {
        if (bodyLength == -1) {
            setAuthzData(myEnctypeNeg.encode());
            bodyLength = super.encodingBodyLength();
        }
        return bodyLength;
    }

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        super.dumpWith(dumper, indents);
        dumper.newLine();
        myEnctypeNeg.dumpWith(dumper, indents + 8);
    }
}

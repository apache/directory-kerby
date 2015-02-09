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
package org.apache.kerby.kerberos.kerb.codec;

import org.apache.kerby.asn1.LimitedByteBuffer;
import org.apache.kerby.asn1.type.AbstractAsn1Type;
import org.apache.kerby.asn1.type.Asn1Type;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.ap.ApReq;
import org.apache.kerby.kerberos.kerb.spec.common.KrbMessage;
import org.apache.kerby.kerberos.kerb.spec.common.KrbMessageType;
import org.apache.kerby.kerberos.kerb.spec.kdc.AsRep;
import org.apache.kerby.kerberos.kerb.spec.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.spec.kdc.TgsRep;
import org.apache.kerby.kerberos.kerb.spec.kdc.TgsReq;

import java.io.IOException;
import java.nio.ByteBuffer;

public class KrbCodec {

    public static byte[] encode(Asn1Type krbObj) throws KrbException {
        return krbObj.encode();
    }

    public static <T extends Asn1Type> T decode(byte[] content, Class<T> krbType) throws KrbException {
        return decode(ByteBuffer.wrap(content), krbType);
    }

    public static <T extends Asn1Type> T decode(ByteBuffer content, Class<T> krbType) throws KrbException {
        Asn1Type implObj;
        try {
            implObj = krbType.newInstance();
        } catch (Exception e) {
            throw new KrbException("Decoding failed", e);
        }

        try {
            implObj.decode(content);
        } catch (IOException e) {
            throw new KrbException("Decoding failed", e);
        }

        return (T) implObj;
    }

    public static KrbMessage decodeMessage(ByteBuffer byteBuffer) throws IOException {
        LimitedByteBuffer limitedBuffer = new LimitedByteBuffer(byteBuffer);
        int tag = AbstractAsn1Type.readTag(limitedBuffer);
        int tagNo = AbstractAsn1Type.readTagNo(limitedBuffer, tag);
        int length = AbstractAsn1Type.readLength(limitedBuffer);
        LimitedByteBuffer valueBuffer = new LimitedByteBuffer(limitedBuffer, length);

        KrbMessage msg;
        KrbMessageType msgType = KrbMessageType.fromValue(tagNo);
        if (msgType == KrbMessageType.TGS_REQ) {
            msg = new TgsReq();
        } else if (msgType == KrbMessageType.AS_REP) {
            msg = new AsRep();
        } else if (msgType == KrbMessageType.AS_REQ) {
            msg = new AsReq();
        } else if (msgType == KrbMessageType.TGS_REP) {
            msg = new TgsRep();
        } else if (msgType == KrbMessageType.AP_REQ) {
            msg = new ApReq();
        } else if (msgType == KrbMessageType.AP_REP) {
            msg = new ApReq();
        } else {
            throw new IOException("To be supported krb message type with tag: " + tag);
        }
        msg.decode(tag, tagNo, valueBuffer);

        return msg;
    }

}

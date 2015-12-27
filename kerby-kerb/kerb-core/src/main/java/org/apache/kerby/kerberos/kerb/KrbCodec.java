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
package org.apache.kerby.kerberos.kerb;

import org.apache.kerby.asn1.Asn1;
import org.apache.kerby.asn1.Tag;
import org.apache.kerby.asn1.parse.Asn1ParseResult;
import org.apache.kerby.asn1.type.Asn1Type;
import org.apache.kerby.kerberos.kerb.type.ap.ApReq;
import org.apache.kerby.kerberos.kerb.type.base.KrbError;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.type.kdc.AsRep;
import org.apache.kerby.kerberos.kerb.type.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.type.kdc.TgsRep;
import org.apache.kerby.kerberos.kerb.type.kdc.TgsReq;

import java.io.IOException;
import java.nio.ByteBuffer;

public class KrbCodec {

    public static byte[] encode(Asn1Type krbObj) throws KrbException {
        try {
            return krbObj.encode();
        } catch (IOException e) {
            throw new KrbException("encode failed", e);
        }
    }

    public static void encode(Asn1Type krbObj, ByteBuffer buffer) throws KrbException {
        try {
            krbObj.encode(buffer);
        } catch (IOException e) {
            throw new KrbException("Encoding failed", e);
        }
    }

    public static void decode(byte[] content, Asn1Type value) throws KrbException {
        decode(ByteBuffer.wrap(content), value);
    }

    public static void decode(ByteBuffer content, Asn1Type value) throws KrbException {
        try {
            value.decode(content);
        } catch (IOException e) {
            throw new KrbException("Decoding failed", e);
        }
    }

    public static <T extends Asn1Type> T decode(
            byte[] content, Class<T> krbType) throws KrbException {
        return decode(ByteBuffer.wrap(content), krbType);
    }

    public static <T extends Asn1Type> T decode(
            ByteBuffer content, Class<T> krbType) throws KrbException {
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

    public static KrbMessage decodeMessage(ByteBuffer buffer) throws IOException {
        Asn1ParseResult parsingResult = Asn1.parse(buffer);
        Tag tag = parsingResult.tag();
        KrbMessage msg;
        KrbMessageType msgType = KrbMessageType.fromValue(tag.tagNo());
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
        } else if (msgType == KrbMessageType.KRB_ERROR) {
            msg = new KrbError();
        } else {
            throw new IOException("To be supported krb message type with tag: " + tag);
        }

        msg.decode(parsingResult);
        return msg;
    }

}

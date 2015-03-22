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
package org.apache.kerby.kerberos.kerb.spec.base;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.provider.TokenEncoder;
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 KRB-TOKEN_VALUE ::= SEQUENCE {
    token-format [0] INTEGER,
    token-value  [1] OCTET STRING,
 }
 */
public class KrbToken extends KrbSequenceType implements AuthToken {
    private static TokenEncoder tokenEncoder;

    private static int TOKEN_FORMAT = 0;
    private static int TOKEN_VALUE = 1;

    private AuthToken innerToken = null;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(TOKEN_FORMAT, 0, Asn1Integer.class),
            new Asn1FieldInfo(TOKEN_VALUE, 1, Asn1OctetString.class)
    };

    public KrbToken() {
        super(fieldInfos);
    }

    @Override
    public void encode(ByteBuffer buffer) {
        setTokenValue(getTokenEncoder().encodeAsBytes(this));
        super.encode(buffer);
    }

    @Override
    public void decode(ByteBuffer content) throws IOException {
        super.decode(content);
        this.innerToken = getTokenEncoder().decodeFromBytes(getTokenValue());
    }

    private static TokenEncoder getTokenEncoder() {
        if (tokenEncoder == null) {
            tokenEncoder = KrbRuntime.getTokenProvider().createTokenEncoder();
        }
        return tokenEncoder;
    }

    public TokenFormat getTokenFormat() {
        Integer value = getFieldAsInteger(TOKEN_FORMAT);
        return TokenFormat.fromValue(value);
    }

    public void setTokenFormat(TokenFormat tokenFormat) {
        setFieldAsInt(TOKEN_FORMAT, tokenFormat.getValue());
    }

    public byte[] getTokenValue() {
        return getFieldAsOctets(TOKEN_VALUE);
    }

    public void setTokenValue(byte[] tokenValue) {
        setFieldAsOctets(TOKEN_VALUE, tokenValue);
    }

    @Override
    public String getSubject() {
        return innerToken.getSubject();
    }

    @Override
    public void setSubject(String sub) {
        innerToken.setSubject(sub);
    }

    @Override
    public String getIssuer() {
        return innerToken.getIssuer();
    }

    @Override
    public void setIssuer(String issuer) {
        innerToken.setIssuer(issuer);
    }

    @Override
    public List<String> getAudiences() {
        return innerToken.getAudiences();
    }

    @Override
    public void setAudiences(List<String> audiences) {
        innerToken.setAudiences(audiences);
    }

    @Override
    public boolean isIdToken() {
        return innerToken.isIdToken();
    }

    @Override
    public boolean isAcToken() {
        return innerToken.isAcToken();
    }

    @Override
    public boolean isBearerToken() {
        return innerToken.isBearerToken();
    }

    @Override
    public boolean isHolderOfKeyToken() {
        return innerToken.isHolderOfKeyToken();
    }

    @Override
    public Date getExpiredTime() {
        return innerToken.getExpiredTime();
    }

    @Override
    public void setExpiredTime(Date exp) {
        innerToken.setExpiredTime(exp);
    }

    @Override
    public Date getNotBeforeTime() {
        return innerToken.getNotBeforeTime();
    }

    @Override
    public void setNotBeforeTime(Date nbt) {
        innerToken.setNotBeforeTime(nbt);
    }

    @Override
    public Date getIssuedAtTime() {
        return innerToken.getIssuedAtTime();
    }

    @Override
    public void setIssuedAtTime(Date iat) {
        innerToken.setIssuedAtTime(iat);
    }

    @Override
    public Map<String, String> getAttributes() {
        return innerToken.getAttributes();
    }

    @Override
    public void addAttribute(String name, String value) {
        innerToken.addAttribute(name, value);
    }
}

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
import org.apache.kerby.kerberos.kerb.KrbConstant;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.provider.TokenDecoder;
import org.apache.kerby.kerberos.kerb.provider.TokenEncoder;
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * KRB-TOKEN_VALUE ::= SEQUENCE {
 * token-format [0] INTEGER,
 * token-value  [1] OCTET STRING,
 * }
 */
public class KrbToken extends KrbSequenceType implements AuthToken {
    private static TokenEncoder tokenEncoder;
    private static TokenDecoder tokenDecoder;

    private static final int TOKEN_FORMAT = 0;
    private static final int TOKEN_VALUE = 1;

    private AuthToken innerToken = null;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[]{
            new Asn1FieldInfo(TOKEN_FORMAT, 0, Asn1Integer.class),
            new Asn1FieldInfo(TOKEN_VALUE, 1, Asn1OctetString.class)
    };


    /**
     * Default constructor.
     */
    public KrbToken() {
        super(fieldInfos);
    }

    /**
     * Construct with prepared authToken and token format.
     *
     * @param authToken The authToken
     * @param format    The token format
     */
    public KrbToken(AuthToken authToken, TokenFormat format) {
        this();

        this.innerToken = authToken;
        setTokenType();
        setTokenFormat(format);
        try {
            setTokenValue(getTokenEncoder().encodeAsBytes(innerToken));
        } catch (KrbException e) {
            throw new RuntimeException("Failed to encode AuthToken", e);
        }
    }

    /**
     * Get AuthToken.
     *
     * @return The inner token.
     */
    public AuthToken getAuthToken() {
        return innerToken;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void decode(ByteBuffer content) throws IOException {
        super.decode(content);
        this.innerToken = getTokenDecoder().decodeFromBytes(getTokenValue());
        setTokenType();
    }

    /**
     * Set token type.
     */
    private void setTokenType() {
        List<String> audiences = this.innerToken.getAudiences();
        if (audiences.size() == 1 && audiences.get(0).startsWith(KrbConstant.TGS_PRINCIPAL)) {
            isIdToken(true);
        } else {
            isAcToken(true);
        }
    }

    /**
     * Get token encoder.
     * @return The token encoder
     */
    private static TokenEncoder getTokenEncoder() {
        if (tokenEncoder == null) {
            tokenEncoder = KrbRuntime.getTokenProvider().createTokenEncoder();
        }
        return tokenEncoder;
    }

    /**
     * Get token decoder.
     * @return The token decoder
     */
    private static TokenDecoder getTokenDecoder() {
        if (tokenDecoder == null) {
            tokenDecoder = KrbRuntime.getTokenProvider().createTokenDecoder();
        }
        return tokenDecoder;
    }

    /**
     * Get token format.
     * @return The token format
     */
    public TokenFormat getTokenFormat() {
        Integer value = getFieldAsInteger(TOKEN_FORMAT);
        return TokenFormat.fromValue(value);
    }

    /**
     * Set token format.
     * @param tokenFormat The token format
     */
    public void setTokenFormat(TokenFormat tokenFormat) {
        setFieldAsInt(TOKEN_FORMAT, tokenFormat.getValue());
    }

    /**
     * Get token value.
     * @return The token value
     */
    public byte[] getTokenValue() {
        return getFieldAsOctets(TOKEN_VALUE);
    }

    /**
     * Set token value.
     * @param tokenValue The token value
     */
    public void setTokenValue(byte[] tokenValue) {
        setFieldAsOctets(TOKEN_VALUE, tokenValue);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getSubject() {
        return innerToken.getSubject();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setSubject(String sub) {
        innerToken.setSubject(sub);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getIssuer() {
        return innerToken.getIssuer();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setIssuer(String issuer) {
        innerToken.setIssuer(issuer);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getAudiences() {
        return innerToken.getAudiences();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setAudiences(List<String> audiences) {
        innerToken.setAudiences(audiences);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isIdToken() {
        return innerToken.isIdToken();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void isIdToken(boolean isIdToken) {
        innerToken.isIdToken(isIdToken);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAcToken() {
        return innerToken.isAcToken();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void isAcToken(boolean isAcToken) {
        innerToken.isAcToken(isAcToken);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isBearerToken() {
        return innerToken.isBearerToken();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isHolderOfKeyToken() {
        return innerToken.isHolderOfKeyToken();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Date getExpiredTime() {
        return innerToken.getExpiredTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setExpirationTime(Date exp) {
        innerToken.setExpirationTime(exp);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Date getNotBeforeTime() {
        return innerToken.getNotBeforeTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setNotBeforeTime(Date nbt) {
        innerToken.setNotBeforeTime(nbt);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Date getIssueTime() {
        return innerToken.getIssueTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setIssueTime(Date iat) {
        innerToken.setIssueTime(iat);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, Object> getAttributes() {
        return innerToken.getAttributes();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void addAttribute(String name, Object value) {
        innerToken.addAttribute(name, value);
    }
}

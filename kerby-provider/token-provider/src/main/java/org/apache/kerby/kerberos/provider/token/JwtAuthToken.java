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
package org.apache.kerby.kerberos.provider.token;

import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * JWT auth token backed by JWT token.
 */
public class JwtAuthToken implements AuthToken {

    private static final String SUBJECT_CLAIM = "sub";
    private static final String ISSUER_CLAIM = "iss";
    private static final String AUDIENCE_CLAIM = "aud";
    private static final String EXPIRY_CLAIM = "exp";
    private static final String NOT_BEFORE_CLAIM = "nbf";
    private static final String ISSUED_AT_CLAIM = "iat";
    private static final String ID_CLAIM = "jti";

    private Boolean isIdToken = true;
    private Boolean isAcToken = false;
    private final Map<String, Object> claims = new HashMap<>();

    public JwtAuthToken() {
        // complete
    }

    public JwtAuthToken(JWTClaimsSet jwtClaims) {
        if (jwtClaims != null) {
            claims.putAll(jwtClaims.getClaims());
        }
    }

    protected JWT getJwt() {
        String jti = (String) claims.get(ID_CLAIM);
        if (jti == null || jti.isEmpty()) {
            jti = UUID.randomUUID().toString();
            claims.put(ID_CLAIM, jti);
        }

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            builder = builder.claim(entry.getKey(), entry.getValue());
        }
        PlainHeader header = new PlainHeader();
        PlainJWT jwt = new PlainJWT(header, builder.build());
        return jwt;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getSubject() {
        return (String) claims.get(SUBJECT_CLAIM);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setSubject(String sub) {
        claims.put(SUBJECT_CLAIM, sub);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getIssuer() {
        return (String) claims.get(ISSUER_CLAIM);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setIssuer(String issuer) {
        claims.put(ISSUER_CLAIM, issuer);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getAudiences() {
        return (List<String>) claims.get(AUDIENCE_CLAIM);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setAudiences(List<String> audiences) {
        claims.put(AUDIENCE_CLAIM, audiences);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isIdToken() {
        return isIdToken;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void isIdToken(boolean isIdToken) {
        this.isIdToken = isIdToken;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAcToken() {
        return isAcToken;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void isAcToken(boolean isAcToken) {
        this.isAcToken = isAcToken;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isBearerToken() {
        return true;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isHolderOfKeyToken() {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Date getExpiredTime() {
        return (Date) claims.get(EXPIRY_CLAIM);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setExpirationTime(Date exp) {
        claims.put(EXPIRY_CLAIM, exp);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Date getNotBeforeTime() {
        return (Date) claims.get(NOT_BEFORE_CLAIM);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setNotBeforeTime(Date nbt) {
        claims.put(NOT_BEFORE_CLAIM, nbt);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Date getIssueTime() {
        return (Date) claims.get(ISSUED_AT_CLAIM);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setIssueTime(Date iat) {
        claims.put(ISSUED_AT_CLAIM, iat);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, Object> getAttributes() {
        return Collections.unmodifiableMap(claims);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void addAttribute(String name, Object value) {
        claims.put(name, value);
    }
}

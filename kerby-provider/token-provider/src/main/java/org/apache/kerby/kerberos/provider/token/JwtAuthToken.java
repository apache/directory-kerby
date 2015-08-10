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
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * JWT auth token backed by JWT token.
 */
public class JwtAuthToken implements AuthToken {

    private JWTClaimsSet jwtClaims;
    private Boolean isIdToken = true;
    private Boolean isAcToken = false;

    protected JwtAuthToken() {
        this(new JWTClaimsSet());
    }

    protected JwtAuthToken(JWTClaimsSet jwtClaims) {
        this.jwtClaims = jwtClaims;
    }

    protected JwtAuthToken(ReadOnlyJWTClaimsSet jwtClaims) {
        this.jwtClaims = JwtUtil.from(jwtClaims);
    }

    protected JWT getJwt() {
        String jti = jwtClaims.getJWTID();
        if (jti == null || jti.isEmpty()) {
            jti = UUID.randomUUID().toString();
            jwtClaims.setJWTID(jti);
        }

        PlainHeader header = new PlainHeader();
        PlainJWT jwt = new PlainJWT(header, jwtClaims);
        return jwt;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getSubject() {
        return jwtClaims.getSubject();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setSubject(String sub) {
        jwtClaims.setSubject(sub);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getIssuer() {
        return jwtClaims.getIssuer();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setIssuer(String issuer) {
        jwtClaims.setIssuer(issuer);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getAudiences() {
        return jwtClaims.getAudience();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setAudiences(List<String> audiences) {
        jwtClaims.setAudience(audiences);
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
        return jwtClaims.getExpirationTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setExpirationTime(Date exp) {
        jwtClaims.setExpirationTime(exp);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Date getNotBeforeTime() {
        return jwtClaims.getNotBeforeTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setNotBeforeTime(Date nbt) {
        jwtClaims.setNotBeforeTime(nbt);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Date getIssueTime() {
        return jwtClaims.getIssueTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setIssueTime(Date iat) {
        jwtClaims.setIssueTime(iat);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, Object> getAttributes() {
        return jwtClaims.getAllClaims();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void addAttribute(String name, Object value) {
        jwtClaims.setCustomClaim(name, value);
    }
}

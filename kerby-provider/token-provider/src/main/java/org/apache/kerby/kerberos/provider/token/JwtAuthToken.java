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

    @Override
    public String getSubject() {
        return jwtClaims.getSubject();
    }

    @Override
    public void setSubject(String sub) {
        jwtClaims.setSubject(sub);
    }

    @Override
    public String getIssuer() {
        return jwtClaims.getIssuer();
    }

    @Override
    public void setIssuer(String issuer) {
        jwtClaims.setIssuer(issuer);
    }

    @Override
    public List<String> getAudiences() {
        return jwtClaims.getAudience();
    }

    @Override
    public void setAudiences(List<String> audiences) {
        jwtClaims.setAudience(audiences);
    }

    @Override
    public boolean isIdToken() {
        return true;
    }

    @Override
    public boolean isAcToken() {
        return false;
    }

    @Override
    public boolean isBearerToken() {
        return true;
    }

    @Override
    public boolean isHolderOfKeyToken() {
        return false;
    }

    @Override
    public Date getExpiredTime() {
        return jwtClaims.getExpirationTime();
    }

    @Override
    public void setExpiredTime(Date exp) {
        jwtClaims.setExpirationTime(exp);
    }

    @Override
    public Date getNotBeforeTime() {
        return jwtClaims.getNotBeforeTime();
    }

    @Override
    public void setNotBeforeTime(Date nbt) {
        jwtClaims.setNotBeforeTime(nbt);
    }

    @Override
    public Date getIssueTime() {
        return jwtClaims.getIssueTime();
    }

    @Override
    public void setIssueTime(Date iat) {
        jwtClaims.setIssueTime(iat);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return jwtClaims.getAllClaims();
    }

    @Override
    public void addAttribute(String name, Object value) {
        jwtClaims.setCustomClaim(name, value);
    }
}

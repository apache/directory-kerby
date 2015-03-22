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

import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * JWT auth token backed by JWT token.
 */
public class JwtAuthToken implements AuthToken {

    @Override
    public String getSubject() {
        return null;
    }

    @Override
    public void setSubject(String sub) {

    }

    @Override
    public String getIssuer() {
        return null;
    }

    @Override
    public void setIssuer(String issuer) {

    }

    @Override
    public List<String> getAudiences() {
        return null;
    }

    @Override
    public void setAudiences(List<String> audiences) {

    }

    @Override
    public boolean isIdToken() {
        return false;
    }

    @Override
    public boolean isAcToken() {
        return false;
    }

    @Override
    public boolean isBearerToken() {
        return false;
    }

    @Override
    public boolean isHolderOfKeyToken() {
        return false;
    }

    @Override
    public Date getExpiredTime() {
        return null;
    }

    @Override
    public void setExpiredTime(Date exp) {

    }

    @Override
    public Date getNotBeforeTime() {
        return null;
    }

    @Override
    public void setNotBeforeTime(Date nbt) {

    }

    @Override
    public Date getIssuedAtTime() {
        return null;
    }

    @Override
    public void setIssuedAtTime(Date iat) {

    }

    @Override
    public Map<String, String> getAttributes() {
        return null;
    }

    @Override
    public void addAttribute(String name, String value) {

    }
}

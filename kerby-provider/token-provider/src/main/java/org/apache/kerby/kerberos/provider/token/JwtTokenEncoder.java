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

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.provider.TokenEncoder;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;

import java.io.IOException;
import java.text.ParseException;

/**
 * JWT token encoder, implemented using Nimbus JWT library.
 */
public class JwtTokenEncoder implements TokenEncoder {

    @Override
    public byte[] encodeAsBytes(AuthToken token) throws KrbException {
        String tokenStr = encodeAsString(token);
        return tokenStr.getBytes();
    }

    @Override
    public AuthToken decodeFromBytes(byte[] content) throws IOException {
        return null;
    }

    @Override
    public String encodeAsString(AuthToken token) throws KrbException {
        if (! (token instanceof JwtAuthToken) ) {
            throw new KrbException("Unexpected AuthToken, not JwtAuthToken");
        }

        JwtAuthToken jwtAuthToken = (JwtAuthToken) token;
        JWT jwt = jwtAuthToken.getJwt();

        String tokenStr = jwt.serialize();
        return tokenStr;
    }

    @Override
    public AuthToken decodeFromString(String content) throws KrbException {
        try {
            PlainJWT jwt = PlainJWT.parse(content);
            return new JwtAuthToken(jwt.getJWTClaimsSet());
        } catch (ParseException e) {
            throw new KrbException("Failed to parse JWT token string", e);
        }
    }
}

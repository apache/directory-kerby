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
package org.apache.kerby.token;

import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import java.text.ParseException;
import java.util.*;

public class TokenTool {

    public static JWT issueToken(String principal, String group, String role) {
        // must have for kerb-token
        String krbPrincipal = principal + "@SH.INTEL.COM";

        PlainHeader header = new PlainHeader();
        //header.setCustomParameter("krbPrincipal", krbPrincipal);

        JWTClaimsSet jwtClaims = new JWTClaimsSet();

        String iss = "token-service";
        jwtClaims.setIssuer(iss);

        String sub = principal;
        jwtClaims.setSubject(sub);

        // must have for kerb-token
        jwtClaims.setSubject(krbPrincipal);

        jwtClaims.setClaim("group", group);
        if (role != null) {
            jwtClaims.setClaim("role", role);
        }

        List<String> aud = new ArrayList<String>();
        aud.add("krb5kdc-with-token-extension");
        jwtClaims.setAudience(aud);

        // Set expiration in 60 minutes
        final Date NOW =  new Date(new Date().getTime() / 1000 * 1000);
        Date exp = new Date(NOW.getTime() + 1000 * 60 * 60);
        jwtClaims.setExpirationTime(exp);

        Date nbf = NOW;
        jwtClaims.setNotBeforeTime(nbf);

        Date iat = NOW;
        jwtClaims.setIssueTime(iat);

        String jti = UUID.randomUUID().toString();
        jwtClaims.setJWTID(jti);

        PlainJWT jwt = new PlainJWT(header, jwtClaims);
        return jwt;
    }

    public static JWT decodeToken(String token) throws ParseException {
        PlainJWT jwt = PlainJWT.parse(token);

        return jwt;
    }

    public static KerbToken fromJwtToken(String token) throws ParseException {
        Map<String, Object> attrs = decodeAndExtractTokenAttributes(token);
        return new KerbToken(attrs);
    }

    public static Map<String, Object> decodeAndExtractTokenAttributes(String token) throws ParseException {
        PlainJWT jwt = PlainJWT.parse(token);

        Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.putAll(jwt.getJWTClaimsSet().getAllClaims());
        //attrs.putAll(jwt.getHeader().getCustomParameters());

        return attrs;
    }

    public static void main(String[] args) throws ParseException {
        String principal, group, role = null;

        if (args.length != 2 && args.length != 3) {
            System.out.println("This is a simple token issuing tool just for kerb-token PoC usage\n");
            System.out.println("tokeninit <username> <group> [role]\n");
            System.exit(1);
        }
        principal = args[0];
        group = args[1];
        if (args.length > 2) {
            role = args[2];
        }

        JWT jwt = issueToken(principal, group, role);
        String token = jwt.serialize();

        TokenCache.writeToken(token);
        System.out.println("Issued token: " + token);

        /*
        JWT jwt2 = decodeToken(token);
        String krbPrincipal = (String) jwt2.getHeader().getCustomParameter("krbPrincipal");
        System.out.println("Decoded token with krbprincipal: " + krbPrincipal);
        */
    }
}

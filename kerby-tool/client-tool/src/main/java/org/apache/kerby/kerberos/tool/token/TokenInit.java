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
package org.apache.kerby.kerberos.tool.token;

import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.provider.TokenDecoder;
import org.apache.kerby.kerberos.kerb.provider.TokenEncoder;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.kerberos.provider.token.JwtTokenProvider;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * This is token init simulation tool pretending passing the auth then issuing
 * a result token, and putting the token in a token cache.
 */
public class TokenInit {

    static {
        KrbRuntime.setTokenProvider(new JwtTokenProvider());
    }

    public static AuthToken issueToken(String principal, String group, String role) {
        AuthToken authToken = KrbRuntime.getTokenProvider().createTokenFactory().createToken();

        String iss = "token-service";
        authToken.setIssuer(iss);

        String sub = principal;
        authToken.setSubject(sub);

        authToken.addAttribute("group", group);
        if (role != null) {
            authToken.addAttribute("role", role);
        }

        List<String> aud = new ArrayList<String>();
        aud.add("krb5kdc-with-token-extension");
        authToken.setAudiences(aud);

        // Set expiration in 60 minutes
        final Date now =  new Date(new Date().getTime() / 1000 * 1000);
        Date exp = new Date(now.getTime() + 1000 * 60 * 60);
        authToken.setExpirationTime(exp);

        Date nbf = now;
        authToken.setNotBeforeTime(nbf);

        Date iat = now;
        authToken.setIssueTime(iat);

        return authToken;
    }

    public static void main(String[] args) throws Exception {
        String principal, group, role = null;

        if (args.length != 2 && args.length != 3) {
            System.out.println("This is a simple token issuing tool just for "
                    + "kerb-token PoC usage\n");
            System.out.println("tokeninit <username> <group> [role]\n");
            System.exit(1);
        }
        principal = args[0];
        group = args[1];
        if (args.length > 2) {
            role = args[2];
        }

        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider().createTokenEncoder();
        AuthToken token = issueToken(principal, group, role);
        String tokenStr = tokenEncoder.encodeAsString(token);
        TokenCache.writeToken(tokenStr);
        System.out.println("Issued token: " + tokenStr);

        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider().createTokenDecoder();
        AuthToken token2 = tokenDecoder.decodeFromString(tokenStr);
        System.out.println("Decoded token's subject: " + token2.getSubject());
    }
}

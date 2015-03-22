package org.apache.kerby.kerberos.provider.token;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;

/**
 * JWT token utilities.
 */
public class JwtUtil {

    public static JWTClaimsSet from(ReadOnlyJWTClaimsSet readOnlyClaims) {
        JWTClaimsSet result = new JWTClaimsSet();
        //readOnlyClaims.getAudience()

        return result;
    }
}

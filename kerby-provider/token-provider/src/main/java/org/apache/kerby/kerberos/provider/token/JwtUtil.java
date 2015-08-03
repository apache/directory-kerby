package org.apache.kerby.kerberos.provider.token;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;

/**
 * JWT token utilities.
 */
public class JwtUtil {

    /**
     * Get jwt claims set from read only jwt claims set
     *
     * @param readOnlyClaims
     */
    public static JWTClaimsSet from(ReadOnlyJWTClaimsSet readOnlyClaims) {
        JWTClaimsSet result = new JWTClaimsSet(readOnlyClaims);

        return result;
    }
}

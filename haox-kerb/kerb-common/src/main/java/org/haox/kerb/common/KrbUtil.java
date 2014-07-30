package org.haox.kerb.common;

import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class KrbUtil {

    public static String extractRealm( String principal ) {
        int pos = principal.indexOf( '@' );

        if ( pos > 0 )
        {
            return principal.substring( pos + 1 );
        }

        throw new IllegalArgumentException( "Not a valid principal, missing realm name" );
    }


    public static String extractName( String principal ) {
        int pos = principal.indexOf( '@' );

        if ( pos < 0 )
        {
            return principal;
        }

        return principal.substring( 0, pos );
    }

    public static List<EncryptionType> getEncryptionTypes(List<String> encryptionTypes) {
        if (!encryptionTypes.isEmpty()) {
            List<EncryptionType> results = new ArrayList<EncryptionType>();
            EncryptionType etype;
            for (String etypeName : encryptionTypes) {
                etype = EncryptionType.fromName(etypeName);
                if (etype != EncryptionType.UNKNOWN) {
                    results.add(etype);
                }
            }
            return results;
        }

        return Collections.emptyList();
    }
}

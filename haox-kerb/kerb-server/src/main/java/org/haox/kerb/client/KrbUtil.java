package org.haox.kerb.client;

public class KrbUtil {

    public static String extractRealm( String principal )
    {
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

}

package org.haox.token;

import com.sun.security.jgss.AuthorizationDataEntry;
import com.sun.security.jgss.ExtendedGSSContext;
import com.sun.security.jgss.InquireType;
import org.haox.asn1.type.Asn1SequenceOf;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;

import java.io.IOException;
import java.util.List;

public class TokenExtractor {
    static final int JWT_AUTHZ_DATA_TYPE = 81;
    public static final int AD_IF_RELEVANT_TYPE = 1;

    /**
     AuthorizationData       ::= SEQUENCE OF SEQUENCE {
         ad-type         [0] Int32,
         ad-data         [1] OCTET STRING
     }
     */
    public static class AuthorizationData extends Asn1SequenceOf<AuthzDataEntry> {

    }

    public static KerbToken checkAuthzData(GSSContext context) throws GSSException, IOException {
        System.out.println("Looking for token from authorization data in GSSContext");

        Object authzData = null;
        if (context instanceof ExtendedGSSContext) {
            ExtendedGSSContext ex = (ExtendedGSSContext)context;
            authzData = ex.inquireSecContext(
                    InquireType.KRB5_GET_AUTHZ_DATA);
        }

        if (authzData != null) {
            AuthorizationDataEntry[] authzEntries = (AuthorizationDataEntry[]) authzData;
            KerbToken resultToken = null;
            for (int i = 0; i < authzEntries.length; ++i) {
                resultToken = getAuthzToken(authzEntries[i]);
                if (resultToken != null) {
                    return resultToken;
                }
            }
        }
        return null;
    }

    public static KerbToken getAuthzToken(AuthorizationDataEntry authzDataEntry) throws IOException {
        if (authzDataEntry.getType() == AD_IF_RELEVANT_TYPE) {
            String token = getToken(authzDataEntry);
            if (token == null) {
                return null;
            }

            try {
                return TokenTool.fromJwtToken(token);
            } catch (Exception e) {
                // noop when not jwt token
            }
        }

        return null;
    }

    public static String getToken(AuthorizationDataEntry authzDataEntry) throws IOException {
        List<AuthzDataEntry> entries = decode(authzDataEntry);
        for (AuthzDataEntry entry : entries) {
            if (entry.getAuthzType() == JWT_AUTHZ_DATA_TYPE) {
                return new String(entry.getAuthzData());
            }
        }
        return null;
    }

    public static List<AuthzDataEntry> decode(AuthorizationDataEntry authzDataEntry) throws IOException {
        AuthorizationData authzData = new AuthorizationData();
        authzData.decode(authzDataEntry.getData());
        return authzData.getElements();
    }
}

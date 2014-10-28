package org.haox.token.gsskrb5ext;

import com.sun.security.sasl.util.PolicyUtils;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.*;
import java.security.Provider;
import java.util.Map;

/**
 * Adapted from original gssapi factory impl
 */
public class GssKrb5ExtProvider extends Provider {

    public GssKrb5ExtProvider() {
        super("GSSAPIEXT", 1.0, "GSSAPI-EXT Client");
        put("SaslClientFactory.GSSAPIEXT",
                SaslGssapiExtFactory.class.getName());
        put("SaslServerFactory.GSSAPIEXT",
                SaslGssapiExtFactory.class.getName());
    }

    public static class SaslGssapiExtFactory implements SaslClientFactory, SaslServerFactory {
        private static final String myMechs[] = {
                "GSSAPIEXT"};

        private static final int mechPolicies[] = {
                PolicyUtils.NOPLAINTEXT | PolicyUtils.NOANONYMOUS | PolicyUtils.NOACTIVE
        };

        private static final int GSS_KERB_V5 = 0;

        public SaslGssapiExtFactory() {
        }

        public SaslClient createSaslClient(String[] mechs,
                                           String authorizationId,
                                           String protocol,
                                           String serverName,
                                           Map<String, ?> props,
                                           CallbackHandler cbh) throws SaslException {

            for (int i = 0; i < mechs.length; i++) {
                if (mechs[i].equals(myMechs[GSS_KERB_V5])
                        && PolicyUtils.checkPolicy(mechPolicies[GSS_KERB_V5], props)) {
                    return new GssKrb5ClientExt(
                            authorizationId,
                            protocol,
                            serverName,
                            props,
                            cbh);
                }
            }
            return null;
        }

        public SaslServer createSaslServer(String mech,
                                           String protocol,
                                           String serverName,
                                           Map<String, ?> props,
                                           CallbackHandler cbh) throws SaslException {
            if (mech.equals(myMechs[GSS_KERB_V5])
                    && PolicyUtils.checkPolicy(mechPolicies[GSS_KERB_V5], props)) {
                if (cbh == null) {
                    throw new SaslException(
                            "Callback handler with support for AuthorizeCallback required");
                }
                return new GssKrb5ServerExt(
                        protocol,
                        serverName,
                        props,
                        cbh);
            }
            return null;
        }

        public String[] getMechanismNames(Map<String, ?> props) {
            return PolicyUtils.filterMechs(myMechs, mechPolicies, props);
        }
    }
}

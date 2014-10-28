package org.haox.kerb.client.request;

import org.haox.kerb.client.KrbContext;
import org.haox.token.KerbToken;

public class TokenAsRequest extends AsRequest {

    private KerbToken token;

    public TokenAsRequest(KrbContext context) {
        super(context);
    }

    public void setToken(KerbToken token) {
        this.token = token;
    }
}

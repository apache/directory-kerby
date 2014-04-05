package org.haox.kerb.codec.kerberos;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class KerberosCredentials {

    private Subject subject;

    public KerberosCredentials() throws LoginException {
        this(System.getProperty("jaaslounge.sso.jaas.org.haox.config"));
    }

    public KerberosCredentials(String loginContextName) throws LoginException {
        LoginContext lc = new LoginContext(loginContextName);
        lc.login();
        subject = lc.getSubject();
    }

    public KerberosKey[] getKeys() {
        List<Key> serverKeys = new ArrayList<Key>();

        Set<Object> serverPrivateCredentials = subject.getPrivateCredentials();
        for(Object credential : serverPrivateCredentials)
            if(credential instanceof KerberosKey)
                serverKeys.add((KerberosKey)credential);

        return serverKeys.toArray(new KerberosKey[0]);
    }

    public KerberosKey getKey(int keyType) {
        KerberosKey serverKey = null;

        Set<Object> serverPrivateCredentials = subject.getPrivateCredentials();
        for(Object credential : serverPrivateCredentials)
            if(credential instanceof KerberosKey)
                if(((KerberosKey)credential).getKeyType() == keyType)
                    serverKey = (KerberosKey)credential;

        return serverKey;
    }

    public Subject getSubject() {
        return subject;
    }

}

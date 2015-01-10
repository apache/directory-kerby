package org.apache.kerberos.kerb.preauth.pkinit;

import org.apache.kerberos.kerb.spec.common.PrincipalName;

public class PkinitIdenity {

    public static void processIdentityOption(IdentityOpts identityOpts, String value) {
        IdentityType idType = IdentityType.NONE;
        String residual = null;
        if (value.contains(":")) {
            if (value.startsWith("FILE:")) {
                idType = IdentityType.FILE;
            } else if (value.startsWith("PKCS11:")) {
                idType = IdentityType.PKCS11;
            } else if (value.startsWith("PKCS12:")) {
                idType = IdentityType.PKCS12;
            } else if (value.startsWith("DIR:")) {
                idType = IdentityType.DIR;
            } else if (value.startsWith("ENV:")) {
                idType = IdentityType.ENVVAR;
            } else {
                throw new RuntimeException("Invalid Identity option format: " + value);
            }
        } else {
            residual = value;
            idType = IdentityType.FILE;
        }

        identityOpts.idType = idType;
        switch (idType) {
            case ENVVAR:
                processIdentityOption(identityOpts, System.getenv(residual));
                break;
            case FILE:
                parseFileOption(identityOpts, residual);
                break;
            case PKCS11:
                parsePkcs11Option(identityOpts, residual);
                break;
            case PKCS12:
                parsePkcs12Option(identityOpts, residual);
                break;
            case DIR:
                identityOpts.certFile = residual;
                break;
        }
    }

    public static void parseFileOption(IdentityOpts identityOpts, String residual) {
        String[] parts = residual.split(",");
        String certName = null;
        String keyName = null;

        certName = parts[0];
        if (parts.length > 1) {
            keyName = parts[1];
        }

        identityOpts.certFile = certName;
        identityOpts.keyFile = keyName;
    }

    public static void parsePkcs12Option(IdentityOpts identityOpts, String residual) {
        identityOpts.certFile = residual;
        identityOpts.keyFile = residual;
    }

    public static void parsePkcs11Option(IdentityOpts identityOpts, String residual) {
        // TODO
    }

    public static void loadCerts(IdentityOpts identityOpts, PrincipalName principal) {
        switch (identityOpts.idType) {
            case FILE:
                loadCertsFromFile(identityOpts, principal);
                break;
            case DIR:
                loadCertsFromDir(identityOpts, principal);
                break;
            case PKCS11:
                loadCertsAsPkcs11(identityOpts, principal);
                break;
            case PKCS12:
                loadCertsAsPkcs12(identityOpts, principal);
                break;
        }
    }

    private static void loadCertsAsPkcs12(IdentityOpts identityOpts, PrincipalName principal) {

    }

    private static void loadCertsAsPkcs11(IdentityOpts identityOpts, PrincipalName principal) {

    }

    private static void loadCertsFromDir(IdentityOpts identityOpts, PrincipalName principal) {

    }

    private static void loadCertsFromFile(IdentityOpts identityOpts, PrincipalName principal) {

    }

    public static void initialize(IdentityOpts identityOpts, PrincipalName principal) {

    }

}

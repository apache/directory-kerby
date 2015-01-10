package org.apache.kerberos.kerb.spec.pa.pkinit;

import org.apache.kerberos.kerb.spec.KrbSequenceOfType;
import org.apache.kerberos.kerb.spec.x509.AlgorithmIdentifier;

/**
 trustedCertifiers       SEQUENCE OF AlgorithmIdentifier OPTIONAL,
 */
public class AlgorithmIdentifiers extends KrbSequenceOfType<AlgorithmIdentifier> {

}

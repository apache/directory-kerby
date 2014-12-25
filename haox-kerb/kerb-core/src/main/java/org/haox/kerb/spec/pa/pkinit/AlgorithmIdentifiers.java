package org.haox.kerb.spec.pa.pkinit;

import org.haox.kerb.spec.KrbSequenceOfType;
import org.haox.kerb.spec.x509.AlgorithmIdentifier;

/**
 trustedCertifiers       SEQUENCE OF AlgorithmIdentifier OPTIONAL,
 */
public class AlgorithmIdentifiers extends KrbSequenceOfType<AlgorithmIdentifier> {

}

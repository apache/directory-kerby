package org.haox.kerb.spec.type.pa.pkinit;

import org.haox.kerb.spec.type.KrbSequenceOfType;
import org.haox.kerb.spec.type.x509.AlgorithmIdentifier;

/**
 trustedCertifiers       SEQUENCE OF AlgorithmIdentifier OPTIONAL,
 */
public class AlgorithmIdentifiers extends KrbSequenceOfType<AlgorithmIdentifier> {

}

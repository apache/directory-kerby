/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.kerberos.kerb.type.ad;

import org.apache.kerby.asn1.EnumType;

import java.util.HashMap;
import java.util.Map;

/**
 * The various AuthorizationType values, as defined in RFC 4120 and RFC 1510.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum AuthorizationType implements EnumType {
    /**
     * Constant for the "null" authorization type.
     */
    NULL(0),

    /**
     * Constant for the "if relevant" authorization type.
     *
     * RFC 4120
     * 
     * AD elements encapsulated within the if-relevant element are intended for
     * interpretation only by application servers that understand the particular
     * ad-type of the embedded element. Application servers that do not
     * understand the type of an element embedded within the if-relevant element
     * may ignore the uninterpretable element. This element promotes
     * interoperability across implementations which may have local extensions
     * for authorization.
     */
    AD_IF_RELEVANT(1),

    /**
     * Constant for the "intended for server" authorization type.
     *
     * RFC 4120
     * 
     * AD-INTENDED-FOR-SERVER SEQUENCE { intended-server[0] SEQUENCE OF
     * PrincipalName elements[1] AuthorizationData }
     * 
     * AD elements encapsulated within the intended-for-server element may be
     * ignored if the application server is not in the list of principal names
     * of intended servers. Further, a KDC issuing a ticket for an application
     * server can remove this element if the application server is not in the
     * list of intended servers.
     * 
     * Application servers should check for their principal name in the
     * intended-server field of this element. If their principal name is not
     * found, this element should be ignored. If found, then the encapsulated
     * elements should be evaluated in the same manner as if they were present
     * in the top level authorization data field. Applications and application
     * servers that do not implement this element should reject tickets that
     * contain authorization data elements of this type.
     */
    AD_INTENDED_FOR_SERVER(2),

    /**
     * Constant for the  "intended for application class" authorization type.
     *
     * RFC 4120
     * 
     * AD-INTENDED-FOR-APPLICATION-CLASS SEQUENCE {
     * intended-application-class[0] SEQUENCE OF GeneralString elements[1]
     * AuthorizationData } AD elements
     * 
     * encapsulated within the intended-for-application-class element may be
     * ignored if the application server is not in one of the named classes of
     * application servers. Examples of application server classes include
     * "FILESYSTEM", and other kinds of servers.
     * 
     * This element and the elements it encapsulates may be safely ignored by
     * applications, application servers, and KDCs that do not implement this
     * element.
     */
    AD_INTENDED_FOR_APPLICATION_CLASS(3),

    /**
     * Constant for the "kdc issued" authorization type.
     *
     * RFC 4120
     * 
     * AD-KDCIssued SEQUENCE { ad-checksum[0] Checksum, i-realm[1] Realm
     * OPTIONAL, i-sname[2] PrincipalName OPTIONAL, elements[3]
     * AuthorizationData. }
     * 
     * ad-checksum A checksum over the elements field using a cryptographic
     * checksum method that is identical to the checksum used to protect the
     * ticket itself (i.e. using the same hash function and the same encryption
     * algorithm used to encrypt the ticket) and using a key derived from the
     * same key used to protect the ticket. i-realm, i-sname The name of the
     * issuing principal if different from the KDC itself. This field would be
     * used when the KDC can verify the authenticity of elements signed by the
     * issuing principal and it allows this KDC to notify the application server
     * of the validity of those elements. elements A sequence of authorization
     * data elements issued by the KDC.
     * 
     * The KDC-issued ad-data field is intended to provide a means for Kerberos
     * principal credentials to embed within themselves privilege attributes and
     * other mechanisms for positive authorization, amplifying the privileges of
     * the principal beyond what can be done using a credentials without such an
     * a-data element.
     * 
     * This can not be provided without this element because the definition of
     * the authorization-data field allows elements to be added at will by the
     * bearer of a TGT at the time that they request service tickets and
     * elements may also be added to a delegated ticket by inclusion in the
     * authenticator.
     */
    AD_KDC_ISSUED(4),

    /**
     * Constant for the "and/or" authorization type.
     *
     * RFC 4120
     * 
     * When restrictive AD elements encapsulated within the and-or element are
     * encountered, only the number specified in condition-count of the
     * encapsulated conditions must be met in order to satisfy this element.
     * This element may be used to implement an "or" operation by setting the
     * condition-count field to 1, and it may specify an "and" operation by
     * setting the condition count to the number of embedded elements.
     * Application servers that do not implement this element must reject
     * tickets that contain authorization data elements of this type.
     */
    AD_AND_OR(5),

    /**
     * Constant for the "mandatory ticket extensions" authorization type.
     *
     * RFC 4120
     * 
     * AD-Mandatory-Ticket-Extensions Checksum
     * 
     * An authorization data element of type mandatory-ticket-extensions
     * specifies a collision-proof checksum using the same hash algorithm used
     * to protect the integrity of the ticket itself. This checksum will be
     * calculated over the entire extensions field. If there are more than one
     * extension, all will be covered by the checksum. This restriction
     * indicates that the ticket should not be accepted if the checksum does not
     * match that calculated over the ticket extensions. Application servers
     * that do not implement this element must reject tickets that contain
     * authorization data elements of this type.
     */
    AD_MANDATORY_TICKET_EXTENSIONS(6),

    /**
     * Constant for the "in ticket extensions" authorization type.
     *
     * RFC 4120
     * 
     * AD-IN-Ticket-Extensions Checksum
     * 
     * An authorization data element of type in-ticket-extensions specifies a
     * collision-proof checksum using the same hash algorithm used to protect
     * the integrity of the ticket itself. This checksum is calculated over a
     * separate external AuthorizationData field carried in the ticket
     * extensions. Application servers that do not implement this element must
     * reject tickets that contain authorization data elements of this type.
     * Application servers that do implement this element will search the ticket
     * extensions for authorization data fields, calculate the specified
     * checksum over each authorization data field and look for one matching the
     * checksum in this in-ticket-extensions element. If not found, then the
     * ticket must be rejected. If found, the corresponding authorization data
     * elements will be interpreted in the same manner as if they were contained
     * in the top level authorization data field.
     */
    AD_IN_TICKET_EXTENSIONS(7),

    /**
     * Constant for the "mandatory-for-kdc" authorization type.
     *
     * RFC 4120
     * 
     * AD-MANDATORY-FOR-KDC ::= AuthorizationData
     * 
     * AD elements encapsulated within the mandatory-for-kdc element are to be
     * interpreted by the KDC. KDCs that do not understand the type of an
     * element embedded within the mandatory-for-kdc element MUST reject the
     * request.
     */
    AD_MANDATORY_FOR_KDC(8),

    /**
     * Constant for the "initial-verified-cas" authorization type.
     *
     * RFC 4556
     * 
     * AD-INITIAL-VERIFIED-CAS ::= SEQUENCE OF ExternalPrincipalIdentifier --
     * Identifies the certification path with which -- the client certificate
     * was validated. -- Each ExternalPrincipalIdentifier identifies a CA -- or
     * a CA certificate (thereby its public key).
     * 
     * The AD-INITIAL-VERIFIED-CAS structure identifies the certification path
     * with which the client certificate was validated. Each
     * ExternalPrincipalIdentifier (as defined in Section 3.2.1) in the AD-
     * INITIAL-VERIFIED-CAS structure identifies a CA or a CA certificate
     * (thereby its public key).
     * 
     * Note that the syntax for the AD-INITIAL-VERIFIED-CAS authorization data
     * does permit empty SEQUENCEs to be encoded. Such empty sequences may only
     * be used if the KDC itself vouches for the user's certificate.
     * 
     * The AS wraps any AD-INITIAL-VERIFIED-CAS data in AD-IF-RELEVANT
     * containers if the list of CAs satisfies the AS' realm's local policy
     * (this corresponds to the TRANSITED-POLICY-CHECKED ticket flag [RFC4120]).
     * Furthermore, any TGS MUST copy such authorization data from tickets used
     * within a PA-TGS-REQ of the TGS-REQ into the resulting ticket. If the list
     * of CAs satisfies the local KDC's realm's policy, the TGS MAY wrap the
     * data into the AD-IF-RELEVANT container; otherwise, it MAY unwrap the
     * authorization data out of the AD-IF-RELEVANT container.
     * 
     * Application servers that understand this authorization data type SHOULD
     * apply local policy to determine whether a given ticket bearing such a
     * type *not* contained within an AD-IF-RELEVANT container is acceptable.
     * (This corresponds to the AP server's checking the transited field when
     * the TRANSITED-POLICY-CHECKED flag has not been set [RFC4120].) If such a
     * data type is contained within an AD-IF- RELEVANT container, AP servers
     * MAY apply local policy to determine whether the authorization data is
     * acceptable.
     * 
     * ExternalPrincipalIdentifier ::= SEQUENCE { subjectName [0] IMPLICIT OCTET
     * STRING OPTIONAL, -- Contains a PKIX type Name encoded according to --
     * [RFC3280]. -- Identifies the certificate subject by the -- distinguished
     * subject name. -- REQUIRED when there is a distinguished subject -- name
     * present in the certificate. issuerAndSerialNumber [1] IMPLICIT OCTET
     * STRING OPTIONAL, -- Contains a CMS type IssuerAndSerialNumber encoded --
     * according to [RFC3852]. -- Identifies a certificate of the subject. --
     * REQUIRED for TD-INVALID-CERTIFICATES and -- TD-TRUSTED-CERTIFIERS.
     * subjectKeyIdentifier [2] IMPLICIT OCTET STRING OPTIONAL, -- Identifies
     * the subject's public key by a key -- identifier. When an X.509
     * certificate is -- referenced, this key identifier matches the X.509 --
     * subjectKeyIdentifier extension value. When other -- certificate formats
     * are referenced, the documents -- that specify the certificate format and
     * their use -- with the CMS must include details on matching the -- key
     * identifier to the appropriate certificate -- field. -- RECOMMENDED for
     * TD-TRUSTED-CERTIFIERS. ... }
     */
    AD_INITIAL_VERIFIED_CAS(9),

    /**
     * Constant for the "OSF DCE" authorization type.
     *
     * RFC 1510
     */
    OSF_DCE(64),

    /**
     * Constant for the "sesame" authorization type.
     *
     * RFC 4120
     */
    SESAME(65),

    /**
     * Constant for the "OSF-DCE pki certid" authorization type.
     *
     * RFC 4120
     */
    AD_OSF_DCE_PKI_CERTID(66),

    /**
     * Constant for the "CAM-MAC" authorization type.
     *
     * RFC 7751 for details.
     */
    AD_CAMMAC(96),

    /**
     * Constant for the "Windows 2K Privilege Attribute Certificate (PAC)"
     * authorization type.
     *
     * RFC 4120
     * 
     * See: Microsoft standard documents MS-PAC and MS-KILE.
     */
    AD_WIN2K_PAC(128),

    /**
     * Constant for the "EncType-Negotiation" authorization type.
     *
     * RFC 4537 for details.
     */
    AD_ETYPE_NEGOTIATION(129),

    /**
     * Constant for the "Authentication-Indicator" authorization type.
     * 
     * RFC 6711 An IANA Registry for Level of Assurance (LoA) Profiles provides
     * the syntax and semantics of LoA profiles.
     *
     * See: Internet draft "draft-jain-kitten-krb-auth-indicator-01"
     */
    AD_AUTHENTICAION_INDICATOR(-1); // Not yet assigned an IANA registry number.

    /** The internal value */
    private final int value;

    private static Map<Integer, AuthorizationType> valueMap;

    /**
     * Create a new enum 
     */
    AuthorizationType(int value) {
        this.value = value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getValue() {
        return value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName() {
        return name();
    }

    /**
     * Get the AuthorizationType associated with a value.
     * 
     * @param value The integer value of the AuthorizationType we are looking for
     * @return The associated AuthorizationType, or NULL if not found or if value is null
     */
    public static AuthorizationType fromValue(Integer value) {
        if (value != null) {
            if (valueMap == null) {
                valueMap = new HashMap<Integer, AuthorizationType>(32);
                for (EnumType e : values()) {
                    valueMap.put(e.getValue(), (AuthorizationType) e);
                }
            }
            return valueMap.get(value);
        }

        return NULL;
    }
}

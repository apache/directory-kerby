/*
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
package org.apache.kerby.kerberos.kerb.client.preauth.pkinit;


import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;


/**
 * Encapsulates working with PKINIT enveloped data structures.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class EnvelopedDataEngine
{
    /**
     * Uses a certificate to encrypt data in a CMS EnvelopedData structure and
     * returns the encoded EnvelopedData as bytes.
     * 
     * 'encKeyPack' contains a CMS type ContentInfo encoded according to [RFC3852].
     * The contentType field of the type ContentInfo is id-envelopedData (1.2.840.113549.1.7.3).
     * The content field is an EnvelopedData. The contentType field for the type
     * EnvelopedData is id-signedData (1.2.840.113549.1.7.2).
     * 
     * @param dataToEnvelope
     * @param certificate
     * @return The EnvelopedData bytes.
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws CMSException
     * @throws NoSuchProviderException
     */
    public static byte[] getEnvelopedReplyKeyPack( byte[] dataToEnvelope, X509Certificate certificate )
        throws NoSuchAlgorithmException, IOException, CMSException, NoSuchProviderException
    {
        CMSProcessableByteArray content = new CMSProcessableByteArray( dataToEnvelope );
        String algorithm = CMSEnvelopedDataGenerator.DES_EDE3_CBC;

        CMSEnvelopedDataGenerator envelopeGenerator = new CMSEnvelopedDataGenerator();
        envelopeGenerator.addKeyTransRecipient( certificate );
        CMSEnvelopedData envdata = envelopeGenerator.generate( content, algorithm, "BC" );

        return envdata.getEncoded();
    }


    /**
     * Uses a private key to decrypt data in a CMS EnvelopedData structure and
     * returns the recovered (decrypted) data bytes.
     *
     * @param envelopedDataBytes
     * @param certificate
     * @param privateKey
     * @return The recovered (decrypted) data bytes.
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws CMSException
     * @throws NoSuchAlgorithmException
     * @throws CertStoreException
     */
    @SuppressWarnings("unchecked")
    public static byte[] getUnenvelopedData( byte[] envelopedDataBytes, X509Certificate certificate,
        PrivateKey privateKey ) throws NoSuchProviderException, InvalidAlgorithmParameterException, CMSException,
        NoSuchAlgorithmException, CertStoreException
    {
        CMSEnvelopedData envelopedData = new CMSEnvelopedData( envelopedDataBytes );

        // Set up to iterate through the recipients.
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        CertStore certStore = CertStore.getInstance( "Collection", new CollectionCertStoreParameters( Collections
            .singleton( certificate ) ), "BC" );
        Iterator<RecipientInformation> it = recipients.getRecipients().iterator();

        while ( it.hasNext() )
        {
            RecipientInformation recipient = it.next();
            if ( recipient instanceof KeyTransRecipientInformation )
            {
                // Match the recipient ID.
                Collection<? extends Certificate> matches = certStore.getCertificates( recipient.getRID() );

                if ( !matches.isEmpty() )
                {
                    // Decrypt the data.
                    return recipient.getContent( privateKey, "BC" );
                }
            }
        }

        return new byte[0];
    }
}

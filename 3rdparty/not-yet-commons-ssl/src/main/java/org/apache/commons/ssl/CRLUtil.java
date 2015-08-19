/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/CRLUtil.java $
 * $Revision: 121 $
 * $Date: 2007-11-13 21:26:57 -0800 (Tue, 13 Nov 2007) $
 *
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.ssl;

/*
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
*/

import java.io.IOException;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 20-Dec-2005
 */
public class CRLUtil {

    public static String getURLToCRL(byte[] extension2_5_29_31)
        throws IOException {

        throw new UnsupportedOperationException("not yet implemented");

        /*
                    byte[] bytes = extension2_5_29_31;
                    ASN1Encodable asn1 = X509ExtensionUtil.fromExtensionValue(bytes);
                    DERObject obj = asn1.getDERObject();
                    CRLDistPoint distPoint = CRLDistPoint.getInstance(obj);
                    DistributionPoint[] points = distPoint.getDistributionPoints();
                    DistributionPointName dpn = points[0].getDistributionPoint();
                    obj = dpn.getName().toASN1Object();
                    ASN1Sequence seq = ASN1Sequence.getInstance(obj);
                    DERTaggedObject tag = (DERTaggedObject) seq.getObjectAt(0);
                    bytes = ASN1OctetString.getInstance(tag, false).getOctets();
                    return new String(bytes);
                    */
    }
}

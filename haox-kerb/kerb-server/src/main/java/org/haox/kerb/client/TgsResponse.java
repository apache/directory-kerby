package org.haox.kerb.client;

import org.apache.directory.shared.kerberos.exceptions.KerberosException;
import org.haox.kerb.spec.type.common.KrbErrorCode;
import org.haox.kerb.spec.type.kdc.EncTgsRepPart;
import org.haox.kerb.spec.type.kdc.TgsRep;
import org.haox.kerb.spec.type.ticket.ServiceTicket;

public class TgsResponse extends KdcResponse {

    public TgsResponse(KrbContext context, TgsRep tgsRep) {
        super(context, tgsRep);
    }

    @Override
    public void handle() {
        byte[] decryptedData = cipherTextHandler.decrypt(sessionKey, rep.getEncPart(), KeyUsage.TGS_REP_ENC_PART_TGS_SESS_KEY);
        EncTgsRepPart encTgsRepPart = KerberosDecoder.decodeEncTgsRepPart(decryptedData);

        if (currentNonce != encTgsRepPart.getEncKdcRepPart().getNonce())
        {
            throw new KerberosException(KrbErrorCode.KRB_ERR_GENERIC, "received nonce didn't match with the nonce sent in the request");
        }


        // Everything is fine, return the response
        LOG.debug("TGT request successful : {}", rep);

    }

    public ServiceTicket getServiceTicket() {
        ServiceTicket srvTkt = new ServiceTicket(rep.getTicket(), encTgsRepPart.getEncKdcRepPart());
        return srvTkt;
    }
}

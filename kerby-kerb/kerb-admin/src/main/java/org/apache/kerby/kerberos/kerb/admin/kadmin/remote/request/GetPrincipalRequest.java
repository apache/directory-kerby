package org.apache.kerby.kerberos.kerb.admin.kadmin.remote.request;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.message.AdminMessageCode;
import org.apache.kerby.kerberos.kerb.admin.message.AdminMessageType;
import org.apache.kerby.kerberos.kerb.admin.message.GetPrincipalReq;
import org.apache.kerby.xdr.XdrDataType;
import org.apache.kerby.xdr.XdrFieldInfo;

import java.io.IOException;
import java.nio.ByteBuffer;

public class GetPrincipalRequest extends AdminRequest {
    
    public GetPrincipalRequest(String principal) {
        super(principal);
    }

    @Override
    public void process() throws KrbException {
        super.process();

        GetPrincipalReq getPrincipalReq = new GetPrincipalReq();
        XdrFieldInfo[] xdrFieldInfos = new XdrFieldInfo[3];
        xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.GET_PRINCIPAL_REQ);
        xdrFieldInfos[1] = new XdrFieldInfo(1, XdrDataType.INTEGER, 1);
        xdrFieldInfos[2] = new XdrFieldInfo(2, XdrDataType.STRING, getPrincipal());

        AdminMessageCode value = new AdminMessageCode(xdrFieldInfos);
        byte[] encodeBytes;
        try {
            encodeBytes = value.encode();
        } catch (IOException e) {
            throw new KrbException("Xdr encode error when generate delete principal request.", e);
        }
        ByteBuffer messageBuffer = ByteBuffer.wrap(encodeBytes);
        getPrincipalReq.setMessageBuffer(messageBuffer);

        setAdminReq(getPrincipalReq);
    }
}

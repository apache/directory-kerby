package org.apache.kerberos.kerb;

import org.apache.kerberos.kerb.spec.KerberosTime;
import org.apache.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerberos.kerb.spec.common.PrincipalName;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public abstract class KrbOutputStream extends DataOutputStream
{
	public KrbOutputStream(OutputStream out) {
        super(out);
    }

    public abstract void writePrincipal(PrincipalName principal, int version) throws IOException;

    public void writeRealm(String realm) throws IOException {
        writeCountedString(realm);
    }

    public abstract void writeKey(EncryptionKey key, int version) throws IOException;

    public void writeTime(KerberosTime ktime) throws IOException {
    	int time = 0;
    	if (ktime != null) {
    		time = (int) (ktime.getValue().getTime() / 1000);
    	}
    	writeInt(time);
    }

    public void writeCountedString(String string) throws IOException {
        byte[] data = string != null ? string.getBytes() : null; // ASCII

        writeCountedOctets(data);
    }

    public void writeCountedOctets(byte[] data) throws IOException {
        if (data != null) {
            writeInt(data.length);
            write(data);
        } else {
            writeInt(0);
        }
    }
}

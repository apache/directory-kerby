package org.haox.kerb.ccache;

import org.haox.kerb.spec.type.common.PrincipalName;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class CredentialCache implements KrbCredentialCache
{
    public static final int FCC_FVNO_1 = 0x501;
    public static final int FCC_FVNO_2 = 0x502;
    public static final int FCC_FVNO_3 = 0x503;
    public static final int FCC_FVNO_4 = 0x504;

    public static final int FCC_TAG_DELTATIME = 1;
    public static final int NT_UNKNOWN = 0;
    public static final int MAXNAMELENGTH = 1024;

    private int version = FCC_FVNO_4;
    private List<Tag> tags;
    private PrincipalName primaryPrincipal;
    private List<Credential> credentials = new ArrayList<Credential> ();

    @Override
    public void store(File ccacheFile) throws IOException {
        OutputStream outputStream = new FileOutputStream(ccacheFile);

        store(outputStream);
    }

    @Override
    public void store(OutputStream outputStream) throws IOException {
        if (outputStream == null) {
            throw new IllegalArgumentException("Invalid and null output stream");
        }

        CredCacheOutputStream ccos = new CredCacheOutputStream(outputStream);

        doStore(ccos);

        ccos.close();
    }

    private void doStore(CredCacheOutputStream ccos) throws IOException {
        this.version = FCC_FVNO_3;

        writeVersion(ccos);

        if (version == FCC_FVNO_4) {
            writeTags(ccos);
        }

        ccos.writePrincipal(primaryPrincipal, version);

        for (Credential cred : credentials) {
            cred.store(ccos, version);
        }
    }

    @Override
    public void setVersion(int version) {
        this.version = version;
    }

    @Override
    public PrincipalName getPrimaryPrincipal() {
        return primaryPrincipal;
    }

    @Override
    public void setPrimaryPrincipal(PrincipalName principal) {
        primaryPrincipal = principal;
    }

    @Override
    public int getVersion() {
        return version;
    }

    public void setTags(List<Tag> tags) {
        this.tags = tags;
    }

    public List<Tag> getTags() {
        return this.tags;
    }

    @Override
    public List<Credential> getCredentials() {
        return credentials;
    }

    @Override
    public void addCredential(Credential credential) {
        if (credential != null) {
            this.credentials.add(credential);
        }
    }

    @Override
    public void addCredentials(List<Credential> credentials) {
        if (credentials != null) {
            this.credentials.addAll(credentials);
        }
    }

    @Override
    public void removeCredentials(List<Credential> credentials) {
        if (credentials != null) {
            for (Credential cred : credentials) {
                removeCredential(cred);
            }
        }
    }

    @Override
    public void removeCredential(Credential credential) {
        if (credential != null) {
            for (Credential cred : credentials) {
                if (cred.equals(credential)) {
                    credentials.remove(cred);
                    break;
                }
            }
        }
    }

    @Override
    public void load(File ccacheFile) throws IOException {
        if (! ccacheFile.exists() || ! ccacheFile.canRead()) {
            throw new IllegalArgumentException("Invalid ccache file: " + ccacheFile.getAbsolutePath());
        }

        InputStream inputStream = new FileInputStream(ccacheFile);

        load(inputStream);
    }

    @Override
    public void load(InputStream inputStream) throws IOException {
        if (inputStream == null) {
            throw new IllegalArgumentException("Invalid and null input stream");
        }

        CredCacheInputStream ccis = new CredCacheInputStream(inputStream);

        doLoad(ccis);

        ccis.close();
    }

    private void doLoad(CredCacheInputStream ccis) throws IOException {
        this.version = readVersion(ccis);

        this.tags = readTags(ccis);

        this.primaryPrincipal = ccis.readPrincipal(version);

        this.credentials = readCredentials(ccis);
    }

    private List<Credential> readCredentials(CredCacheInputStream ccis) throws IOException {
        List<Credential> results = new ArrayList<Credential>(2);

        Credential cred;
        while (ccis.available() > 0) {
            cred =  new Credential();
            cred.load(ccis, version);

            results.add(cred);
        }
        
        return results;
    }

    private int readVersion(CredCacheInputStream ccis) throws IOException {
        int result = ccis.readShort();
        return result;
    }

    private List<Tag> readTags(CredCacheInputStream ccis) throws IOException {
        int len = ccis.readShort();
        List<Tag> tags = new ArrayList<Tag>();

        int tag, tagLen, time, usec;
        while (len > 0) {
            tag = ccis.readShort();
            tagLen = ccis.readShort();
            switch (tag) {
                case FCC_TAG_DELTATIME:
                    time = ccis.readInt();
                    usec = ccis.readInt();
                    tags.add(new Tag(tag, time, usec));
                    break;
                default:
                    ccis.read(new byte[tagLen], 0, tagLen); // ignore unknown tag
            }
            len = len - (4 + tagLen);
        }

        return tags;
    }

    private void writeVersion(CredCacheOutputStream ccos) throws IOException {
        ccos.writeShort(version);
    }

    private void writeTags(CredCacheOutputStream ccos) throws IOException {
        if (tags == null) {
            ccos.writeShort(0);
            return;
        }

        int length = 0;
        for (Tag tag : tags) {
            if (tag.tag != FCC_TAG_DELTATIME) {
                continue;
            }
            length += tag.length;
        }
        ccos.writeShort(length);

        for (Tag tag : tags) {
            if (tag.tag != CredentialCache.FCC_TAG_DELTATIME) {
                continue;
            }
            writeTag(ccos, tag);
        }
    }

    private void writeTag(CredCacheOutputStream ccos, Tag tag) throws IOException {
        ccos.writeShort(tag.tag);
        ccos.writeShort(tag.length);
        ccos.writeInt(tag.time);
        ccos.writeInt(tag.usec);
    }
}

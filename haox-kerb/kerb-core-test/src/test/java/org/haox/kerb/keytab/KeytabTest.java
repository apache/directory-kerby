package org.haox.kerb.keytab;

import java.io.IOException;
import java.io.InputStream;

public class KeytabTest {

    public static void main(String[] args) throws IOException {
        InputStream kis = KeytabTest.class.getResourceAsStream("/server.keytab");
        Keytab keytab = new Keytab();
        keytab.load(kis);
        System.out.println("Principals:" + keytab.getPrincipals().size());
    }
}

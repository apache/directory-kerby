#!/bin/sh

export DNAME_SUFFIX="OU=commons-ssl, O=apache, L=Victoria, ST=BC, C=CA"
export PASS=changeit
export KEYPASS=itchange
export EXPIRY_IN_YEARS=40

export VALIDITY=`echo 366 \* $EXPIRY_IN_YEARS | bc`

# bouncy-castle BKS
export TYPE=BKS; export NAME=BC.$TYPE.ks;
rm -f $NAME
export CMD="$JAVA_HOME/bin/keytool -genkey -v -keyalg RSA -keysize 2048 -sigalg SHA1WithRSA -dname \"CN=$NAME, $DNAME_SUFFIX\" -validity $VALIDITY -keypass $PASS -keystore $NAME -storepass $PASS -storetype $TYPE"
bash -c "$CMD"

# bouncy-castle UBER
export TYPE=UBER; export NAME=BC.$TYPE.ks;
rm -f $NAME
export CMD="$JAVA_HOME/bin/keytool -genkey -v -keyalg RSA -keysize 2048 -sigalg SHA1WithRSA -dname \"CN=$NAME, $DNAME_SUFFIX\" -validity $VALIDITY -keypass $PASS -keystore $NAME -storepass $PASS -storetype $TYPE"
bash -c "$CMD"

# bouncy-castle PKCS12
export TYPE=PKCS12; export NAME=BC.$TYPE.ks;
rm -f $NAME
export CMD="$JAVA_HOME/bin/keytool -genkey -v -keyalg RSA -keysize 2048 -sigalg SHA1WithRSA -dname \"CN=$NAME, $DNAME_SUFFIX\" -validity $VALIDITY -keypass $PASS -keystore $NAME -storepass $PASS -storetype $TYPE"
bash -c "$CMD"

# bouncy-castle PKCS12-DEF
export TYPE=PKCS12-DEF; export NAME=BC.$TYPE.ks;
rm -f $NAME
export CMD="$JAVA_HOME/bin/keytool -genkey -v -keyalg RSA -keysize 2048 -sigalg SHA1WithRSA -dname \"CN=$NAME, $DNAME_SUFFIX\" -validity $VALIDITY -keypass $PASS -keystore $NAME -storepass $PASS -storetype $TYPE"
bash -c "$CMD"

# bouncy-castle PKCS12-3DES-3DES
export TYPE=PKCS12-3DES-3DES; export NAME=BC.$TYPE.ks;
rm -f $NAME
export CMD="$JAVA_HOME/bin/keytool -genkey -v -keyalg RSA -keysize 2048 -sigalg SHA1WithRSA -dname \"CN=$NAME, $DNAME_SUFFIX\" -validity $VALIDITY -keypass $PASS -keystore $NAME -storepass $PASS -storetype $TYPE"
bash -c "$CMD"

# bouncy-castle PKCS12-DEF-3DES-3DES
export TYPE=PKCS12-DEF-3DES-3DES; export NAME=BC.$TYPE.ks;
rm -f $NAME
export CMD="$JAVA_HOME/bin/keytool -genkey -v -keyalg RSA -keysize 2048 -sigalg SHA1WithRSA -dname \"CN=$NAME, $DNAME_SUFFIX\" -validity $VALIDITY -keypass $PASS -keystore $NAME -storepass $PASS -storetype $TYPE"
bash -c "$CMD"

# SunJCE
export TYPE=jceks; export NAME=SunJCE.$TYPE.ks;
rm -f $NAME
export CMD="$JAVA_HOME/bin/keytool -genkey -v -keyalg RSA -keysize 2048 -sigalg SHA1WithRSA -dname \"CN=$NAME, $DNAME_SUFFIX\" -validity $VALIDITY -keypass $PASS -keystore $NAME -storepass $PASS -storetype $TYPE"
bash -c "$CMD"

# SUN
export TYPE=jks; export NAME=Sun.$TYPE.ks;
rm -f $NAME
export CMD="$JAVA_HOME/bin/keytool -genkey -v -keyalg RSA -keysize 2048 -sigalg SHA1WithRSA -dname \"CN=$NAME, $DNAME_SUFFIX\" -validity $VALIDITY -keypass $PASS -keystore $NAME -storepass $PASS -storetype $TYPE"
bash -c "$CMD"


# SUN with different key password
export TYPE=jks; export NAME=Sun.2pass.$TYPE.ks;
rm -f $NAME
export CMD="$JAVA_HOME/bin/keytool -genkey -v -keyalg RSA -keysize 2048 -sigalg SHA1WithRSA -dname \"CN=$NAME, $DNAME_SUFFIX\" -validity $VALIDITY -keypass $KEYPASS -keystore $NAME -storepass $PASS -storetype $TYPE"
bash -c "$CMD"

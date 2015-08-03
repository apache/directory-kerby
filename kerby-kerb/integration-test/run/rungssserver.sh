java -Djava.security.krb5.realm=SH.INTEL.COM \
     -Djava.security.krb5.kdc=zkdev.sh.intel.com \
     -Djavax.security.auth.useSubjectCredsOnly=false \
     -Djava.security.auth.login.config=login.conf \
     SampleServer 8080
java -Djava.security.krb5.realm=SH.INTEL.COM \
     -Djava.security.krb5.kdc=zkdesk.sh.intel.com \
     -Djavax.security.auth.useSubjectCredsOnly=false \
     -Djava.security.auth.login.config=login.conf \
     token.samples.sasl.TokenSaslSampleServer \
     8080 myservice zkdesk.sh.intel.com
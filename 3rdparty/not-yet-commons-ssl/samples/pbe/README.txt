
not-yet-commons-ssl PBE tests
=====================================
by Julius Davies
July 4th, 2007


README
-------------------------------------

Underneath this directory are 500+ small files used for testing
commons-ssl's ability to interop with OpenSSL's password-based
symmetric encryption (see OpenSSL's 'enc' command).

Each file is encrypted using the cipher in its filename.  The
password is always "changeit", and every file decrypts to the
phrase "Hello World!" in UTF-8 with no trailing line-feed.

The files underneath "pbe/java/" were created using commons-ssl's
org.apache.commons.ssl.PBETestCreate utility, along with
samples/pbe.tests as the single command-line argument.  These
files were created using pure java.  It is useful to see whether
commons-ssl can decrypt files it created itself, as well as to see
if OpenSSL can also decrypt them.

The files underneath "pbe/openssl/" were created using OpenSSL.
Take a look at the "samples/createPBESamples.sh" shell script
to see how these were created.  You'll probably need to build
your own version of OpenSSL from source to use some of the
ciphers (idea, rc5, for example).

org.apache.commons.ssl.OpenSSLTest tries to decrypt both the
"pbe/java/" and the "pbe/openssl/" files, and reports on any
failures.



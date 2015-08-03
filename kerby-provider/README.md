This contains all the facility providers that the Kerberos implementation relies on.
These providers are not to be coupled with the Kerberos library, and just hooked into
during run time thru KrbRuntime. Kerby KDC may integrate some of such providers regarding
what preauth mechanism(s) it would provide.
pam_krb5_ccache
==========

PAM module for ksu style Kerberos authentication in sudo.

Usage
-----

```

/etc/sudoers:
    Defaults    env_keep += "KRB5CCNAME"
    # optional, to permit `ssh host cmd` style usage
    Defaults !requiretty,visiblepw

/etc/pam.d/sudo:
    auth  sufficient   pam_krb5_ccache.so

```


Notes
-----

Useful in environments where one wishes to use sudo in place of ksu. 

Stackable with other modules, such as pam_krb5. If pam_krb5_ccache is placed
before other authentication modules it will first silently attempt to
authenticate using the credential cache, then fall back to other mechanisms.



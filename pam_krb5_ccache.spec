Name:           pam_krb5_ccache
Version:        0.1.0
Release:        1%{?dist}
Summary:        PAM module for ksu style Kerberos authentication in sudo.

License:        BSD
URL:            https://github.com/square/pam_krb5_ccache
Source0:        pam_krb5_ccache.tar.gz

BuildRequires:  krb5-devel
Requires:       krb5-libs

%description
To use this PAM module:
/etc/sudoers:
    Defaults    env_keep += "KRB5CCNAME"
    Following is optional, to permit `ssh host cmd` style usage:
    Defaults !requiretty,visiblepw

/etc/pam.d/sudo:
    auth  sufficient   pam_krb5_ccache.so

%prep
%setup -q

%build
make

%install
rm -rf $RPM_BUILD_ROOT
%make_install


%files
/lib64/security/pam_krb5_ccache.so

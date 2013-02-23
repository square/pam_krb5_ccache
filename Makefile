all:
	gcc -Wall -fPIC -c pam_krb5_ccache.c
	ld -x --shared -lkrb5 -o pam_krb5_ccache.so pam_krb5_ccache.o

install:
	mkdir -p "$(DESTDIR)/lib64/security"
	cp pam_krb5_ccache.so "$(DESTDIR)/lib64/security/pam_krb5_ccache.so"

clean:
	rm -f pam_krb5_ccache.so pam_krb5_ccache.o

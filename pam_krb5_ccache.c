#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <pwd.h>
#include <errno.h>
#include <syslog.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_misc.h>

#include <krb5.h>

#define MOD_NAME "pam_krb5_ccache"
#define KRB5_CCACHE_LEN 512

/*
  Reimplement krb5_cc_default_name() because the function assumes getuid()
  is the authenticating uid. This needs to come from PAM in a setuid context.
  Following ksu's lead here.
*/
static void ksu_krb5_cc_default_name(char * name_buf, unsigned int name_size, uid_t uid) {
  char * from_env;
  from_env = getenv("KRB5CCNAME");
  if (NULL == from_env) {
    /* if env is unset, use the default value as ksu does */
    snprintf(name_buf, name_size, "FILE:/tmp/krb5cc_%ld", (long int)uid); 
  } else {
    /* use the value from env, if it was set */
    strncpy(name_buf, from_env, name_size);
  }
  name_buf[name_size - 1] = 0; /* ensure null termination */
}

/* sudo handles setting credentials for us, just return success */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  krb5_error_code krb_retval = 0;         /* For the return value of each krb5_ call */
  const char *krb_error_msg = NULL;       /* Human readable error string of krb_retval */
  krb5_context krb_context;               /* Kerberos context */
  char cc_source_tag[KRB5_CCACHE_LEN];    /* Credential cache name. FILE:/tmp/krb5cc_* */
  krb5_ccache cc_source = NULL;           /* Credential cache handle, derived from cc_source_tag */
  krb5_principal client;                  /* Default client principal of the credential cache */
  krb5_principal server;                  /* Host's principal */
  krb5_creds in_creds;                    /* Input credentials, consisting of host(server) and client principals */
  krb5_creds *out_creds = NULL;           /* service ticket obtained using in_creds */
  krb5_verify_init_creds_opt verify_opts; /* options for krb5_verify_init_creds, require ap_req_nofail is TRUE */

  char *ruser = NULL;                     /* PAM_RUSER, the username of the user who invoked sudo */
  uid_t ruid;                             /* uid of PAM_RUSER */
  struct passwd *pw;                      /* passwd structure to convert ruser to ruid */
  char hostname[HOST_NAME_MAX];           /* Hostname is used to obtain the host's principal */

  memset(&in_creds, 0, sizeof(in_creds));

  setlogmask (LOG_UPTO (LOG_DEBUG));
  /* FIXME "sudo" should probably become argv[0] */
  openlog ("sudo" , LOG_PID, LOG_AUTHPRIV);

  if (PAM_SUCCESS != pam_get_item(pamh, PAM_RUSER, (void *) &ruser)) {
    syslog(LOG_ERR, MOD_NAME ": pam_get_item(PAM_RUSER) failed");
    goto error_cleanup1;
  }

  /* Get entry for PAM_RUSER. This is the user calling sudo. */
  if (! (pw = getpwnam(ruser)) ) {
    syslog(LOG_ERR, MOD_NAME ": getpwnam(PAM_RUSER) not found");
    goto error_cleanup1;
  }
  ruid = pw->pw_uid;

  /* Operate as the user who invoked us, ensuring that the ccache is readable
     by the calling user. This prevents tricking sudo into opening another
     user's ccache by redirecting KRB5CCNAME or similar
   */
  syslog(LOG_DEBUG, MOD_NAME ": Invoked by uid: %d", ruid);
  if (!ruid) {
    syslog(LOG_DEBUG, MOD_NAME ": called by root");
  }
  if (seteuid(ruid)) {
    syslog(LOG_ERR, MOD_NAME ": seteuid to %d failed", ruid);
    goto error_cleanup1;
  }

  /* Used to obtain the host's principal */
  if (gethostname(hostname, HOST_NAME_MAX)) {
    syslog(LOG_ERR, MOD_NAME ": gethostname() failed. errno=%d", errno);
    goto error_cleanup1;
  }
  hostname[HOST_NAME_MAX - 1] = 0; /* ensure null termination */

  /* initialize the krb context. Can't pretty-print errors without valid krb_context */
  krb_retval = krb5_init_secure_context(&krb_context);
  if (krb_retval) {
    syslog(LOG_ERR, MOD_NAME ": krb5_init_secure_context() failed: %d", krb_retval);
    goto error_cleanup1;
  }

  /* find the ccache file's default location */
  ksu_krb5_cc_default_name(cc_source_tag, KRB5_CCACHE_LEN - 1, ruid);
  syslog(LOG_DEBUG, MOD_NAME ": cc_source_tag = %s", cc_source_tag);

  /* get a handle for the cache as cc_source, using the default name */
  if ((krb_retval = krb5_cc_resolve(krb_context, cc_source_tag, &cc_source))){
    krb_error_msg = krb5_get_error_message(krb_context, krb_retval);
    syslog(LOG_ERR, MOD_NAME ": krb5_cc_resolve() = %s", krb_error_msg);
    krb5_free_error_message(krb_context, krb_error_msg);
    goto error_cleanup2;
  }

  /* get krb5 princ from cache, copy to &client.
     When used without a ccache, this is generally the call that fails
  */
  krb_retval = krb5_cc_get_principal(krb_context, cc_source, &client);
  if (krb_retval) {
    krb_error_msg = krb5_get_error_message(krb_context, krb_retval);
    syslog(LOG_ERR, MOD_NAME ": krb5_cc_get_principal(client) = %s", krb_error_msg);
    krb5_free_error_message(krb_context, krb_error_msg);

    goto error_cleanup2;
  }

  /* Copy the user's principal into in_creds */
  krb_retval= krb5_copy_principal(krb_context,  client, &in_creds.client);
  if (krb_retval) {
    krb_error_msg = krb5_get_error_message(krb_context, krb_retval);
    syslog(LOG_ERR, MOD_NAME ": krb5_copy_principal(client) = %s", krb_error_msg);
    krb5_free_error_message(krb_context, krb_error_msg);

    goto error_cleanup3;
  }

  /* Take our hostname and generate the host's principal as server */

  krb_retval = krb5_sname_to_principal(krb_context, hostname, NULL, KRB5_NT_SRV_HST, &server);
  if (krb_retval) {
    krb_error_msg = krb5_get_error_message(krb_context, krb_retval);
    syslog(LOG_ERR, MOD_NAME ": krb5_sname_to_principal() = %s", krb_error_msg);
    krb5_free_error_message(krb_context, krb_error_msg);

    goto error_cleanup4;
  }

  /* Copy the host's principal into in_creds */
  krb_retval= krb5_copy_principal(krb_context,  server, &in_creds.server);
  if (krb_retval) {
    krb_error_msg = krb5_get_error_message(krb_context, krb_retval);
    syslog(LOG_ERR, MOD_NAME ": krb5_copy_principal(server) = %s", krb_error_msg);
    krb5_free_error_message(krb_context, krb_error_msg);

    goto error_cleanup5;
  }

  /* using the credential cache handle,
     the user's principal,
     and the host's principal,
     generate a service ticket as out_creds
  */
  krb_retval = krb5_get_credentials(krb_context, 0, cc_source, &in_creds, &out_creds);
  if (krb_retval) {
    krb_error_msg = krb5_get_error_message(krb_context, krb_retval);
    syslog(LOG_ERR, MOD_NAME ": krb5_get_credentials() = %s", krb_error_msg);
    krb5_free_error_message(krb_context, krb_error_msg);
    goto error_cleanup6;
  }

  /* Set verify_opts to require a successful verification */
  krb5_verify_init_creds_opt_init(&verify_opts);
  krb5_verify_init_creds_opt_set_ap_req_nofail(&verify_opts, 1);

  /* Become root before final verification, so we can read /etc/krb5.keytab.
     Stay root upon return
  */
  if ( seteuid(0) ) {
    syslog(LOG_ERR, MOD_NAME " could not seteuid(0) errno = %d", errno);
    goto error_cleanup7;
  }
  /* Verify out_creds against the host's keytab. Destroy any addditional credentials */
  krb_retval = krb5_verify_init_creds(krb_context,
                                      out_creds,
                                      server,
                                      NULL /*keytab*/,
                                      NULL /*output ccache*/,
                                      &verify_opts);

  if (krb_retval) {
    /* unable to verify creds */
    krb_error_msg = krb5_get_error_message(krb_context, krb_retval);
    syslog(LOG_ERR, MOD_NAME ": krb5_verify_init_creds() = %s", krb_error_msg);
    krb5_free_error_message(krb_context, krb_error_msg);
    goto error_cleanup7;
  } else {
    /* we authenticated if krb5_verify_init_creds() succeeded */
    syslog(LOG_NOTICE, MOD_NAME ": user %s successfully authenticated using pam_krb5_ccache", ruser);

    krb5_free_principal(krb_context, client);
    krb5_free_principal(krb_context, in_creds.client);
    krb5_free_principal(krb_context, server);
    krb5_free_principal(krb_context, in_creds.server);
    krb5_free_creds(krb_context, out_creds);
    krb5_free_context(krb_context);
    closelog();
    return PAM_SUCCESS;
  }

  /* Cleanup is cumulative.
     Always seteuid root before returning. Calling twice is harmless.
  */
 error_cleanup7:
  krb5_free_creds(krb_context, out_creds);
 error_cleanup6:
  krb5_free_principal(krb_context, in_creds.server);
 error_cleanup5:
  krb5_free_principal(krb_context, server);
 error_cleanup4:
  krb5_free_principal(krb_context, in_creds.client);
 error_cleanup3:
  krb5_free_principal(krb_context, client);
 error_cleanup2:
  krb5_free_context(krb_context);
 error_cleanup1:
  syslog(LOG_DEBUG, MOD_NAME ": authentication failed");
  closelog();
  seteuid(0);
  return PAM_AUTH_ERR;
}


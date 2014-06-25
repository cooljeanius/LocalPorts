/* Automatically generated, do not edit.  */

#ifndef GUILE_GNUTLS_SMOBS_H
#define GUILE_GNUTLS_SMOBS_H
SCM_API scm_t_bits scm_tc16_gnutls_session;
static inline SCM
scm_from_gnutls_session (gnutls_session_t c_obj)
{
  SCM_RETURN_NEWSMOB (scm_tc16_gnutls_session, (scm_t_bits) c_obj);
}
static inline gnutls_session_t
scm_to_gnutls_session (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_session);
  return ((gnutls_session_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
SCM_API scm_t_bits scm_tc16_gnutls_anonymous_client_credentials;
static inline SCM
scm_from_gnutls_anonymous_client_credentials (gnutls_anon_client_credentials_t c_obj)
{
  SCM_RETURN_NEWSMOB (scm_tc16_gnutls_anonymous_client_credentials, (scm_t_bits) c_obj);
}
static inline gnutls_anon_client_credentials_t
scm_to_gnutls_anonymous_client_credentials (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_anonymous_client_credentials);
  return ((gnutls_anon_client_credentials_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
SCM_API scm_t_bits scm_tc16_gnutls_anonymous_server_credentials;
static inline SCM
scm_from_gnutls_anonymous_server_credentials (gnutls_anon_server_credentials_t c_obj)
{
  SCM_RETURN_NEWSMOB (scm_tc16_gnutls_anonymous_server_credentials, (scm_t_bits) c_obj);
}
static inline gnutls_anon_server_credentials_t
scm_to_gnutls_anonymous_server_credentials (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_anonymous_server_credentials);
  return ((gnutls_anon_server_credentials_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
SCM_API scm_t_bits scm_tc16_gnutls_dh_parameters;
static inline SCM
scm_from_gnutls_dh_parameters (gnutls_dh_params_t c_obj)
{
  SCM_RETURN_NEWSMOB (scm_tc16_gnutls_dh_parameters, (scm_t_bits) c_obj);
}
static inline gnutls_dh_params_t
scm_to_gnutls_dh_parameters (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_dh_parameters);
  return ((gnutls_dh_params_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
SCM_API scm_t_bits scm_tc16_gnutls_rsa_parameters;
static inline SCM
scm_from_gnutls_rsa_parameters (gnutls_rsa_params_t c_obj)
{
  SCM_RETURN_NEWSMOB (scm_tc16_gnutls_rsa_parameters, (scm_t_bits) c_obj);
}
static inline gnutls_rsa_params_t
scm_to_gnutls_rsa_parameters (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_rsa_parameters);
  return ((gnutls_rsa_params_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
SCM_API scm_t_bits scm_tc16_gnutls_certificate_credentials;
static inline SCM
scm_from_gnutls_certificate_credentials (gnutls_certificate_credentials_t c_obj)
{
  SCM_RETURN_NEWSMOB (scm_tc16_gnutls_certificate_credentials, (scm_t_bits) c_obj);
}
static inline gnutls_certificate_credentials_t
scm_to_gnutls_certificate_credentials (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_certificate_credentials);
  return ((gnutls_certificate_credentials_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
SCM_API scm_t_bits scm_tc16_gnutls_srp_server_credentials;
static inline SCM
scm_from_gnutls_srp_server_credentials (gnutls_srp_server_credentials_t c_obj)
{
  SCM_RETURN_NEWSMOB (scm_tc16_gnutls_srp_server_credentials, (scm_t_bits) c_obj);
}
static inline gnutls_srp_server_credentials_t
scm_to_gnutls_srp_server_credentials (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_srp_server_credentials);
  return ((gnutls_srp_server_credentials_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
SCM_API scm_t_bits scm_tc16_gnutls_srp_client_credentials;
static inline SCM
scm_from_gnutls_srp_client_credentials (gnutls_srp_client_credentials_t c_obj)
{
  SCM_RETURN_NEWSMOB (scm_tc16_gnutls_srp_client_credentials, (scm_t_bits) c_obj);
}
static inline gnutls_srp_client_credentials_t
scm_to_gnutls_srp_client_credentials (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_srp_client_credentials);
  return ((gnutls_srp_client_credentials_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
SCM_API scm_t_bits scm_tc16_gnutls_psk_server_credentials;
static inline SCM
scm_from_gnutls_psk_server_credentials (gnutls_psk_server_credentials_t c_obj)
{
  SCM_RETURN_NEWSMOB (scm_tc16_gnutls_psk_server_credentials, (scm_t_bits) c_obj);
}
static inline gnutls_psk_server_credentials_t
scm_to_gnutls_psk_server_credentials (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_psk_server_credentials);
  return ((gnutls_psk_server_credentials_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
SCM_API scm_t_bits scm_tc16_gnutls_psk_client_credentials;
static inline SCM
scm_from_gnutls_psk_client_credentials (gnutls_psk_client_credentials_t c_obj)
{
  SCM_RETURN_NEWSMOB (scm_tc16_gnutls_psk_client_credentials, (scm_t_bits) c_obj);
}
static inline gnutls_psk_client_credentials_t
scm_to_gnutls_psk_client_credentials (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_psk_client_credentials);
  return ((gnutls_psk_client_credentials_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
SCM_API scm_t_bits scm_tc16_gnutls_x509_certificate;
static inline SCM
scm_from_gnutls_x509_certificate (gnutls_x509_crt_t c_obj)
{
  SCM_RETURN_NEWSMOB (scm_tc16_gnutls_x509_certificate, (scm_t_bits) c_obj);
}
static inline gnutls_x509_crt_t
scm_to_gnutls_x509_certificate (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_x509_certificate);
  return ((gnutls_x509_crt_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
SCM_API scm_t_bits scm_tc16_gnutls_x509_private_key;
static inline SCM
scm_from_gnutls_x509_private_key (gnutls_x509_privkey_t c_obj)
{
  SCM_RETURN_NEWSMOB (scm_tc16_gnutls_x509_private_key, (scm_t_bits) c_obj);
}
static inline gnutls_x509_privkey_t
scm_to_gnutls_x509_private_key (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_x509_private_key);
  return ((gnutls_x509_privkey_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
#endif

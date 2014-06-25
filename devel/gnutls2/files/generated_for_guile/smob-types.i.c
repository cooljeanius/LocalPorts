SCM_GLOBAL_SMOB (scm_tc16_gnutls_session, "session", 0);
SCM_SMOB_FREE (scm_tc16_gnutls_session, session_free, obj)
{
  gnutls_session_t c_obj;
  c_obj = (gnutls_session_t) SCM_SMOB_DATA (obj);
  gnutls_deinit (c_obj);
  return 0;
}
SCM_DEFINE (scm_gnutls_session_p, "session?", 1, 0, 0,
            (SCM obj),
            "Return true if @var{obj} is of type @code{session}.")
#define FUNC_NAME s_scm_gnutls_session_p
{
  return (scm_from_bool (SCM_SMOB_PREDICATE (scm_tc16_gnutls_session, obj)));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_anonymous_client_credentials, "anonymous-client-credentials", 0);
SCM_SMOB_FREE (scm_tc16_gnutls_anonymous_client_credentials, anonymous_client_credentials_free, obj)
{
  gnutls_anon_client_credentials_t c_obj;
  c_obj = (gnutls_anon_client_credentials_t) SCM_SMOB_DATA (obj);
  gnutls_anon_free_client_credentials (c_obj);
  return 0;
}
SCM_DEFINE (scm_gnutls_anonymous_client_credentials_p, "anonymous-client-credentials?", 1, 0, 0,
            (SCM obj),
            "Return true if @var{obj} is of type @code{anonymous-client-credentials}.")
#define FUNC_NAME s_scm_gnutls_anonymous_client_credentials_p
{
  return (scm_from_bool (SCM_SMOB_PREDICATE (scm_tc16_gnutls_anonymous_client_credentials, obj)));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_anonymous_server_credentials, "anonymous-server-credentials", 0);
SCM_SMOB_FREE (scm_tc16_gnutls_anonymous_server_credentials, anonymous_server_credentials_free, obj)
{
  gnutls_anon_server_credentials_t c_obj;
  c_obj = (gnutls_anon_server_credentials_t) SCM_SMOB_DATA (obj);
  gnutls_anon_free_server_credentials (c_obj);
  return 0;
}
SCM_DEFINE (scm_gnutls_anonymous_server_credentials_p, "anonymous-server-credentials?", 1, 0, 0,
            (SCM obj),
            "Return true if @var{obj} is of type @code{anonymous-server-credentials}.")
#define FUNC_NAME s_scm_gnutls_anonymous_server_credentials_p
{
  return (scm_from_bool (SCM_SMOB_PREDICATE (scm_tc16_gnutls_anonymous_server_credentials, obj)));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_dh_parameters, "dh-parameters", 0);
SCM_SMOB_FREE (scm_tc16_gnutls_dh_parameters, dh_parameters_free, obj)
{
  gnutls_dh_params_t c_obj;
  c_obj = (gnutls_dh_params_t) SCM_SMOB_DATA (obj);
  gnutls_dh_params_deinit (c_obj);
  return 0;
}
SCM_DEFINE (scm_gnutls_dh_parameters_p, "dh-parameters?", 1, 0, 0,
            (SCM obj),
            "Return true if @var{obj} is of type @code{dh-parameters}.")
#define FUNC_NAME s_scm_gnutls_dh_parameters_p
{
  return (scm_from_bool (SCM_SMOB_PREDICATE (scm_tc16_gnutls_dh_parameters, obj)));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_rsa_parameters, "rsa-parameters", 0);
SCM_SMOB_FREE (scm_tc16_gnutls_rsa_parameters, rsa_parameters_free, obj)
{
  gnutls_rsa_params_t c_obj;
  c_obj = (gnutls_rsa_params_t) SCM_SMOB_DATA (obj);
  gnutls_rsa_params_deinit (c_obj);
  return 0;
}
SCM_DEFINE (scm_gnutls_rsa_parameters_p, "rsa-parameters?", 1, 0, 0,
            (SCM obj),
            "Return true if @var{obj} is of type @code{rsa-parameters}.")
#define FUNC_NAME s_scm_gnutls_rsa_parameters_p
{
  return (scm_from_bool (SCM_SMOB_PREDICATE (scm_tc16_gnutls_rsa_parameters, obj)));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_certificate_credentials, "certificate-credentials", 0);
SCM_SMOB_FREE (scm_tc16_gnutls_certificate_credentials, certificate_credentials_free, obj)
{
  gnutls_certificate_credentials_t c_obj;
  c_obj = (gnutls_certificate_credentials_t) SCM_SMOB_DATA (obj);
  gnutls_certificate_free_credentials (c_obj);
  return 0;
}
SCM_DEFINE (scm_gnutls_certificate_credentials_p, "certificate-credentials?", 1, 0, 0,
            (SCM obj),
            "Return true if @var{obj} is of type @code{certificate-credentials}.")
#define FUNC_NAME s_scm_gnutls_certificate_credentials_p
{
  return (scm_from_bool (SCM_SMOB_PREDICATE (scm_tc16_gnutls_certificate_credentials, obj)));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_srp_server_credentials, "srp-server-credentials", 0);
SCM_SMOB_FREE (scm_tc16_gnutls_srp_server_credentials, srp_server_credentials_free, obj)
{
  gnutls_srp_server_credentials_t c_obj;
  c_obj = (gnutls_srp_server_credentials_t) SCM_SMOB_DATA (obj);
  gnutls_srp_free_server_credentials (c_obj);
  return 0;
}
SCM_DEFINE (scm_gnutls_srp_server_credentials_p, "srp-server-credentials?", 1, 0, 0,
            (SCM obj),
            "Return true if @var{obj} is of type @code{srp-server-credentials}.")
#define FUNC_NAME s_scm_gnutls_srp_server_credentials_p
{
  return (scm_from_bool (SCM_SMOB_PREDICATE (scm_tc16_gnutls_srp_server_credentials, obj)));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_srp_client_credentials, "srp-client-credentials", 0);
SCM_SMOB_FREE (scm_tc16_gnutls_srp_client_credentials, srp_client_credentials_free, obj)
{
  gnutls_srp_client_credentials_t c_obj;
  c_obj = (gnutls_srp_client_credentials_t) SCM_SMOB_DATA (obj);
  gnutls_srp_free_client_credentials (c_obj);
  return 0;
}
SCM_DEFINE (scm_gnutls_srp_client_credentials_p, "srp-client-credentials?", 1, 0, 0,
            (SCM obj),
            "Return true if @var{obj} is of type @code{srp-client-credentials}.")
#define FUNC_NAME s_scm_gnutls_srp_client_credentials_p
{
  return (scm_from_bool (SCM_SMOB_PREDICATE (scm_tc16_gnutls_srp_client_credentials, obj)));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_psk_server_credentials, "psk-server-credentials", 0);
SCM_SMOB_FREE (scm_tc16_gnutls_psk_server_credentials, psk_server_credentials_free, obj)
{
  gnutls_psk_server_credentials_t c_obj;
  c_obj = (gnutls_psk_server_credentials_t) SCM_SMOB_DATA (obj);
  gnutls_psk_free_server_credentials (c_obj);
  return 0;
}
SCM_DEFINE (scm_gnutls_psk_server_credentials_p, "psk-server-credentials?", 1, 0, 0,
            (SCM obj),
            "Return true if @var{obj} is of type @code{psk-server-credentials}.")
#define FUNC_NAME s_scm_gnutls_psk_server_credentials_p
{
  return (scm_from_bool (SCM_SMOB_PREDICATE (scm_tc16_gnutls_psk_server_credentials, obj)));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_psk_client_credentials, "psk-client-credentials", 0);
SCM_SMOB_FREE (scm_tc16_gnutls_psk_client_credentials, psk_client_credentials_free, obj)
{
  gnutls_psk_client_credentials_t c_obj;
  c_obj = (gnutls_psk_client_credentials_t) SCM_SMOB_DATA (obj);
  gnutls_psk_free_client_credentials (c_obj);
  return 0;
}
SCM_DEFINE (scm_gnutls_psk_client_credentials_p, "psk-client-credentials?", 1, 0, 0,
            (SCM obj),
            "Return true if @var{obj} is of type @code{psk-client-credentials}.")
#define FUNC_NAME s_scm_gnutls_psk_client_credentials_p
{
  return (scm_from_bool (SCM_SMOB_PREDICATE (scm_tc16_gnutls_psk_client_credentials, obj)));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_x509_certificate, "x509-certificate", 0);
SCM_SMOB_FREE (scm_tc16_gnutls_x509_certificate, x509_certificate_free, obj)
{
  gnutls_x509_crt_t c_obj;
  c_obj = (gnutls_x509_crt_t) SCM_SMOB_DATA (obj);
  gnutls_x509_crt_deinit (c_obj);
  return 0;
}
SCM_DEFINE (scm_gnutls_x509_certificate_p, "x509-certificate?", 1, 0, 0,
            (SCM obj),
            "Return true if @var{obj} is of type @code{x509-certificate}.")
#define FUNC_NAME s_scm_gnutls_x509_certificate_p
{
  return (scm_from_bool (SCM_SMOB_PREDICATE (scm_tc16_gnutls_x509_certificate, obj)));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_x509_private_key, "x509-private-key", 0);
SCM_SMOB_FREE (scm_tc16_gnutls_x509_private_key, x509_private_key_free, obj)
{
  gnutls_x509_privkey_t c_obj;
  c_obj = (gnutls_x509_privkey_t) SCM_SMOB_DATA (obj);
  gnutls_x509_privkey_deinit (c_obj);
  return 0;
}
SCM_DEFINE (scm_gnutls_x509_private_key_p, "x509-private-key?", 1, 0, 0,
            (SCM obj),
            "Return true if @var{obj} is of type @code{x509-private-key}.")
#define FUNC_NAME s_scm_gnutls_x509_private_key_p
{
  return (scm_from_bool (SCM_SMOB_PREDICATE (scm_tc16_gnutls_x509_private_key, obj)));
}
#undef FUNC_NAME

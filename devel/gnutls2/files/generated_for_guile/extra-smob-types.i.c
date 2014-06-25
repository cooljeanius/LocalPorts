SCM_GLOBAL_SMOB (scm_tc16_gnutls_openpgp_certificate, "openpgp-certificate", 0);
SCM_SMOB_FREE (scm_tc16_gnutls_openpgp_certificate, openpgp_certificate_free, obj)
{
  gnutls_openpgp_crt_t c_obj;
  c_obj = (gnutls_openpgp_crt_t) SCM_SMOB_DATA (obj);
  gnutls_openpgp_crt_deinit (c_obj);
  return 0;
}
SCM_DEFINE (scm_gnutls_openpgp_certificate_p, "openpgp-certificate?", 1, 0, 0,
            (SCM obj),
            "Return true if @var{obj} is of type @code{openpgp-certificate}.")
#define FUNC_NAME s_scm_gnutls_openpgp_certificate_p
{
  return (scm_from_bool (SCM_SMOB_PREDICATE (scm_tc16_gnutls_openpgp_certificate, obj)));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_openpgp_private_key, "openpgp-private-key", 0);
SCM_SMOB_FREE (scm_tc16_gnutls_openpgp_private_key, openpgp_private_key_free, obj)
{
  gnutls_openpgp_privkey_t c_obj;
  c_obj = (gnutls_openpgp_privkey_t) SCM_SMOB_DATA (obj);
  gnutls_openpgp_privkey_deinit (c_obj);
  return 0;
}
SCM_DEFINE (scm_gnutls_openpgp_private_key_p, "openpgp-private-key?", 1, 0, 0,
            (SCM obj),
            "Return true if @var{obj} is of type @code{openpgp-private-key}.")
#define FUNC_NAME s_scm_gnutls_openpgp_private_key_p
{
  return (scm_from_bool (SCM_SMOB_PREDICATE (scm_tc16_gnutls_openpgp_private_key, obj)));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_openpgp_keyring, "openpgp-keyring", 0);
SCM_SMOB_FREE (scm_tc16_gnutls_openpgp_keyring, openpgp_keyring_free, obj)
{
  gnutls_openpgp_keyring_t c_obj;
  c_obj = (gnutls_openpgp_keyring_t) SCM_SMOB_DATA (obj);
  gnutls_openpgp_keyring_deinit (c_obj);
  return 0;
}
SCM_DEFINE (scm_gnutls_openpgp_keyring_p, "openpgp-keyring?", 1, 0, 0,
            (SCM obj),
            "Return true if @var{obj} is of type @code{openpgp-keyring}.")
#define FUNC_NAME s_scm_gnutls_openpgp_keyring_p
{
  return (scm_from_bool (SCM_SMOB_PREDICATE (scm_tc16_gnutls_openpgp_keyring, obj)));
}
#undef FUNC_NAME

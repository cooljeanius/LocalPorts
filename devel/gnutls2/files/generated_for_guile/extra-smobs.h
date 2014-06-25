/* Automatically generated, do not edit.  */

#ifndef GUILE_GNUTLS_EXTRA_SMOBS_H
#define GUILE_GNUTLS_EXTRA_SMOBS_H
SCM_API scm_t_bits scm_tc16_gnutls_openpgp_certificate;
static inline SCM
scm_from_gnutls_openpgp_certificate (gnutls_openpgp_crt_t c_obj)
{
  SCM_RETURN_NEWSMOB (scm_tc16_gnutls_openpgp_certificate, (scm_t_bits) c_obj);
}
static inline gnutls_openpgp_crt_t
scm_to_gnutls_openpgp_certificate (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_openpgp_certificate);
  return ((gnutls_openpgp_crt_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
SCM_API scm_t_bits scm_tc16_gnutls_openpgp_private_key;
static inline SCM
scm_from_gnutls_openpgp_private_key (gnutls_openpgp_privkey_t c_obj)
{
  SCM_RETURN_NEWSMOB (scm_tc16_gnutls_openpgp_private_key, (scm_t_bits) c_obj);
}
static inline gnutls_openpgp_privkey_t
scm_to_gnutls_openpgp_private_key (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_openpgp_private_key);
  return ((gnutls_openpgp_privkey_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
SCM_API scm_t_bits scm_tc16_gnutls_openpgp_keyring;
static inline SCM
scm_from_gnutls_openpgp_keyring (gnutls_openpgp_keyring_t c_obj)
{
  SCM_RETURN_NEWSMOB (scm_tc16_gnutls_openpgp_keyring, (scm_t_bits) c_obj);
}
static inline gnutls_openpgp_keyring_t
scm_to_gnutls_openpgp_keyring (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_openpgp_keyring);
  return ((gnutls_openpgp_keyring_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
#endif

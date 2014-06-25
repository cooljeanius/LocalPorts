/* Automatically generated, do not edit.  */

#ifndef GUILE_GNUTLS_EXTRA_ENUMS_H
#define GUILE_GNUTLS_EXTRA_ENUMS_H
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/extra.h>
#include <gnutls/openpgp.h>
SCM_API scm_t_bits scm_tc16_gnutls_openpgp_certificate_format_enum;
SCM_API SCM scm_gnutls_openpgp_certificate_format_enum_values;
static inline gnutls_openpgp_crt_fmt_t
scm_to_gnutls_openpgp_certificate_format (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_openpgp_certificate_format_enum);
  return ((gnutls_openpgp_crt_fmt_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_openpgp_certificate_format (gnutls_openpgp_crt_fmt_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_openpgp_certificate_format_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_openpgp_crt_fmt_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
#endif

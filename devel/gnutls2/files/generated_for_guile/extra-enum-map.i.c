SCM_GLOBAL_SMOB (scm_tc16_gnutls_openpgp_certificate_format_enum, "openpgp-certificate-format", 0);
SCM scm_gnutls_openpgp_certificate_format_enum_values = SCM_EOL;
static const char *
scm_gnutls_openpgp_certificate_format_to_c_string (gnutls_openpgp_crt_fmt_t c_obj)
{
  static const struct { gnutls_openpgp_crt_fmt_t value; const char *name; } table[] =
    {
       { GNUTLS_OPENPGP_FMT_RAW, "raw" },
       { GNUTLS_OPENPGP_FMT_BASE64, "base64" },
    };
  unsigned i;
  const char *name = NULL;
  for (i = 0; i < 2; i++)
    {
      if (table[i].value == c_obj)
        {
          name = table[i].name;
          break;
        }
    }
  return (name);
}
SCM_SMOB_PRINT (scm_tc16_gnutls_openpgp_certificate_format_enum, openpgp_certificate_format_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-openpgp-certificate-format-enum ", port);
  scm_puts (scm_gnutls_openpgp_certificate_format_to_c_string (scm_to_gnutls_openpgp_certificate_format (obj, 1, "openpgp_certificate_format_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_openpgp_certificate_format_to_string, "openpgp-certificate-format->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{openpgp-certificate-format} value.")
#define FUNC_NAME s_scm_gnutls_openpgp_certificate_format_to_string
{
  gnutls_openpgp_crt_fmt_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_openpgp_certificate_format (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_openpgp_certificate_format_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
static inline void
scm_gnutls_define_enums (void)
{
  SCM enum_values, enum_smob;
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_openpgp_certificate_format_enum, (scm_t_bits) GNUTLS_OPENPGP_FMT_RAW);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("openpgp-certificate-format/raw", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_openpgp_certificate_format_enum, (scm_t_bits) GNUTLS_OPENPGP_FMT_BASE64);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("openpgp-certificate-format/base64", enum_smob);
  scm_gnutls_openpgp_certificate_format_enum_values = scm_permanent_object (enum_values);
}

/* Automatically generated, do not edit.  */

#ifndef GUILE_GNUTLS_ENUMS_H
#define GUILE_GNUTLS_ENUMS_H
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
SCM_API scm_t_bits scm_tc16_gnutls_cipher_enum;
SCM_API SCM scm_gnutls_cipher_enum_values;
static inline gnutls_cipher_algorithm_t
scm_to_gnutls_cipher (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_cipher_enum);
  return ((gnutls_cipher_algorithm_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_cipher (gnutls_cipher_algorithm_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_cipher_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_cipher_algorithm_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_kx_enum;
SCM_API SCM scm_gnutls_kx_enum_values;
static inline gnutls_kx_algorithm_t
scm_to_gnutls_kx (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_kx_enum);
  return ((gnutls_kx_algorithm_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_kx (gnutls_kx_algorithm_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_kx_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_kx_algorithm_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_params_enum;
SCM_API SCM scm_gnutls_params_enum_values;
static inline gnutls_params_type_t
scm_to_gnutls_params (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_params_enum);
  return ((gnutls_params_type_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_params (gnutls_params_type_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_params_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_params_type_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_credentials_enum;
SCM_API SCM scm_gnutls_credentials_enum_values;
static inline gnutls_credentials_type_t
scm_to_gnutls_credentials (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_credentials_enum);
  return ((gnutls_credentials_type_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_credentials (gnutls_credentials_type_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_credentials_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_credentials_type_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_mac_enum;
SCM_API SCM scm_gnutls_mac_enum_values;
static inline gnutls_mac_algorithm_t
scm_to_gnutls_mac (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_mac_enum);
  return ((gnutls_mac_algorithm_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_mac (gnutls_mac_algorithm_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_mac_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_mac_algorithm_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_digest_enum;
SCM_API SCM scm_gnutls_digest_enum_values;
static inline gnutls_digest_algorithm_t
scm_to_gnutls_digest (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_digest_enum);
  return ((gnutls_digest_algorithm_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_digest (gnutls_digest_algorithm_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_digest_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_digest_algorithm_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_compression_method_enum;
SCM_API SCM scm_gnutls_compression_method_enum_values;
static inline gnutls_compression_method_t
scm_to_gnutls_compression_method (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_compression_method_enum);
  return ((gnutls_compression_method_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_compression_method (gnutls_compression_method_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_compression_method_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_compression_method_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_connection_end_enum;
SCM_API SCM scm_gnutls_connection_end_enum_values;
static inline gnutls_connection_end_t
scm_to_gnutls_connection_end (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_connection_end_enum);
  return ((gnutls_connection_end_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_connection_end (gnutls_connection_end_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_connection_end_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_connection_end_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_alert_level_enum;
SCM_API SCM scm_gnutls_alert_level_enum_values;
static inline gnutls_alert_level_t
scm_to_gnutls_alert_level (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_alert_level_enum);
  return ((gnutls_alert_level_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_alert_level (gnutls_alert_level_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_alert_level_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_alert_level_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_alert_description_enum;
SCM_API SCM scm_gnutls_alert_description_enum_values;
static inline gnutls_alert_description_t
scm_to_gnutls_alert_description (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_alert_description_enum);
  return ((gnutls_alert_description_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_alert_description (gnutls_alert_description_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_alert_description_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_alert_description_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_handshake_description_enum;
SCM_API SCM scm_gnutls_handshake_description_enum_values;
static inline gnutls_handshake_description_t
scm_to_gnutls_handshake_description (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_handshake_description_enum);
  return ((gnutls_handshake_description_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_handshake_description (gnutls_handshake_description_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_handshake_description_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_handshake_description_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_certificate_status_enum;
SCM_API SCM scm_gnutls_certificate_status_enum_values;
static inline gnutls_certificate_status_t
scm_to_gnutls_certificate_status (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_certificate_status_enum);
  return ((gnutls_certificate_status_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_certificate_status (gnutls_certificate_status_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_certificate_status_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_certificate_status_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_certificate_request_enum;
SCM_API SCM scm_gnutls_certificate_request_enum_values;
static inline gnutls_certificate_request_t
scm_to_gnutls_certificate_request (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_certificate_request_enum);
  return ((gnutls_certificate_request_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_certificate_request (gnutls_certificate_request_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_certificate_request_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_certificate_request_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_close_request_enum;
SCM_API SCM scm_gnutls_close_request_enum_values;
static inline gnutls_close_request_t
scm_to_gnutls_close_request (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_close_request_enum);
  return ((gnutls_close_request_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_close_request (gnutls_close_request_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_close_request_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_close_request_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_protocol_enum;
SCM_API SCM scm_gnutls_protocol_enum_values;
static inline gnutls_protocol_t
scm_to_gnutls_protocol (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_protocol_enum);
  return ((gnutls_protocol_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_protocol (gnutls_protocol_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_protocol_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_protocol_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_certificate_type_enum;
SCM_API SCM scm_gnutls_certificate_type_enum_values;
static inline gnutls_certificate_type_t
scm_to_gnutls_certificate_type (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_certificate_type_enum);
  return ((gnutls_certificate_type_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_certificate_type (gnutls_certificate_type_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_certificate_type_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_certificate_type_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_x509_certificate_format_enum;
SCM_API SCM scm_gnutls_x509_certificate_format_enum_values;
static inline gnutls_x509_crt_fmt_t
scm_to_gnutls_x509_certificate_format (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_x509_certificate_format_enum);
  return ((gnutls_x509_crt_fmt_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_x509_certificate_format (gnutls_x509_crt_fmt_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_x509_certificate_format_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_x509_crt_fmt_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_x509_subject_alternative_name_enum;
SCM_API SCM scm_gnutls_x509_subject_alternative_name_enum_values;
static inline gnutls_x509_subject_alt_name_t
scm_to_gnutls_x509_subject_alternative_name (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_x509_subject_alternative_name_enum);
  return ((gnutls_x509_subject_alt_name_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_x509_subject_alternative_name (gnutls_x509_subject_alt_name_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_x509_subject_alternative_name_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_x509_subject_alt_name_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_pk_algorithm_enum;
SCM_API SCM scm_gnutls_pk_algorithm_enum_values;
static inline gnutls_pk_algorithm_t
scm_to_gnutls_pk_algorithm (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_pk_algorithm_enum);
  return ((gnutls_pk_algorithm_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_pk_algorithm (gnutls_pk_algorithm_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_pk_algorithm_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_pk_algorithm_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_sign_algorithm_enum;
SCM_API SCM scm_gnutls_sign_algorithm_enum_values;
static inline gnutls_sign_algorithm_t
scm_to_gnutls_sign_algorithm (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_sign_algorithm_enum);
  return ((gnutls_sign_algorithm_t) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_sign_algorithm (gnutls_sign_algorithm_t c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_sign_algorithm_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_sign_algorithm_t) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_psk_key_format_enum;
SCM_API SCM scm_gnutls_psk_key_format_enum_values;
static inline gnutls_psk_key_flags
scm_to_gnutls_psk_key_format (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_psk_key_format_enum);
  return ((gnutls_psk_key_flags) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_psk_key_format (gnutls_psk_key_flags c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_psk_key_format_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_psk_key_flags) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_key_usage_enum;
SCM_API SCM scm_gnutls_key_usage_enum_values;
static inline int
scm_to_gnutls_key_usage (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_key_usage_enum);
  return ((int) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_key_usage (int c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_key_usage_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((int) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_certificate_verify_enum;
SCM_API SCM scm_gnutls_certificate_verify_enum_values;
static inline gnutls_certificate_verify_flags
scm_to_gnutls_certificate_verify (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_certificate_verify_enum);
  return ((gnutls_certificate_verify_flags) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_certificate_verify (gnutls_certificate_verify_flags c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_certificate_verify_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((gnutls_certificate_verify_flags) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
SCM_API scm_t_bits scm_tc16_gnutls_error_enum;
SCM_API SCM scm_gnutls_error_enum_values;
static inline int
scm_to_gnutls_error (SCM obj, unsigned pos, const char *func)
#define FUNC_NAME func
{
  SCM_VALIDATE_SMOB (pos, obj, gnutls_error_enum);
  return ((int) SCM_SMOB_DATA (obj));
}
#undef FUNC_NAME
static inline SCM
scm_from_gnutls_error (int c_obj)
{
  SCM pair, result = SCM_BOOL_F;
  for (pair = scm_gnutls_error_enum_values; scm_is_pair (pair); pair = SCM_CDR (pair))
    {
      SCM enum_smob;
      enum_smob = SCM_CAR (pair);
      if ((int) SCM_SMOB_DATA (enum_smob) == c_obj)
        {
          result = enum_smob;
          break;
        }
    }
  return result;
}
#endif

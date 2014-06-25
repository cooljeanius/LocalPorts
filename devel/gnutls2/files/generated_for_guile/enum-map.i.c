SCM_GLOBAL_SMOB (scm_tc16_gnutls_cipher_enum, "cipher", 0);
SCM scm_gnutls_cipher_enum_values = SCM_EOL;
SCM_SMOB_PRINT (scm_tc16_gnutls_cipher_enum, cipher_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-cipher-enum ", port);
  scm_puts (gnutls_cipher_get_name (scm_to_gnutls_cipher (obj, 1, "cipher_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_cipher_to_string, "cipher->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{cipher} value.")
#define FUNC_NAME s_scm_gnutls_cipher_to_string
{
  gnutls_cipher_algorithm_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_cipher (enumval, 1, FUNC_NAME);
  c_string = gnutls_cipher_get_name (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_kx_enum, "kx", 0);
SCM scm_gnutls_kx_enum_values = SCM_EOL;
SCM_SMOB_PRINT (scm_tc16_gnutls_kx_enum, kx_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-kx-enum ", port);
  scm_puts (gnutls_kx_get_name (scm_to_gnutls_kx (obj, 1, "kx_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_kx_to_string, "kx->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{kx} value.")
#define FUNC_NAME s_scm_gnutls_kx_to_string
{
  gnutls_kx_algorithm_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_kx (enumval, 1, FUNC_NAME);
  c_string = gnutls_kx_get_name (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_params_enum, "params", 0);
SCM scm_gnutls_params_enum_values = SCM_EOL;
static const char *
scm_gnutls_params_to_c_string (gnutls_params_type_t c_obj)
{
  static const struct { gnutls_params_type_t value; const char *name; } table[] =
    {
       { GNUTLS_PARAMS_RSA_EXPORT, "rsa-export" },
       { GNUTLS_PARAMS_DH, "dh" },
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
SCM_SMOB_PRINT (scm_tc16_gnutls_params_enum, params_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-params-enum ", port);
  scm_puts (scm_gnutls_params_to_c_string (scm_to_gnutls_params (obj, 1, "params_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_params_to_string, "params->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{params} value.")
#define FUNC_NAME s_scm_gnutls_params_to_string
{
  gnutls_params_type_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_params (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_params_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_credentials_enum, "credentials", 0);
SCM scm_gnutls_credentials_enum_values = SCM_EOL;
static const char *
scm_gnutls_credentials_to_c_string (gnutls_credentials_type_t c_obj)
{
  static const struct { gnutls_credentials_type_t value; const char *name; } table[] =
    {
       { GNUTLS_CRD_CERTIFICATE, "certificate" },
       { GNUTLS_CRD_ANON, "anon" },
       { GNUTLS_CRD_SRP, "srp" },
       { GNUTLS_CRD_PSK, "psk" },
       { GNUTLS_CRD_IA, "ia" },
    };
  unsigned i;
  const char *name = NULL;
  for (i = 0; i < 5; i++)
    {
      if (table[i].value == c_obj)
        {
          name = table[i].name;
          break;
        }
    }
  return (name);
}
SCM_SMOB_PRINT (scm_tc16_gnutls_credentials_enum, credentials_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-credentials-enum ", port);
  scm_puts (scm_gnutls_credentials_to_c_string (scm_to_gnutls_credentials (obj, 1, "credentials_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_credentials_to_string, "credentials->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{credentials} value.")
#define FUNC_NAME s_scm_gnutls_credentials_to_string
{
  gnutls_credentials_type_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_credentials (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_credentials_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_mac_enum, "mac", 0);
SCM scm_gnutls_mac_enum_values = SCM_EOL;
SCM_SMOB_PRINT (scm_tc16_gnutls_mac_enum, mac_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-mac-enum ", port);
  scm_puts (gnutls_mac_get_name (scm_to_gnutls_mac (obj, 1, "mac_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_mac_to_string, "mac->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{mac} value.")
#define FUNC_NAME s_scm_gnutls_mac_to_string
{
  gnutls_mac_algorithm_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_mac (enumval, 1, FUNC_NAME);
  c_string = gnutls_mac_get_name (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_digest_enum, "digest", 0);
SCM scm_gnutls_digest_enum_values = SCM_EOL;
static const char *
scm_gnutls_digest_to_c_string (gnutls_digest_algorithm_t c_obj)
{
  static const struct { gnutls_digest_algorithm_t value; const char *name; } table[] =
    {
       { GNUTLS_DIG_NULL, "null" },
       { GNUTLS_DIG_MD5, "md5" },
       { GNUTLS_DIG_SHA1, "sha1" },
       { GNUTLS_DIG_RMD160, "rmd160" },
       { GNUTLS_DIG_MD2, "md2" },
    };
  unsigned i;
  const char *name = NULL;
  for (i = 0; i < 5; i++)
    {
      if (table[i].value == c_obj)
        {
          name = table[i].name;
          break;
        }
    }
  return (name);
}
SCM_SMOB_PRINT (scm_tc16_gnutls_digest_enum, digest_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-digest-enum ", port);
  scm_puts (scm_gnutls_digest_to_c_string (scm_to_gnutls_digest (obj, 1, "digest_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_digest_to_string, "digest->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{digest} value.")
#define FUNC_NAME s_scm_gnutls_digest_to_string
{
  gnutls_digest_algorithm_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_digest (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_digest_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_compression_method_enum, "compression-method", 0);
SCM scm_gnutls_compression_method_enum_values = SCM_EOL;
SCM_SMOB_PRINT (scm_tc16_gnutls_compression_method_enum, compression_method_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-compression-method-enum ", port);
  scm_puts (gnutls_compression_get_name (scm_to_gnutls_compression_method (obj, 1, "compression_method_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_compression_method_to_string, "compression-method->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{compression-method} value.")
#define FUNC_NAME s_scm_gnutls_compression_method_to_string
{
  gnutls_compression_method_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_compression_method (enumval, 1, FUNC_NAME);
  c_string = gnutls_compression_get_name (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_connection_end_enum, "connection-end", 0);
SCM scm_gnutls_connection_end_enum_values = SCM_EOL;
static const char *
scm_gnutls_connection_end_to_c_string (gnutls_connection_end_t c_obj)
{
  static const struct { gnutls_connection_end_t value; const char *name; } table[] =
    {
       { GNUTLS_SERVER, "server" },
       { GNUTLS_CLIENT, "client" },
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
SCM_SMOB_PRINT (scm_tc16_gnutls_connection_end_enum, connection_end_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-connection-end-enum ", port);
  scm_puts (scm_gnutls_connection_end_to_c_string (scm_to_gnutls_connection_end (obj, 1, "connection_end_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_connection_end_to_string, "connection-end->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{connection-end} value.")
#define FUNC_NAME s_scm_gnutls_connection_end_to_string
{
  gnutls_connection_end_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_connection_end (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_connection_end_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_alert_level_enum, "alert-level", 0);
SCM scm_gnutls_alert_level_enum_values = SCM_EOL;
static const char *
scm_gnutls_alert_level_to_c_string (gnutls_alert_level_t c_obj)
{
  static const struct { gnutls_alert_level_t value; const char *name; } table[] =
    {
       { GNUTLS_AL_WARNING, "warning" },
       { GNUTLS_AL_FATAL, "fatal" },
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
SCM_SMOB_PRINT (scm_tc16_gnutls_alert_level_enum, alert_level_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-alert-level-enum ", port);
  scm_puts (scm_gnutls_alert_level_to_c_string (scm_to_gnutls_alert_level (obj, 1, "alert_level_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_alert_level_to_string, "alert-level->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{alert-level} value.")
#define FUNC_NAME s_scm_gnutls_alert_level_to_string
{
  gnutls_alert_level_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_alert_level (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_alert_level_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_alert_description_enum, "alert-description", 0);
SCM scm_gnutls_alert_description_enum_values = SCM_EOL;
static const char *
scm_gnutls_alert_description_to_c_string (gnutls_alert_description_t c_obj)
{
  static const struct { gnutls_alert_description_t value; const char *name; } table[] =
    {
       { GNUTLS_A_CLOSE_NOTIFY, "close-notify" },
       { GNUTLS_A_UNEXPECTED_MESSAGE, "unexpected-message" },
       { GNUTLS_A_BAD_RECORD_MAC, "bad-record-mac" },
       { GNUTLS_A_DECRYPTION_FAILED, "decryption-failed" },
       { GNUTLS_A_RECORD_OVERFLOW, "record-overflow" },
       { GNUTLS_A_DECOMPRESSION_FAILURE, "decompression-failure" },
       { GNUTLS_A_HANDSHAKE_FAILURE, "handshake-failure" },
       { GNUTLS_A_SSL3_NO_CERTIFICATE, "ssl3-no-certificate" },
       { GNUTLS_A_BAD_CERTIFICATE, "bad-certificate" },
       { GNUTLS_A_UNSUPPORTED_CERTIFICATE, "unsupported-certificate" },
       { GNUTLS_A_CERTIFICATE_REVOKED, "certificate-revoked" },
       { GNUTLS_A_CERTIFICATE_EXPIRED, "certificate-expired" },
       { GNUTLS_A_CERTIFICATE_UNKNOWN, "certificate-unknown" },
       { GNUTLS_A_ILLEGAL_PARAMETER, "illegal-parameter" },
       { GNUTLS_A_UNKNOWN_CA, "unknown-ca" },
       { GNUTLS_A_ACCESS_DENIED, "access-denied" },
       { GNUTLS_A_DECODE_ERROR, "decode-error" },
       { GNUTLS_A_DECRYPT_ERROR, "decrypt-error" },
       { GNUTLS_A_EXPORT_RESTRICTION, "export-restriction" },
       { GNUTLS_A_PROTOCOL_VERSION, "protocol-version" },
       { GNUTLS_A_INSUFFICIENT_SECURITY, "insufficient-security" },
       { GNUTLS_A_INTERNAL_ERROR, "internal-error" },
       { GNUTLS_A_USER_CANCELED, "user-canceled" },
       { GNUTLS_A_NO_RENEGOTIATION, "no-renegotiation" },
       { GNUTLS_A_UNSUPPORTED_EXTENSION, "unsupported-extension" },
       { GNUTLS_A_CERTIFICATE_UNOBTAINABLE, "certificate-unobtainable" },
       { GNUTLS_A_UNRECOGNIZED_NAME, "unrecognized-name" },
       { GNUTLS_A_UNKNOWN_PSK_IDENTITY, "unknown-psk-identity" },
       { GNUTLS_A_INNER_APPLICATION_FAILURE, "inner-application-failure" },
       { GNUTLS_A_INNER_APPLICATION_VERIFICATION, "inner-application-verification" },
    };
  unsigned i;
  const char *name = NULL;
  for (i = 0; i < 30; i++)
    {
      if (table[i].value == c_obj)
        {
          name = table[i].name;
          break;
        }
    }
  return (name);
}
SCM_SMOB_PRINT (scm_tc16_gnutls_alert_description_enum, alert_description_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-alert-description-enum ", port);
  scm_puts (scm_gnutls_alert_description_to_c_string (scm_to_gnutls_alert_description (obj, 1, "alert_description_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_alert_description_to_string, "alert-description->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{alert-description} value.")
#define FUNC_NAME s_scm_gnutls_alert_description_to_string
{
  gnutls_alert_description_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_alert_description (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_alert_description_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_handshake_description_enum, "handshake-description", 0);
SCM scm_gnutls_handshake_description_enum_values = SCM_EOL;
static const char *
scm_gnutls_handshake_description_to_c_string (gnutls_handshake_description_t c_obj)
{
  static const struct { gnutls_handshake_description_t value; const char *name; } table[] =
    {
       { GNUTLS_HANDSHAKE_HELLO_REQUEST, "hello-request" },
       { GNUTLS_HANDSHAKE_CLIENT_HELLO, "client-hello" },
       { GNUTLS_HANDSHAKE_SERVER_HELLO, "server-hello" },
       { GNUTLS_HANDSHAKE_CERTIFICATE_PKT, "certificate-pkt" },
       { GNUTLS_HANDSHAKE_SERVER_KEY_EXCHANGE, "server-key-exchange" },
       { GNUTLS_HANDSHAKE_CERTIFICATE_REQUEST, "certificate-request" },
       { GNUTLS_HANDSHAKE_SERVER_HELLO_DONE, "server-hello-done" },
       { GNUTLS_HANDSHAKE_CERTIFICATE_VERIFY, "certificate-verify" },
       { GNUTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE, "client-key-exchange" },
       { GNUTLS_HANDSHAKE_FINISHED, "finished" },
    };
  unsigned i;
  const char *name = NULL;
  for (i = 0; i < 10; i++)
    {
      if (table[i].value == c_obj)
        {
          name = table[i].name;
          break;
        }
    }
  return (name);
}
SCM_SMOB_PRINT (scm_tc16_gnutls_handshake_description_enum, handshake_description_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-handshake-description-enum ", port);
  scm_puts (scm_gnutls_handshake_description_to_c_string (scm_to_gnutls_handshake_description (obj, 1, "handshake_description_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_handshake_description_to_string, "handshake-description->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{handshake-description} value.")
#define FUNC_NAME s_scm_gnutls_handshake_description_to_string
{
  gnutls_handshake_description_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_handshake_description (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_handshake_description_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_certificate_status_enum, "certificate-status", 0);
SCM scm_gnutls_certificate_status_enum_values = SCM_EOL;
static const char *
scm_gnutls_certificate_status_to_c_string (gnutls_certificate_status_t c_obj)
{
  static const struct { gnutls_certificate_status_t value; const char *name; } table[] =
    {
       { GNUTLS_CERT_INVALID, "invalid" },
       { GNUTLS_CERT_REVOKED, "revoked" },
       { GNUTLS_CERT_SIGNER_NOT_FOUND, "signer-not-found" },
       { GNUTLS_CERT_SIGNER_NOT_CA, "signer-not-ca" },
       { GNUTLS_CERT_INSECURE_ALGORITHM, "insecure-algorithm" },
    };
  unsigned i;
  const char *name = NULL;
  for (i = 0; i < 5; i++)
    {
      if (table[i].value == c_obj)
        {
          name = table[i].name;
          break;
        }
    }
  return (name);
}
SCM_SMOB_PRINT (scm_tc16_gnutls_certificate_status_enum, certificate_status_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-certificate-status-enum ", port);
  scm_puts (scm_gnutls_certificate_status_to_c_string (scm_to_gnutls_certificate_status (obj, 1, "certificate_status_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_certificate_status_to_string, "certificate-status->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{certificate-status} value.")
#define FUNC_NAME s_scm_gnutls_certificate_status_to_string
{
  gnutls_certificate_status_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_certificate_status (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_certificate_status_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_certificate_request_enum, "certificate-request", 0);
SCM scm_gnutls_certificate_request_enum_values = SCM_EOL;
static const char *
scm_gnutls_certificate_request_to_c_string (gnutls_certificate_request_t c_obj)
{
  static const struct { gnutls_certificate_request_t value; const char *name; } table[] =
    {
       { GNUTLS_CERT_IGNORE, "ignore" },
       { GNUTLS_CERT_REQUEST, "request" },
       { GNUTLS_CERT_REQUIRE, "require" },
    };
  unsigned i;
  const char *name = NULL;
  for (i = 0; i < 3; i++)
    {
      if (table[i].value == c_obj)
        {
          name = table[i].name;
          break;
        }
    }
  return (name);
}
SCM_SMOB_PRINT (scm_tc16_gnutls_certificate_request_enum, certificate_request_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-certificate-request-enum ", port);
  scm_puts (scm_gnutls_certificate_request_to_c_string (scm_to_gnutls_certificate_request (obj, 1, "certificate_request_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_certificate_request_to_string, "certificate-request->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{certificate-request} value.")
#define FUNC_NAME s_scm_gnutls_certificate_request_to_string
{
  gnutls_certificate_request_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_certificate_request (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_certificate_request_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_close_request_enum, "close-request", 0);
SCM scm_gnutls_close_request_enum_values = SCM_EOL;
static const char *
scm_gnutls_close_request_to_c_string (gnutls_close_request_t c_obj)
{
  static const struct { gnutls_close_request_t value; const char *name; } table[] =
    {
       { GNUTLS_SHUT_RDWR, "rdwr" },
       { GNUTLS_SHUT_WR, "wr" },
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
SCM_SMOB_PRINT (scm_tc16_gnutls_close_request_enum, close_request_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-close-request-enum ", port);
  scm_puts (scm_gnutls_close_request_to_c_string (scm_to_gnutls_close_request (obj, 1, "close_request_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_close_request_to_string, "close-request->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{close-request} value.")
#define FUNC_NAME s_scm_gnutls_close_request_to_string
{
  gnutls_close_request_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_close_request (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_close_request_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_protocol_enum, "protocol", 0);
SCM scm_gnutls_protocol_enum_values = SCM_EOL;
static const char *
scm_gnutls_protocol_to_c_string (gnutls_protocol_t c_obj)
{
  static const struct { gnutls_protocol_t value; const char *name; } table[] =
    {
       { GNUTLS_SSL3, "ssl3" },
       { GNUTLS_TLS1_0, "tls1-0" },
       { GNUTLS_TLS1_1, "tls1-1" },
       { GNUTLS_VERSION_UNKNOWN, "version-unknown" },
    };
  unsigned i;
  const char *name = NULL;
  for (i = 0; i < 4; i++)
    {
      if (table[i].value == c_obj)
        {
          name = table[i].name;
          break;
        }
    }
  return (name);
}
SCM_SMOB_PRINT (scm_tc16_gnutls_protocol_enum, protocol_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-protocol-enum ", port);
  scm_puts (scm_gnutls_protocol_to_c_string (scm_to_gnutls_protocol (obj, 1, "protocol_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_protocol_to_string, "protocol->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{protocol} value.")
#define FUNC_NAME s_scm_gnutls_protocol_to_string
{
  gnutls_protocol_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_protocol (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_protocol_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_certificate_type_enum, "certificate-type", 0);
SCM scm_gnutls_certificate_type_enum_values = SCM_EOL;
SCM_SMOB_PRINT (scm_tc16_gnutls_certificate_type_enum, certificate_type_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-certificate-type-enum ", port);
  scm_puts (gnutls_certificate_type_get_name (scm_to_gnutls_certificate_type (obj, 1, "certificate_type_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_certificate_type_to_string, "certificate-type->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{certificate-type} value.")
#define FUNC_NAME s_scm_gnutls_certificate_type_to_string
{
  gnutls_certificate_type_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_certificate_type (enumval, 1, FUNC_NAME);
  c_string = gnutls_certificate_type_get_name (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_x509_certificate_format_enum, "x509-certificate-format", 0);
SCM scm_gnutls_x509_certificate_format_enum_values = SCM_EOL;
static const char *
scm_gnutls_x509_certificate_format_to_c_string (gnutls_x509_crt_fmt_t c_obj)
{
  static const struct { gnutls_x509_crt_fmt_t value; const char *name; } table[] =
    {
       { GNUTLS_X509_FMT_DER, "der" },
       { GNUTLS_X509_FMT_PEM, "pem" },
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
SCM_SMOB_PRINT (scm_tc16_gnutls_x509_certificate_format_enum, x509_certificate_format_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-x509-certificate-format-enum ", port);
  scm_puts (scm_gnutls_x509_certificate_format_to_c_string (scm_to_gnutls_x509_certificate_format (obj, 1, "x509_certificate_format_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_x509_certificate_format_to_string, "x509-certificate-format->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{x509-certificate-format} value.")
#define FUNC_NAME s_scm_gnutls_x509_certificate_format_to_string
{
  gnutls_x509_crt_fmt_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_x509_certificate_format (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_x509_certificate_format_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_x509_subject_alternative_name_enum, "x509-subject-alternative-name", 0);
SCM scm_gnutls_x509_subject_alternative_name_enum_values = SCM_EOL;
static const char *
scm_gnutls_x509_subject_alternative_name_to_c_string (gnutls_x509_subject_alt_name_t c_obj)
{
  static const struct { gnutls_x509_subject_alt_name_t value; const char *name; } table[] =
    {
       { GNUTLS_SAN_DNSNAME, "dnsname" },
       { GNUTLS_SAN_RFC822NAME, "rfc822name" },
       { GNUTLS_SAN_URI, "uri" },
       { GNUTLS_SAN_IPADDRESS, "ipaddress" },
    };
  unsigned i;
  const char *name = NULL;
  for (i = 0; i < 4; i++)
    {
      if (table[i].value == c_obj)
        {
          name = table[i].name;
          break;
        }
    }
  return (name);
}
SCM_SMOB_PRINT (scm_tc16_gnutls_x509_subject_alternative_name_enum, x509_subject_alternative_name_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-x509-subject-alternative-name-enum ", port);
  scm_puts (scm_gnutls_x509_subject_alternative_name_to_c_string (scm_to_gnutls_x509_subject_alternative_name (obj, 1, "x509_subject_alternative_name_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_x509_subject_alternative_name_to_string, "x509-subject-alternative-name->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{x509-subject-alternative-name} value.")
#define FUNC_NAME s_scm_gnutls_x509_subject_alternative_name_to_string
{
  gnutls_x509_subject_alt_name_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_x509_subject_alternative_name (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_x509_subject_alternative_name_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_pk_algorithm_enum, "pk-algorithm", 0);
SCM scm_gnutls_pk_algorithm_enum_values = SCM_EOL;
SCM_SMOB_PRINT (scm_tc16_gnutls_pk_algorithm_enum, pk_algorithm_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-pk-algorithm-enum ", port);
  scm_puts (gnutls_pk_algorithm_get_name (scm_to_gnutls_pk_algorithm (obj, 1, "pk_algorithm_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_pk_algorithm_to_string, "pk-algorithm->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{pk-algorithm} value.")
#define FUNC_NAME s_scm_gnutls_pk_algorithm_to_string
{
  gnutls_pk_algorithm_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_pk_algorithm (enumval, 1, FUNC_NAME);
  c_string = gnutls_pk_algorithm_get_name (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_sign_algorithm_enum, "sign-algorithm", 0);
SCM scm_gnutls_sign_algorithm_enum_values = SCM_EOL;
SCM_SMOB_PRINT (scm_tc16_gnutls_sign_algorithm_enum, sign_algorithm_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-sign-algorithm-enum ", port);
  scm_puts (gnutls_sign_algorithm_get_name (scm_to_gnutls_sign_algorithm (obj, 1, "sign_algorithm_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_sign_algorithm_to_string, "sign-algorithm->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{sign-algorithm} value.")
#define FUNC_NAME s_scm_gnutls_sign_algorithm_to_string
{
  gnutls_sign_algorithm_t c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_sign_algorithm (enumval, 1, FUNC_NAME);
  c_string = gnutls_sign_algorithm_get_name (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_psk_key_format_enum, "psk-key-format", 0);
SCM scm_gnutls_psk_key_format_enum_values = SCM_EOL;
static const char *
scm_gnutls_psk_key_format_to_c_string (gnutls_psk_key_flags c_obj)
{
  static const struct { gnutls_psk_key_flags value; const char *name; } table[] =
    {
       { GNUTLS_PSK_KEY_RAW, "raw" },
       { GNUTLS_PSK_KEY_HEX, "hex" },
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
SCM_SMOB_PRINT (scm_tc16_gnutls_psk_key_format_enum, psk_key_format_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-psk-key-format-enum ", port);
  scm_puts (scm_gnutls_psk_key_format_to_c_string (scm_to_gnutls_psk_key_format (obj, 1, "psk_key_format_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_psk_key_format_to_string, "psk-key-format->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{psk-key-format} value.")
#define FUNC_NAME s_scm_gnutls_psk_key_format_to_string
{
  gnutls_psk_key_flags c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_psk_key_format (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_psk_key_format_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_key_usage_enum, "key-usage", 0);
SCM scm_gnutls_key_usage_enum_values = SCM_EOL;
static const char *
scm_gnutls_key_usage_to_c_string (int c_obj)
{
  static const struct { int value; const char *name; } table[] =
    {
       { GNUTLS_KEY_DIGITAL_SIGNATURE, "digital-signature" },
       { GNUTLS_KEY_NON_REPUDIATION, "non-repudiation" },
       { GNUTLS_KEY_KEY_ENCIPHERMENT, "key-encipherment" },
       { GNUTLS_KEY_DATA_ENCIPHERMENT, "data-encipherment" },
       { GNUTLS_KEY_KEY_AGREEMENT, "key-agreement" },
       { GNUTLS_KEY_KEY_CERT_SIGN, "key-cert-sign" },
       { GNUTLS_KEY_CRL_SIGN, "crl-sign" },
       { GNUTLS_KEY_ENCIPHER_ONLY, "encipher-only" },
       { GNUTLS_KEY_DECIPHER_ONLY, "decipher-only" },
    };
  unsigned i;
  const char *name = NULL;
  for (i = 0; i < 9; i++)
    {
      if (table[i].value == c_obj)
        {
          name = table[i].name;
          break;
        }
    }
  return (name);
}
SCM_SMOB_PRINT (scm_tc16_gnutls_key_usage_enum, key_usage_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-key-usage-enum ", port);
  scm_puts (scm_gnutls_key_usage_to_c_string (scm_to_gnutls_key_usage (obj, 1, "key_usage_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_key_usage_to_string, "key-usage->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{key-usage} value.")
#define FUNC_NAME s_scm_gnutls_key_usage_to_string
{
  int c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_key_usage (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_key_usage_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_certificate_verify_enum, "certificate-verify", 0);
SCM scm_gnutls_certificate_verify_enum_values = SCM_EOL;
static const char *
scm_gnutls_certificate_verify_to_c_string (gnutls_certificate_verify_flags c_obj)
{
  static const struct { gnutls_certificate_verify_flags value; const char *name; } table[] =
    {
       { GNUTLS_VERIFY_DISABLE_CA_SIGN, "disable-ca-sign" },
       { GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT, "allow-x509-v1-ca-crt" },
       { GNUTLS_VERIFY_DO_NOT_ALLOW_SAME, "do-not-allow-same" },
       { GNUTLS_VERIFY_ALLOW_ANY_X509_V1_CA_CRT, "allow-any-x509-v1-ca-crt" },
       { GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2, "allow-sign-rsa-md2" },
       { GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5, "allow-sign-rsa-md5" },
    };
  unsigned i;
  const char *name = NULL;
  for (i = 0; i < 6; i++)
    {
      if (table[i].value == c_obj)
        {
          name = table[i].name;
          break;
        }
    }
  return (name);
}
SCM_SMOB_PRINT (scm_tc16_gnutls_certificate_verify_enum, certificate_verify_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-certificate-verify-enum ", port);
  scm_puts (scm_gnutls_certificate_verify_to_c_string (scm_to_gnutls_certificate_verify (obj, 1, "certificate_verify_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_certificate_verify_to_string, "certificate-verify->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{certificate-verify} value.")
#define FUNC_NAME s_scm_gnutls_certificate_verify_to_string
{
  gnutls_certificate_verify_flags c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_certificate_verify (enumval, 1, FUNC_NAME);
  c_string = scm_gnutls_certificate_verify_to_c_string (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
SCM_GLOBAL_SMOB (scm_tc16_gnutls_error_enum, "error", 0);
SCM scm_gnutls_error_enum_values = SCM_EOL;
SCM_SMOB_PRINT (scm_tc16_gnutls_error_enum, error_print, obj, port, pstate)
{
  scm_puts ("#<gnutls-error-enum ", port);
  scm_puts (gnutls_strerror (scm_to_gnutls_error (obj, 1, "error_print")), port);
  scm_puts (">", port);
  return 1;
}
SCM_DEFINE (scm_gnutls_error_to_string, "error->string", 1, 0, 0,
            (SCM enumval),
            "Return a string describing @var{enumval}, a @code{error} value.")
#define FUNC_NAME s_scm_gnutls_error_to_string
{
  int c_enum;
  const char *c_string;
  c_enum = scm_to_gnutls_error (enumval, 1, FUNC_NAME);
  c_string = gnutls_strerror (c_enum);
  return (scm_from_locale_string (c_string));
}
#undef FUNC_NAME
static inline void
scm_gnutls_define_enums (void)
{
  SCM enum_values, enum_smob;
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_cipher_enum, (scm_t_bits) GNUTLS_CIPHER_NULL);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("cipher/null", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_cipher_enum, (scm_t_bits) GNUTLS_CIPHER_ARCFOUR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("cipher/arcfour", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_cipher_enum, (scm_t_bits) GNUTLS_CIPHER_3DES_CBC);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("cipher/3des-cbc", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_cipher_enum, (scm_t_bits) GNUTLS_CIPHER_AES_128_CBC);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("cipher/aes-128-cbc", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_cipher_enum, (scm_t_bits) GNUTLS_CIPHER_AES_256_CBC);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("cipher/aes-256-cbc", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_cipher_enum, (scm_t_bits) GNUTLS_CIPHER_ARCFOUR_40);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("cipher/arcfour-40", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_cipher_enum, (scm_t_bits) GNUTLS_CIPHER_RC2_40_CBC);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("cipher/rc2-40-cbc", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_cipher_enum, (scm_t_bits) GNUTLS_CIPHER_DES_CBC);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("cipher/des-cbc", enum_smob);
  scm_gnutls_cipher_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_kx_enum, (scm_t_bits) GNUTLS_KX_RSA);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("kx/rsa", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_kx_enum, (scm_t_bits) GNUTLS_KX_DHE_DSS);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("kx/dhe-dss", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_kx_enum, (scm_t_bits) GNUTLS_KX_DHE_RSA);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("kx/dhe-rsa", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_kx_enum, (scm_t_bits) GNUTLS_KX_ANON_DH);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("kx/anon-dh", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_kx_enum, (scm_t_bits) GNUTLS_KX_SRP);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("kx/srp", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_kx_enum, (scm_t_bits) GNUTLS_KX_RSA_EXPORT);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("kx/rsa-export", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_kx_enum, (scm_t_bits) GNUTLS_KX_SRP_RSA);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("kx/srp-rsa", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_kx_enum, (scm_t_bits) GNUTLS_KX_SRP_DSS);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("kx/srp-dss", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_kx_enum, (scm_t_bits) GNUTLS_KX_PSK);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("kx/psk", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_kx_enum, (scm_t_bits) GNUTLS_KX_DHE_DSS);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("kx/dhe-dss", enum_smob);
  scm_gnutls_kx_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_params_enum, (scm_t_bits) GNUTLS_PARAMS_RSA_EXPORT);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("params/rsa-export", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_params_enum, (scm_t_bits) GNUTLS_PARAMS_DH);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("params/dh", enum_smob);
  scm_gnutls_params_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_credentials_enum, (scm_t_bits) GNUTLS_CRD_CERTIFICATE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("credentials/certificate", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_credentials_enum, (scm_t_bits) GNUTLS_CRD_ANON);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("credentials/anon", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_credentials_enum, (scm_t_bits) GNUTLS_CRD_SRP);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("credentials/srp", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_credentials_enum, (scm_t_bits) GNUTLS_CRD_PSK);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("credentials/psk", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_credentials_enum, (scm_t_bits) GNUTLS_CRD_IA);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("credentials/ia", enum_smob);
  scm_gnutls_credentials_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_mac_enum, (scm_t_bits) GNUTLS_MAC_UNKNOWN);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("mac/unknown", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_mac_enum, (scm_t_bits) GNUTLS_MAC_NULL);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("mac/null", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_mac_enum, (scm_t_bits) GNUTLS_MAC_MD5);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("mac/md5", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_mac_enum, (scm_t_bits) GNUTLS_MAC_SHA1);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("mac/sha1", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_mac_enum, (scm_t_bits) GNUTLS_MAC_RMD160);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("mac/rmd160", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_mac_enum, (scm_t_bits) GNUTLS_MAC_MD2);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("mac/md2", enum_smob);
  scm_gnutls_mac_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_digest_enum, (scm_t_bits) GNUTLS_DIG_NULL);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("digest/null", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_digest_enum, (scm_t_bits) GNUTLS_DIG_MD5);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("digest/md5", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_digest_enum, (scm_t_bits) GNUTLS_DIG_SHA1);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("digest/sha1", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_digest_enum, (scm_t_bits) GNUTLS_DIG_RMD160);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("digest/rmd160", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_digest_enum, (scm_t_bits) GNUTLS_DIG_MD2);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("digest/md2", enum_smob);
  scm_gnutls_digest_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_compression_method_enum, (scm_t_bits) GNUTLS_COMP_NULL);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("compression-method/null", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_compression_method_enum, (scm_t_bits) GNUTLS_COMP_DEFLATE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("compression-method/deflate", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_compression_method_enum, (scm_t_bits) GNUTLS_COMP_LZO);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("compression-method/lzo", enum_smob);
  scm_gnutls_compression_method_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_connection_end_enum, (scm_t_bits) GNUTLS_SERVER);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("connection-end/server", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_connection_end_enum, (scm_t_bits) GNUTLS_CLIENT);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("connection-end/client", enum_smob);
  scm_gnutls_connection_end_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_level_enum, (scm_t_bits) GNUTLS_AL_WARNING);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-level/warning", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_level_enum, (scm_t_bits) GNUTLS_AL_FATAL);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-level/fatal", enum_smob);
  scm_gnutls_alert_level_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_CLOSE_NOTIFY);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/close-notify", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_UNEXPECTED_MESSAGE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/unexpected-message", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_BAD_RECORD_MAC);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/bad-record-mac", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_DECRYPTION_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/decryption-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_RECORD_OVERFLOW);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/record-overflow", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_DECOMPRESSION_FAILURE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/decompression-failure", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_HANDSHAKE_FAILURE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/handshake-failure", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_SSL3_NO_CERTIFICATE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/ssl3-no-certificate", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_BAD_CERTIFICATE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/bad-certificate", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_UNSUPPORTED_CERTIFICATE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/unsupported-certificate", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_CERTIFICATE_REVOKED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/certificate-revoked", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_CERTIFICATE_EXPIRED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/certificate-expired", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_CERTIFICATE_UNKNOWN);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/certificate-unknown", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_ILLEGAL_PARAMETER);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/illegal-parameter", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_UNKNOWN_CA);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/unknown-ca", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_ACCESS_DENIED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/access-denied", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_DECODE_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/decode-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_DECRYPT_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/decrypt-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_EXPORT_RESTRICTION);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/export-restriction", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_PROTOCOL_VERSION);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/protocol-version", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_INSUFFICIENT_SECURITY);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/insufficient-security", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_INTERNAL_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/internal-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_USER_CANCELED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/user-canceled", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_NO_RENEGOTIATION);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/no-renegotiation", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_UNSUPPORTED_EXTENSION);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/unsupported-extension", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_CERTIFICATE_UNOBTAINABLE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/certificate-unobtainable", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_UNRECOGNIZED_NAME);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/unrecognized-name", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_UNKNOWN_PSK_IDENTITY);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/unknown-psk-identity", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_INNER_APPLICATION_FAILURE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/inner-application-failure", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_alert_description_enum, (scm_t_bits) GNUTLS_A_INNER_APPLICATION_VERIFICATION);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("alert-description/inner-application-verification", enum_smob);
  scm_gnutls_alert_description_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_handshake_description_enum, (scm_t_bits) GNUTLS_HANDSHAKE_HELLO_REQUEST);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("handshake-description/hello-request", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_handshake_description_enum, (scm_t_bits) GNUTLS_HANDSHAKE_CLIENT_HELLO);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("handshake-description/client-hello", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_handshake_description_enum, (scm_t_bits) GNUTLS_HANDSHAKE_SERVER_HELLO);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("handshake-description/server-hello", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_handshake_description_enum, (scm_t_bits) GNUTLS_HANDSHAKE_CERTIFICATE_PKT);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("handshake-description/certificate-pkt", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_handshake_description_enum, (scm_t_bits) GNUTLS_HANDSHAKE_SERVER_KEY_EXCHANGE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("handshake-description/server-key-exchange", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_handshake_description_enum, (scm_t_bits) GNUTLS_HANDSHAKE_CERTIFICATE_REQUEST);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("handshake-description/certificate-request", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_handshake_description_enum, (scm_t_bits) GNUTLS_HANDSHAKE_SERVER_HELLO_DONE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("handshake-description/server-hello-done", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_handshake_description_enum, (scm_t_bits) GNUTLS_HANDSHAKE_CERTIFICATE_VERIFY);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("handshake-description/certificate-verify", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_handshake_description_enum, (scm_t_bits) GNUTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("handshake-description/client-key-exchange", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_handshake_description_enum, (scm_t_bits) GNUTLS_HANDSHAKE_FINISHED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("handshake-description/finished", enum_smob);
  scm_gnutls_handshake_description_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_certificate_status_enum, (scm_t_bits) GNUTLS_CERT_INVALID);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("certificate-status/invalid", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_certificate_status_enum, (scm_t_bits) GNUTLS_CERT_REVOKED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("certificate-status/revoked", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_certificate_status_enum, (scm_t_bits) GNUTLS_CERT_SIGNER_NOT_FOUND);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("certificate-status/signer-not-found", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_certificate_status_enum, (scm_t_bits) GNUTLS_CERT_SIGNER_NOT_CA);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("certificate-status/signer-not-ca", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_certificate_status_enum, (scm_t_bits) GNUTLS_CERT_INSECURE_ALGORITHM);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("certificate-status/insecure-algorithm", enum_smob);
  scm_gnutls_certificate_status_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_certificate_request_enum, (scm_t_bits) GNUTLS_CERT_IGNORE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("certificate-request/ignore", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_certificate_request_enum, (scm_t_bits) GNUTLS_CERT_REQUEST);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("certificate-request/request", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_certificate_request_enum, (scm_t_bits) GNUTLS_CERT_REQUIRE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("certificate-request/require", enum_smob);
  scm_gnutls_certificate_request_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_close_request_enum, (scm_t_bits) GNUTLS_SHUT_RDWR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("close-request/rdwr", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_close_request_enum, (scm_t_bits) GNUTLS_SHUT_WR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("close-request/wr", enum_smob);
  scm_gnutls_close_request_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_protocol_enum, (scm_t_bits) GNUTLS_SSL3);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("protocol/ssl3", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_protocol_enum, (scm_t_bits) GNUTLS_TLS1_0);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("protocol/tls1-0", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_protocol_enum, (scm_t_bits) GNUTLS_TLS1_1);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("protocol/tls1-1", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_protocol_enum, (scm_t_bits) GNUTLS_VERSION_UNKNOWN);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("protocol/version-unknown", enum_smob);
  scm_gnutls_protocol_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_certificate_type_enum, (scm_t_bits) GNUTLS_CRT_X509);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("certificate-type/x509", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_certificate_type_enum, (scm_t_bits) GNUTLS_CRT_OPENPGP);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("certificate-type/openpgp", enum_smob);
  scm_gnutls_certificate_type_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_x509_certificate_format_enum, (scm_t_bits) GNUTLS_X509_FMT_DER);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("x509-certificate-format/der", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_x509_certificate_format_enum, (scm_t_bits) GNUTLS_X509_FMT_PEM);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("x509-certificate-format/pem", enum_smob);
  scm_gnutls_x509_certificate_format_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_x509_subject_alternative_name_enum, (scm_t_bits) GNUTLS_SAN_DNSNAME);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("x509-subject-alternative-name/dnsname", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_x509_subject_alternative_name_enum, (scm_t_bits) GNUTLS_SAN_RFC822NAME);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("x509-subject-alternative-name/rfc822name", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_x509_subject_alternative_name_enum, (scm_t_bits) GNUTLS_SAN_URI);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("x509-subject-alternative-name/uri", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_x509_subject_alternative_name_enum, (scm_t_bits) GNUTLS_SAN_IPADDRESS);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("x509-subject-alternative-name/ipaddress", enum_smob);
  scm_gnutls_x509_subject_alternative_name_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_pk_algorithm_enum, (scm_t_bits) GNUTLS_PK_UNKNOWN);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("pk-algorithm/unknown", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_pk_algorithm_enum, (scm_t_bits) GNUTLS_PK_RSA);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("pk-algorithm/rsa", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_pk_algorithm_enum, (scm_t_bits) GNUTLS_PK_DSA);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("pk-algorithm/dsa", enum_smob);
  scm_gnutls_pk_algorithm_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_sign_algorithm_enum, (scm_t_bits) GNUTLS_SIGN_UNKNOWN);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("sign-algorithm/unknown", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_sign_algorithm_enum, (scm_t_bits) GNUTLS_SIGN_RSA_SHA1);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("sign-algorithm/rsa-sha1", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_sign_algorithm_enum, (scm_t_bits) GNUTLS_SIGN_DSA_SHA1);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("sign-algorithm/dsa-sha1", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_sign_algorithm_enum, (scm_t_bits) GNUTLS_SIGN_RSA_MD5);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("sign-algorithm/rsa-md5", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_sign_algorithm_enum, (scm_t_bits) GNUTLS_SIGN_RSA_MD2);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("sign-algorithm/rsa-md2", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_sign_algorithm_enum, (scm_t_bits) GNUTLS_SIGN_RSA_RMD160);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("sign-algorithm/rsa-rmd160", enum_smob);
  scm_gnutls_sign_algorithm_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_psk_key_format_enum, (scm_t_bits) GNUTLS_PSK_KEY_RAW);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("psk-key-format/raw", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_psk_key_format_enum, (scm_t_bits) GNUTLS_PSK_KEY_HEX);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("psk-key-format/hex", enum_smob);
  scm_gnutls_psk_key_format_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_key_usage_enum, (scm_t_bits) GNUTLS_KEY_DIGITAL_SIGNATURE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("key-usage/digital-signature", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_key_usage_enum, (scm_t_bits) GNUTLS_KEY_NON_REPUDIATION);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("key-usage/non-repudiation", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_key_usage_enum, (scm_t_bits) GNUTLS_KEY_KEY_ENCIPHERMENT);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("key-usage/key-encipherment", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_key_usage_enum, (scm_t_bits) GNUTLS_KEY_DATA_ENCIPHERMENT);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("key-usage/data-encipherment", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_key_usage_enum, (scm_t_bits) GNUTLS_KEY_KEY_AGREEMENT);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("key-usage/key-agreement", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_key_usage_enum, (scm_t_bits) GNUTLS_KEY_KEY_CERT_SIGN);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("key-usage/key-cert-sign", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_key_usage_enum, (scm_t_bits) GNUTLS_KEY_CRL_SIGN);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("key-usage/crl-sign", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_key_usage_enum, (scm_t_bits) GNUTLS_KEY_ENCIPHER_ONLY);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("key-usage/encipher-only", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_key_usage_enum, (scm_t_bits) GNUTLS_KEY_DECIPHER_ONLY);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("key-usage/decipher-only", enum_smob);
  scm_gnutls_key_usage_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_certificate_verify_enum, (scm_t_bits) GNUTLS_VERIFY_DISABLE_CA_SIGN);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("certificate-verify/disable-ca-sign", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_certificate_verify_enum, (scm_t_bits) GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("certificate-verify/allow-x509-v1-ca-crt", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_certificate_verify_enum, (scm_t_bits) GNUTLS_VERIFY_DO_NOT_ALLOW_SAME);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("certificate-verify/do-not-allow-same", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_certificate_verify_enum, (scm_t_bits) GNUTLS_VERIFY_ALLOW_ANY_X509_V1_CA_CRT);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("certificate-verify/allow-any-x509-v1-ca-crt", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_certificate_verify_enum, (scm_t_bits) GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("certificate-verify/allow-sign-rsa-md2", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_certificate_verify_enum, (scm_t_bits) GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("certificate-verify/allow-sign-rsa-md5", enum_smob);
  scm_gnutls_certificate_verify_enum_values = scm_permanent_object (enum_values);
  enum_values = SCM_EOL;
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_SUCCESS);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/success", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/unknown-compression-algorithm", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_UNKNOWN_CIPHER_TYPE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/unknown-cipher-type", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_LARGE_PACKET);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/large-packet", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_UNSUPPORTED_VERSION_PACKET);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/unsupported-version-packet", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/unexpected-packet-length", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_INVALID_SESSION);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/invalid-session", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_FATAL_ALERT_RECEIVED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/fatal-alert-received", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_UNEXPECTED_PACKET);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/unexpected-packet", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_WARNING_ALERT_RECEIVED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/warning-alert-received", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_ERROR_IN_FINISHED_PACKET);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/error-in-finished-packet", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/unexpected-handshake-packet", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_UNKNOWN_CIPHER_SUITE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/unknown-cipher-suite", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_UNWANTED_ALGORITHM);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/unwanted-algorithm", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_MPI_SCAN_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/mpi-scan-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_DECRYPTION_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/decryption-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_MEMORY_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/memory-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_DECOMPRESSION_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/decompression-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_COMPRESSION_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/compression-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_AGAIN);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/again", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_EXPIRED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/expired", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_DB_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/db-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_SRP_PWD_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/srp-pwd-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_INSUFFICIENT_CREDENTIALS);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/insufficient-credentials", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_INSUFICIENT_CREDENTIALS);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/insuficient-credentials", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_INSUFFICIENT_CRED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/insufficient-cred", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_INSUFICIENT_CRED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/insuficient-cred", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_HASH_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/hash-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_BASE64_DECODING_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/base64-decoding-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_MPI_PRINT_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/mpi-print-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_REHANDSHAKE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/rehandshake", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_GOT_APPLICATION_DATA);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/got-application-data", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_RECORD_LIMIT_REACHED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/record-limit-reached", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_ENCRYPTION_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/encryption-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_PK_ENCRYPTION_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/pk-encryption-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_PK_DECRYPTION_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/pk-decryption-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_PK_SIGN_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/pk-sign-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_X509_UNSUPPORTED_CRITICAL_EXTENSION);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/x509-unsupported-critical-extension", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_KEY_USAGE_VIOLATION);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/key-usage-violation", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_NO_CERTIFICATE_FOUND);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/no-certificate-found", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_INVALID_REQUEST);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/invalid-request", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_SHORT_MEMORY_BUFFER);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/short-memory-buffer", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_INTERRUPTED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/interrupted", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_PUSH_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/push-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_PULL_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/pull-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/received-illegal-parameter", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/requested-data-not-available", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_PKCS1_WRONG_PAD);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/pkcs1-wrong-pad", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/received-illegal-extension", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_INTERNAL_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/internal-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_DH_PRIME_UNACCEPTABLE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/dh-prime-unacceptable", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_FILE_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/file-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_TOO_MANY_EMPTY_PACKETS);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/too-many-empty-packets", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_UNKNOWN_PK_ALGORITHM);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/unknown-pk-algorithm", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_INIT_LIBEXTRA);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/init-libextra", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_LIBRARY_VERSION_MISMATCH);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/library-version-mismatch", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_NO_TEMPORARY_RSA_PARAMS);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/no-temporary-rsa-params", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_LZO_INIT_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/lzo-init-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_NO_COMPRESSION_ALGORITHMS);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/no-compression-algorithms", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_NO_CIPHER_SUITES);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/no-cipher-suites", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_OPENPGP_GETKEY_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/openpgp-getkey-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_PK_SIG_VERIFY_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/pk-sig-verify-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_ILLEGAL_SRP_USERNAME);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/illegal-srp-username", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_SRP_PWD_PARSING_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/srp-pwd-parsing-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_NO_TEMPORARY_DH_PARAMS);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/no-temporary-dh-params", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_ASN1_ELEMENT_NOT_FOUND);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/asn1-element-not-found", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_ASN1_IDENTIFIER_NOT_FOUND);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/asn1-identifier-not-found", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_ASN1_DER_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/asn1-der-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_ASN1_VALUE_NOT_FOUND);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/asn1-value-not-found", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_ASN1_GENERIC_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/asn1-generic-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_ASN1_VALUE_NOT_VALID);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/asn1-value-not-valid", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_ASN1_TAG_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/asn1-tag-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_ASN1_TAG_IMPLICIT);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/asn1-tag-implicit", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_ASN1_TYPE_ANY_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/asn1-type-any-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_ASN1_SYNTAX_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/asn1-syntax-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_ASN1_DER_OVERFLOW);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/asn1-der-overflow", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_OPENPGP_UID_REVOKED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/openpgp-uid-revoked", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_CERTIFICATE_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/certificate-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_X509_CERTIFICATE_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/x509-certificate-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_CERTIFICATE_KEY_MISMATCH);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/certificate-key-mismatch", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/unsupported-certificate-type", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_X509_UNKNOWN_SAN);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/x509-unknown-san", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_OPENPGP_FINGERPRINT_UNSUPPORTED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/openpgp-fingerprint-unsupported", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_X509_UNSUPPORTED_ATTRIBUTE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/x509-unsupported-attribute", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_UNKNOWN_ALGORITHM);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/unknown-algorithm", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/unknown-hash-algorithm", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_UNKNOWN_PKCS_CONTENT_TYPE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/unknown-pkcs-content-type", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_UNKNOWN_PKCS_BAG_TYPE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/unknown-pkcs-bag-type", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_INVALID_PASSWORD);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/invalid-password", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_MAC_VERIFY_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/mac-verify-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_CONSTRAINT_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/constraint-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_WARNING_IA_IPHF_RECEIVED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/warning-ia-iphf-received", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_WARNING_IA_FPHF_RECEIVED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/warning-ia-fphf-received", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_IA_VERIFY_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/ia-verify-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_BASE64_ENCODING_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/base64-encoding-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_INCOMPATIBLE_GCRYPT_LIBRARY);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/incompatible-gcrypt-library", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_INCOMPATIBLE_CRYPTO_LIBRARY);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/incompatible-crypto-library", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_INCOMPATIBLE_LIBTASN1_LIBRARY);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/incompatible-libtasn1-library", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_OPENPGP_KEYRING_ERROR);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/openpgp-keyring-error", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_X509_UNSUPPORTED_OID);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/x509-unsupported-oid", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_RANDOM_FAILED);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/random-failed", enum_smob);
  SCM_NEWSMOB (enum_smob, scm_tc16_gnutls_error_enum, (scm_t_bits) GNUTLS_E_UNIMPLEMENTED_FEATURE);
  enum_values = scm_cons (enum_smob, enum_values);
  scm_c_define ("error/unimplemented-feature", enum_smob);
  scm_gnutls_error_enum_values = scm_permanent_object (enum_values);
}

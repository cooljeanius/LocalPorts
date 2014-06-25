SCM_DEFINE (scm_gnutls_set_session_cipher_priority_x,
            "set-session-cipher-priority!", 2, 0, 0,
            (SCM session, SCM items),
            "Use @var{items} (a list) as the list of "
            "preferred cipher for @var{session}.")
#define FUNC_NAME s_scm_gnutls_set_session_cipher_priority_x
{
  gnutls_session_t c_session;
  gnutls_cipher_algorithm_t *c_items;
  long int c_len, i;
  c_session = scm_to_gnutls_session (session, 1, FUNC_NAME);
  SCM_VALIDATE_LIST_COPYLEN (2, items, c_len);
  c_items = (gnutls_cipher_algorithm_t *) alloca (sizeof (* c_items) * c_len);
  for (i = 0; i < c_len; i++, items = SCM_CDR (items))
    c_items[i] = scm_to_gnutls_cipher (SCM_CAR (items), 2, FUNC_NAME);
  c_items[c_len] = (gnutls_cipher_algorithm_t) 0;
  gnutls_cipher_set_priority (c_session, (int *) c_items);
  return SCM_UNSPECIFIED;
}
#undef FUNC_NAME
SCM_DEFINE (scm_gnutls_set_session_mac_priority_x,
            "set-session-mac-priority!", 2, 0, 0,
            (SCM session, SCM items),
            "Use @var{items} (a list) as the list of "
            "preferred mac for @var{session}.")
#define FUNC_NAME s_scm_gnutls_set_session_mac_priority_x
{
  gnutls_session_t c_session;
  gnutls_mac_algorithm_t *c_items;
  long int c_len, i;
  c_session = scm_to_gnutls_session (session, 1, FUNC_NAME);
  SCM_VALIDATE_LIST_COPYLEN (2, items, c_len);
  c_items = (gnutls_mac_algorithm_t *) alloca (sizeof (* c_items) * c_len);
  for (i = 0; i < c_len; i++, items = SCM_CDR (items))
    c_items[i] = scm_to_gnutls_mac (SCM_CAR (items), 2, FUNC_NAME);
  c_items[c_len] = (gnutls_mac_algorithm_t) 0;
  gnutls_mac_set_priority (c_session, (int *) c_items);
  return SCM_UNSPECIFIED;
}
#undef FUNC_NAME
SCM_DEFINE (scm_gnutls_set_session_compression_method_priority_x,
            "set-session-compression-method-priority!", 2, 0, 0,
            (SCM session, SCM items),
            "Use @var{items} (a list) as the list of "
            "preferred compression-method for @var{session}.")
#define FUNC_NAME s_scm_gnutls_set_session_compression_method_priority_x
{
  gnutls_session_t c_session;
  gnutls_compression_method_t *c_items;
  long int c_len, i;
  c_session = scm_to_gnutls_session (session, 1, FUNC_NAME);
  SCM_VALIDATE_LIST_COPYLEN (2, items, c_len);
  c_items = (gnutls_compression_method_t *) alloca (sizeof (* c_items) * c_len);
  for (i = 0; i < c_len; i++, items = SCM_CDR (items))
    c_items[i] = scm_to_gnutls_compression_method (SCM_CAR (items), 2, FUNC_NAME);
  c_items[c_len] = (gnutls_compression_method_t) 0;
  gnutls_compression_set_priority (c_session, (int *) c_items);
  return SCM_UNSPECIFIED;
}
#undef FUNC_NAME
SCM_DEFINE (scm_gnutls_set_session_kx_priority_x,
            "set-session-kx-priority!", 2, 0, 0,
            (SCM session, SCM items),
            "Use @var{items} (a list) as the list of "
            "preferred kx for @var{session}.")
#define FUNC_NAME s_scm_gnutls_set_session_kx_priority_x
{
  gnutls_session_t c_session;
  gnutls_kx_algorithm_t *c_items;
  long int c_len, i;
  c_session = scm_to_gnutls_session (session, 1, FUNC_NAME);
  SCM_VALIDATE_LIST_COPYLEN (2, items, c_len);
  c_items = (gnutls_kx_algorithm_t *) alloca (sizeof (* c_items) * c_len);
  for (i = 0; i < c_len; i++, items = SCM_CDR (items))
    c_items[i] = scm_to_gnutls_kx (SCM_CAR (items), 2, FUNC_NAME);
  c_items[c_len] = (gnutls_kx_algorithm_t) 0;
  gnutls_kx_set_priority (c_session, (int *) c_items);
  return SCM_UNSPECIFIED;
}
#undef FUNC_NAME
SCM_DEFINE (scm_gnutls_set_session_protocol_priority_x,
            "set-session-protocol-priority!", 2, 0, 0,
            (SCM session, SCM items),
            "Use @var{items} (a list) as the list of "
            "preferred protocol for @var{session}.")
#define FUNC_NAME s_scm_gnutls_set_session_protocol_priority_x
{
  gnutls_session_t c_session;
  gnutls_protocol_t *c_items;
  long int c_len, i;
  c_session = scm_to_gnutls_session (session, 1, FUNC_NAME);
  SCM_VALIDATE_LIST_COPYLEN (2, items, c_len);
  c_items = (gnutls_protocol_t *) alloca (sizeof (* c_items) * c_len);
  for (i = 0; i < c_len; i++, items = SCM_CDR (items))
    c_items[i] = scm_to_gnutls_protocol (SCM_CAR (items), 2, FUNC_NAME);
  c_items[c_len] = (gnutls_protocol_t) 0;
  gnutls_protocol_set_priority (c_session, (int *) c_items);
  return SCM_UNSPECIFIED;
}
#undef FUNC_NAME
SCM_DEFINE (scm_gnutls_set_session_certificate_type_priority_x,
            "set-session-certificate-type-priority!", 2, 0, 0,
            (SCM session, SCM items),
            "Use @var{items} (a list) as the list of "
            "preferred certificate-type for @var{session}.")
#define FUNC_NAME s_scm_gnutls_set_session_certificate_type_priority_x
{
  gnutls_session_t c_session;
  gnutls_certificate_type_t *c_items;
  long int c_len, i;
  c_session = scm_to_gnutls_session (session, 1, FUNC_NAME);
  SCM_VALIDATE_LIST_COPYLEN (2, items, c_len);
  c_items = (gnutls_certificate_type_t *) alloca (sizeof (* c_items) * c_len);
  for (i = 0; i < c_len; i++, items = SCM_CDR (items))
    c_items[i] = scm_to_gnutls_certificate_type (SCM_CAR (items), 2, FUNC_NAME);
  c_items[c_len] = (gnutls_certificate_type_t) 0;
  gnutls_certificate_type_set_priority (c_session, (int *) c_items);
  return SCM_UNSPECIFIED;
}
#undef FUNC_NAME

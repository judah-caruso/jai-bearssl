BR_SSL30 :: 0x0300;
BR_TLS10 :: 0x0301;
BR_TLS11 :: 0x0302;
BR_TLS12 :: 0x0303;

BR_SSL_BUFSIZE_INPUT  :: 16384 + 325;
BR_SSL_BUFSIZE_OUTPUT :: 16384 + 85;
BR_SSL_BUFSIZE_MONO   :: BR_SSL_BUFSIZE_INPUT;
BR_SSL_BUFSIZE_BIDI   :: BR_SSL_BUFSIZE_INPUT + BR_SSL_BUFSIZE_OUTPUT;

BR_MAX_CIPHER_SUITES :: 48;

BR_AUTH_ECDH  :: 0;
BR_AUTH_RSA   :: 1;
BR_AUTH_ECDSA :: 3;

BR_SSL_CLOSED         :: 0x0001;
BR_SSL_SENDREC        :: 0x0002;
BR_SSL_RECVREC        :: 0x0004;
BR_SSL_SENDAPP        :: 0x0008;
BR_SSL_RECVAPP        :: 0x0010;

BR_ERR_OK                  :: 0;
BR_ERR_BAD_PARAM           :: 1;
BR_ERR_BAD_STATE           :: 2;
BR_ERR_UNSUPPORTED_VERSION :: 3;
BR_ERR_BAD_VERSION         :: 4;
BR_ERR_BAD_LENGTH          :: 5;
BR_ERR_TOO_LARGE           :: 6;
BR_ERR_BAD_MAC             :: 7;
BR_ERR_NO_RANDOM           :: 8;
BR_ERR_UNKNOWN_TYPE        :: 9;
BR_ERR_UNEXPECTED          :: 10;
BR_ERR_BAD_CCS             :: 12;
BR_ERR_BAD_ALERT           :: 13;
BR_ERR_BAD_HANDSHAKE       :: 14;
BR_ERR_OVERSIZED_ID        :: 15;
BR_ERR_BAD_CIPHER_SUITE    :: 16;
BR_ERR_BAD_COMPRESSION     :: 17;
BR_ERR_BAD_FRAGLEN         :: 18;
BR_ERR_BAD_SECRENEG        :: 19;
BR_ERR_EXTRA_EXTENSION     :: 20;
BR_ERR_BAD_SNI             :: 21;
BR_ERR_BAD_HELLO_DONE      :: 22;
BR_ERR_LIMIT_EXCEEDED      :: 23;
BR_ERR_BAD_FINISHED        :: 24;
BR_ERR_RESUME_MISMATCH     :: 25;
BR_ERR_INVALID_ALGORITHM   :: 26;
BR_ERR_BAD_SIGNATURE       :: 27;
BR_ERR_WRONG_KEY_USAGE     :: 28;
BR_ERR_NO_CLIENT_AUTH      :: 29;
BR_ERR_IO                  :: 31;
BR_ERR_RECV_FATAL_ALERT    :: 256;
BR_ERR_SEND_FATAL_ALERT    :: 51;

BR_OPT_ENFORCE_SERVER_PREFERENCES : u32 : 1 << 0;
BR_OPT_NO_RENEGOTIATION           : u32 : 1 << 1;
BR_OPT_TOLERATE_NO_CLIENT_AUTH    : u32 : 1 << 2;
BR_OPT_FAIL_ON_ALPN_MISMATCH      : u32 : 1 << 3;

BR_SSLKEYX_RSA         :: 0;
BR_SSLKEYX_ECDHE_RSA   :: 1;
BR_SSLKEYX_ECDHE_ECDSA :: 2;
BR_SSLKEYX_ECDH_RSA    :: 3;
BR_SSLKEYX_ECDH_ECDSA  :: 4;
BR_SSLENC_3DES_CBC     :: 0;
BR_SSLENC_AES128_CBC   :: 1;
BR_SSLENC_AES256_CBC   :: 2;
BR_SSLENC_AES128_GCM   :: 3;
BR_SSLENC_AES256_GCM   :: 4;
BR_SSLENC_CHACHA20     :: 5;
BR_SSLMAC_AEAD         :: 0;
BR_SSLMAC_SHA1         :: br_sha1_ID;
BR_SSLMAC_SHA256       :: br_sha256_ID;
BR_SSLMAC_SHA384       :: br_sha384_ID;
BR_SSLPRF_SHA256       :: br_sha256_ID;
BR_SSLPRF_SHA384       :: br_sha384_ID;

BR_TLS_NULL_WITH_NULL_NULL             :: 0x0000;
BR_TLS_RSA_WITH_NULL_MD5               :: 0x0001;
BR_TLS_RSA_WITH_NULL_SHA               :: 0x0002;
BR_TLS_RSA_WITH_NULL_SHA256            :: 0x003B;
BR_TLS_RSA_WITH_RC4_128_MD5            :: 0x0004;
BR_TLS_RSA_WITH_RC4_128_SHA            :: 0x0005;
BR_TLS_RSA_WITH_3DES_EDE_CBC_SHA       :: 0x000A;
BR_TLS_RSA_WITH_AES_128_CBC_SHA        :: 0x002F;
BR_TLS_RSA_WITH_AES_256_CBC_SHA        :: 0x0035;
BR_TLS_RSA_WITH_AES_128_CBC_SHA256     :: 0x003C;
BR_TLS_RSA_WITH_AES_256_CBC_SHA256     :: 0x003D;
BR_TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA    :: 0x000D;
BR_TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA    :: 0x0010;
BR_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA   :: 0x0013;
BR_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA   :: 0x0016;
BR_TLS_DH_DSS_WITH_AES_128_CBC_SHA     :: 0x0030;
BR_TLS_DH_RSA_WITH_AES_128_CBC_SHA     :: 0x0031;
BR_TLS_DHE_DSS_WITH_AES_128_CBC_SHA    :: 0x0032;
BR_TLS_DHE_RSA_WITH_AES_128_CBC_SHA    :: 0x0033;
BR_TLS_DH_DSS_WITH_AES_256_CBC_SHA     :: 0x0036;
BR_TLS_DH_RSA_WITH_AES_256_CBC_SHA     :: 0x0037;
BR_TLS_DHE_DSS_WITH_AES_256_CBC_SHA    :: 0x0038;
BR_TLS_DHE_RSA_WITH_AES_256_CBC_SHA    :: 0x0039;
BR_TLS_DH_DSS_WITH_AES_128_CBC_SHA256  :: 0x003E;
BR_TLS_DH_RSA_WITH_AES_128_CBC_SHA256  :: 0x003F;
BR_TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 :: 0x0040;
BR_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 :: 0x0067;
BR_TLS_DH_DSS_WITH_AES_256_CBC_SHA256  :: 0x0068;
BR_TLS_DH_RSA_WITH_AES_256_CBC_SHA256  :: 0x0069;
BR_TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 :: 0x006A;
BR_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 :: 0x006B;
BR_TLS_DH_anon_WITH_RC4_128_MD5        :: 0x0018;
BR_TLS_DH_anon_WITH_3DES_EDE_CBC_SHA   :: 0x001B;
BR_TLS_DH_anon_WITH_AES_128_CBC_SHA    :: 0x0034;
BR_TLS_DH_anon_WITH_AES_256_CBC_SHA    :: 0x003A;
BR_TLS_DH_anon_WITH_AES_128_CBC_SHA256 :: 0x006C;
BR_TLS_DH_anon_WITH_AES_256_CBC_SHA256 :: 0x006D;

BR_TLS_ECDH_ECDSA_WITH_NULL_SHA          :: 0xC001;
BR_TLS_ECDH_ECDSA_WITH_RC4_128_SHA       :: 0xC002;
BR_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA  :: 0xC003;
BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA   :: 0xC004;
BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA   :: 0xC005;
BR_TLS_ECDHE_ECDSA_WITH_NULL_SHA         :: 0xC006;
BR_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA      :: 0xC007;
BR_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA :: 0xC008;
BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA  :: 0xC009;
BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA  :: 0xC00A;
BR_TLS_ECDH_RSA_WITH_NULL_SHA            :: 0xC00B;
BR_TLS_ECDH_RSA_WITH_RC4_128_SHA         :: 0xC00C;
BR_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA    :: 0xC00D;
BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA     :: 0xC00E;
BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA     :: 0xC00F;
BR_TLS_ECDHE_RSA_WITH_NULL_SHA           :: 0xC010;
BR_TLS_ECDHE_RSA_WITH_RC4_128_SHA        :: 0xC011;
BR_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA   :: 0xC012;
BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA    :: 0xC013;
BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA    :: 0xC014;
BR_TLS_ECDH_anon_WITH_NULL_SHA           :: 0xC015;
BR_TLS_ECDH_anon_WITH_RC4_128_SHA        :: 0xC016;
BR_TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA   :: 0xC017;
BR_TLS_ECDH_anon_WITH_AES_128_CBC_SHA    :: 0xC018;
BR_TLS_ECDH_anon_WITH_AES_256_CBC_SHA    :: 0xC019;

BR_TLS_RSA_WITH_AES_128_GCM_SHA256     :: 0x009C;
BR_TLS_RSA_WITH_AES_256_GCM_SHA384     :: 0x009D;
BR_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 :: 0x009E;
BR_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 :: 0x009F;
BR_TLS_DH_RSA_WITH_AES_128_GCM_SHA256  :: 0x00A0;
BR_TLS_DH_RSA_WITH_AES_256_GCM_SHA384  :: 0x00A1;
BR_TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 :: 0x00A2;
BR_TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 :: 0x00A3;
BR_TLS_DH_DSS_WITH_AES_128_GCM_SHA256  :: 0x00A4;
BR_TLS_DH_DSS_WITH_AES_256_GCM_SHA384  :: 0x00A5;
BR_TLS_DH_anon_WITH_AES_128_GCM_SHA256 :: 0x00A6;
BR_TLS_DH_anon_WITH_AES_256_GCM_SHA384 :: 0x00A7;

BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 :: 0xC023;
BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 :: 0xC024;
BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256  :: 0xC025;
BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384  :: 0xC026;
BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   :: 0xC027;
BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   :: 0xC028;
BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256    :: 0xC029;
BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384    :: 0xC02A;
BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 :: 0xC02B;
BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 :: 0xC02C;
BR_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256  :: 0xC02D;
BR_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384  :: 0xC02E;
BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   :: 0xC02F;
BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   :: 0xC030;
BR_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256    :: 0xC031;
BR_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384    :: 0xC032;

BR_TLS_RSA_WITH_AES_128_CCM           :: 0xC09C;
BR_TLS_RSA_WITH_AES_256_CCM           :: 0xC09D;
BR_TLS_RSA_WITH_AES_128_CCM_8         :: 0xC0A0;
BR_TLS_RSA_WITH_AES_256_CCM_8         :: 0xC0A1;
BR_TLS_ECDHE_ECDSA_WITH_AES_128_CCM   :: 0xC0AC;
BR_TLS_ECDHE_ECDSA_WITH_AES_256_CCM   :: 0xC0AD;
BR_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 :: 0xC0AE;
BR_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 :: 0xC0AF;

BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   :: 0xCCA8;
BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 :: 0xCCA9;
BR_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     :: 0xCCAA;
BR_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256         :: 0xCCAB;
BR_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256   :: 0xCCAC;
BR_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256     :: 0xCCAD;
BR_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256     :: 0xCCAE;

BR_TLS_FALLBACK_SCSV :: 0x5600;

BR_ALERT_CLOSE_NOTIFY            :: 0;
BR_ALERT_UNEXPECTED_MESSAGE      :: 10;
BR_ALERT_BAD_RECORD_MAC          :: 20;
BR_ALERT_RECORD_OVERFLOW         :: 22;
BR_ALERT_DECOMPRESSION_FAILURE   :: 30;
BR_ALERT_HANDSHAKE_FAILURE       :: 40;
BR_ALERT_BAD_CERTIFICATE         :: 42;
BR_ALERT_UNSUPPORTED_CERTIFICATE :: 43;
BR_ALERT_CERTIFICATE_REVOKED     :: 44;
BR_ALERT_CERTIFICATE_EXPIRED     :: 45;
BR_ALERT_CERTIFICATE_UNKNOWN     :: 46;
BR_ALERT_ILLEGAL_PARAMETER       :: 47;
BR_ALERT_UNKNOWN_CA              :: 48;
BR_ALERT_ACCESS_DENIED           :: 49;
BR_ALERT_DECODE_ERROR            :: 50;
BR_ALERT_DECRYPT_ERROR           :: 51;
BR_ALERT_PROTOCOL_VERSION        :: 70;
BR_ALERT_INSUFFICIENT_SECURITY   :: 71;
BR_ALERT_INTERNAL_ERROR          :: 80;
BR_ALERT_USER_CANCELED           :: 90;
BR_ALERT_NO_RENEGOTIATION        :: 100;
BR_ALERT_UNSUPPORTED_EXTENSION   :: 110;
BR_ALERT_NO_APPLICATION_PROTOCOL :: 120;

br_ssl_session_parameters :: struct {
    session_id     : [32]c.unsigned_char;
    session_id_len : c.unsigned_char;
    version        : u16;
    cipher_suite   : u16;
    master_secret  : [48]c.unsigned_char;
}

br_ssl_engine_context :: struct {
    err                   : c.int;
    ibuf                  : *c.unsigned_char;
    obuf                  : *c.unsigned_char;
    ibuf_len              : c.size_t;
    obuf_len              : c.size_t;
    max_frag_len          : u16;
    log_max_frag_len      : c.unsigned_char;
    peer_log_max_frag_len : c.unsigned_char;
    ixa                   : c.size_t;
    ixb                   : c.size_t;
    ixc                   : c.size_t;
    oxa                   : c.size_t;
    oxb                   : c.size_t;
    oxc                   : c.size_t;
    iomode                : c.unsigned_char;
    incrypt               : c.unsigned_char;
    shutdown_recv         : c.unsigned_char;
    record_type_in        : c.unsigned_char;
    record_type_out       : c.unsigned_char;
    version_in            : u16;
    version_out           : u16;

    in: union {
        vtable : *br_sslrec_in_class;
        cbc    : br_sslrec_in_cbc_context;
        gcm    : br_sslrec_gcm_context;
        chapol : br_sslrec_chapol_context;
        ccm    : br_sslrec_ccm_context;
    };

    out: union {
        vtable : *br_sslrec_out_class;
        clear  : br_sslrec_out_clear_context;
        cbc    : br_sslrec_out_cbc_context;
        gcm    : br_sslrec_gcm_context;
        chapol : br_sslrec_chapol_context;
        ccm    : br_sslrec_ccm_context;
    };

    application_data : c.unsigned_char;
    rng              : br_hmac_drbg_context;
    rng_init_done    : c.int;
    rng_os_rand_done : c.int;
    version_min      : u16;
    version_max      : u16;
    suites_buf       : [BR_MAX_CIPHER_SUITES]u16;
    suites_num       : c.unsigned_char;
    server_name      : [256]c.char;
    client_random    : [32]c.unsigned_char;
    server_random    : [32]c.unsigned_char;
    session          : br_ssl_session_parameters;
    ecdhe_curve      : c.unsigned_char;
    ecdhe_point      : [133]c.unsigned_char;
    ecdhe_point_len  : c.unsigned_char;
    reneg            : c.unsigned_char;
    saved_finished   : [24]c.unsigned_char;
    flags            : u32;

    cpu: struct {
        dp : *u32;
        rp : *u32;
        ip : *c.unsigned_char;
    };

    dp_stack           : [32]u32;
    rp_stack           : [32]u32;
    pad                : [512]c.unsigned_char;
    hbuf_in            : *c.unsigned_char;
    hbuf_out           : *c.unsigned_char;
    saved_hbuf_out     : *c.unsigned_char;
    hlen_in            : c.size_t;
    hlen_out           : c.size_t;
    hsrun              : (ctx: *void) #c_call;
    action             : c.unsigned_char;
    alert              : c.unsigned_char;
    close_received     : c.unsigned_char;
    mhash              : br_multihash_context;
    x509ctx            : **br_x509_class;
    chain              : *br_x509_certificate;
    chain_len          : c.size_t;
    cert_cur           : *c.unsigned_char;
    cert_len           : c.size_t;
    protocol_names     : **c.char;
    protocol_names_num : u16;
    selected_protocol  : u16;
    prf10              : br_tls_prf_impl;
    prf_sha256         : br_tls_prf_impl;
    prf_sha384         : br_tls_prf_impl;
    iaes_cbcenc        : *br_block_cbcenc_class;
    iaes_cbcdec        : *br_block_cbcdec_class;
    iaes_ctr           : *br_block_ctr_class;
    iaes_ctrcbc        : *br_block_ctrcbc_class;
    ides_cbcenc        : *br_block_cbcenc_class;
    ides_cbcdec        : *br_block_cbcdec_class;
    ighash             : br_ghash;
    ichacha            : br_chacha20_run;
    ipoly              : br_poly1305_run;
    icbc_in            : *br_sslrec_in_cbc_class;
    icbc_out           : *br_sslrec_out_cbc_class;
    igcm_in            : *br_sslrec_in_gcm_class;
    igcm_out           : *br_sslrec_out_gcm_class;
    ichapol_in         : *br_sslrec_in_chapol_class;
    ichapol_out        : *br_sslrec_out_chapol_class;
    iccm_in            : *br_sslrec_in_ccm_class;
    iccm_out           : *br_sslrec_out_ccm_class;
    iec                : *br_ec_impl;
    irsavrfy           : br_rsa_pkcs1_vrfy;
    iecdsa             : br_ecdsa_vrfy;
}

br_ssl_client_certificate_class :: struct {
    context_size: c.size_t;

    start_name_list : (pctx: **br_ssl_client_certificate_class) #c_call;
    start_name      : (pctx: **br_ssl_client_certificate_class, len: c.size_t) #c_call;
    append_name     : (pctx: **br_ssl_client_certificate_class, data: *c.unsigned_char, len: c.size_t) #c_call;
    end_name        : (pctx: **br_ssl_client_certificate_class) #c_call;
    end_name_list   : (pctx: **br_ssl_client_certificate_class) #c_call;
    choose          : (pctx: **br_ssl_client_certificate_class, cc: *br_ssl_client_context, auth_types: u32, choices: *br_ssl_client_certificate) #c_call;
    do_keyx         : (pctx: **br_ssl_client_certificate_class, data: *c.unsigned_char, len: *c.size_t) -> u32 #c_call;
    do_sign         : (pctx: **br_ssl_client_certificate_class, hash_id: c.int, hv_len: c.size_t, data: *c.unsigned_char, len: c.size_t) -> c.size_t #c_call;
}

br_ssl_client_certificate_ec_context :: struct {
    vtable          : *br_ssl_client_certificate_class;
    chain           : *br_x509_certificate;
    chain_len       : c.size_t;
    sk              : *br_ec_private_key;
    allowed_usages  : c.unsigned;
    issuer_key_type : c.unsigned;
    mhash           : *br_multihash_context;
    iec             : *br_ec_impl;
    iecdsa          : br_ecdsa_sign;
}

br_ssl_client_context :: struct {
    eng                 : br_ssl_engine_context;
    min_clienthello_len : u16;
    hashes              : u32;
    server_curve        : c.int;
    client_auth_vtable  : **br_ssl_client_certificate_class;
    auth_type           : c.unsigned_char;
    hash_id             : c.unsigned_char;

    client_auth: union {
        vtable: *br_ssl_client_certificate_class;
        single_rsa : br_ssl_client_certificate_rsa_context;
        single_ec  : br_ssl_client_certificate_ec_context;
    };

    irsapub: br_rsa_public;
}

br_ssl_client_certificate :: struct {
    auth_type : c.int;
    hash_id   : c.int;
    chain     : *br_x509_certificate;
    chain_len : c.size_t;
}

br_ssl_client_certificate_rsa_context :: struct {
    vtable    : *br_ssl_client_certificate_class;
    chain     : *br_x509_certificate;
    chain_len : c.size_t;
    sk        : *br_rsa_private_key;
    irsasign  : br_rsa_pkcs1_sign;
}

br_ssl_engine_current_state      :: (cc: *br_ssl_engine_context) -> c.unsigned                                                                                                                                                                    #foreign BearSSL;
br_ssl_client_init_full          :: (cc: *br_ssl_client_context, xc: *br_x509_minimal_context, trust_anchors: *br_x509_trust_anchor, trust_anchors_num: c.size_t)                                                                                 #foreign BearSSL;
br_ssl_client_zero               :: (cc: *br_ssl_client_context)                                                                                                                                                                                  #foreign BearSSL;
br_ssl_client_set_default_rsapub :: (cc: *br_ssl_client_context)                                                                                                                                                                                  #foreign BearSSL;
br_ssl_engine_set_buffer         :: (cc: *br_ssl_engine_context, iobuf: *void, iobuf_len: c.size_t, bidi: c.int)                                                                                                                                  #foreign BearSSL;
br_ssl_client_reset              :: (cc: *br_ssl_client_context, server_name: *c.char, resume_session: c.int) -> c.int                                                                                                                            #foreign BearSSL;
br_ssl_client_set_single_rsa     :: (cc: *br_ssl_client_context, chain: *br_x509_certificate, chain_len: c.size_t, sk: *br_rsa_private_key, irsasign: br_rsa_pkcs1_sign)                                                                          #foreign BearSSL;
br_ssl_client_set_single_ec      :: (cc: *br_ssl_client_context, chain: *br_x509_certificate, chain_len: c.size_t, sk: *br_ec_private_key, allowed_usages: c.unsigned, cert_issuer_key_type: c.unsigned, iec: *br_ec_impl, iecdsa: br_ecdsa_sign) #foreign BearSSL;
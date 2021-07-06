BR_KEYTYPE_RSA      :: 1;
BR_KEYTYPE_EC       :: 2;
BR_KEYTYPE_KEYX     :: 0x10;
BR_KEYTYPE_SIGN     :: 0x20;

BR_X509_BUFSIZE_KEY :: 520;
BR_X509_BUFSIZE_SIG :: 512;
BR_X509_TA_CA       :: 0x0001;

BR_ERR_X509_OK                  :: 32;
BR_ERR_X509_INVALID_VALUE       :: 33;
BR_ERR_X509_TRUNCATED           :: 34;
BR_ERR_X509_EMPTY_CHAIN         :: 35;
BR_ERR_X509_INNER_TRUNC         :: 36;
BR_ERR_X509_BAD_TAG_CLASS       :: 37;
BR_ERR_X509_BAD_TAG_VALUE       :: 38;
BR_ERR_X509_INDEFINITE_LENGTH   :: 39;
BR_ERR_X509_EXTRA_ELEMENT       :: 40;
BR_ERR_X509_UNEXPECTED          :: 41;
BR_ERR_X509_NOT_CONSTRUCTED     :: 42;
BR_ERR_X509_NOT_PRIMITIVE       :: 43;
BR_ERR_X509_PARTIAL_BYTE        :: 44;
BR_ERR_X509_BAD_BOOLEAN         :: 45;
BR_ERR_X509_OVERFLOW            :: 46;
BR_ERR_X509_BAD_DN              :: 47;
BR_ERR_X509_BAD_TIME            :: 48;
BR_ERR_X509_UNSUPPORTED         :: 49;
BR_ERR_X509_LIMIT_EXCEEDED      :: 50;
BR_ERR_X509_WRONG_KEY_TYPE      :: 51;
BR_ERR_X509_BAD_SIGNATURE       :: 52;
BR_ERR_X509_TIME_UNKNOWN        :: 53;
BR_ERR_X509_EXPIRED             :: 54;
BR_ERR_X509_DN_MISMATCH         :: 55;
BR_ERR_X509_BAD_SERVER_NAME     :: 56;
BR_ERR_X509_CRITICAL_EXTENSION  :: 57;
BR_ERR_X509_NOT_CA              :: 58;
BR_ERR_X509_FORBIDDEN_KEY_USAGE :: 59;
BR_ERR_X509_WEAK_PUBLIC_KEY     :: 60;
BR_ERR_X509_NOT_TRUSTED         :: 62;

BR_ENCODE_PEM_RSA_RAW :: "RSA PRIVATE KEY";
BR_ENCODE_PEM_EC_RAW  :: "EC PRIVATE KEY";
BR_ENCODE_PEM_PKCS8   :: "PRIVATE KEY";

br_x509_class :: struct {
    context_size: c.size_t;

    start_chain : (ctx: **br_x509_class, server_name: *c.char) #c_call;
    start_cert  : (ctx: **br_x509_class, length: u32) #c_call;
    append      : (ctx: **br_x509_class, buf: *c.unsigned_char, len: c.size_t) #c_call;
    end_cert    : (ctx: **br_x509_class) #c_call;
    end_chain   : (ctx: **br_x509_class) -> c.unsigned #c_call;
    get_pkey    : (ctx: **br_x509_class, usages: *c.unsigned) -> *br_x509_pkey #c_call;
}

br_x500_name :: struct {
    data : *c.unsigned_char;
    len  : c.size_t;
}

br_x509_pkey :: struct {
    key_type: c.unsigned_char;
    key: union {
        rsa : br_rsa_public_key;
        ec  : br_ec_public_key;
    };
}

br_x509_trust_anchor :: struct {
    dn    : br_x500_name;
    flags : c.unsigned;
    pkey  : br_x509_pkey;
}

br_x509_minimal_context :: struct {
    vtable : *br_x509_class;
    pkey   : br_x509_pkey;

    cpu: struct {
        dp: *u32;
        rp: *u32;
        ip: *c.unsigned_char;
    };

    dp_stack             : [32]u32;
    rp_stack             : [32]u32;
    err                  : c.int;
    server_name          : *c.char;
    key_usages           : c.unsigned_char;
    days                 : u32;
    seconds              : u32;
    cert_length          : u32;
    num_certs            : u32;
    hbuf                 : *c.unsigned_char;
    hlen                 : c.size_t;
    pad                  : [256]c.unsigned_char;
    ee_pkey_data         : [BR_X509_BUFSIZE_KEY]c.unsigned_char;
    pkey_data            : [BR_X509_BUFSIZE_KEY]c.unsigned_char;
    cert_signer_key_type : c.unsigned_char;
    cert_sig_hash_oid    : u16;
    cert_sig_hash_len    : c.unsigned_char;
    cert_sig             : [BR_X509_BUFSIZE_SIG]c.unsigned_char;
    cert_sig_len         : u16;
    min_rsa_size         : s16;
    trust_anchors        : *br_x509_trust_anchor;
    trust_anchors_num    : c.size_t;
    do_mhash             : c.unsigned_char;
    mhash                : br_multihash_context;
    tbs_hash             : [64]c.unsigned_char;
    do_dn_hash           : c.unsigned_char;
    dn_hash_impl         : *br_hash_class;
    dn_hash              : br_hash_compat_context;
    current_dn_hash      : [64]c.unsigned_char;
    next_dn_hash         : [64]c.unsigned_char;
    saved_dn_hash        : [64]c.unsigned_char;
    name_elts            : *br_name_element;
    num_name_elts        : c.size_t;
    irsa                 : br_rsa_pkcs1_vrfy;
    iecdsa               : br_ecdsa_vrfy;
    iec                  : *br_ec_impl;
}
br_sslrec_in_class :: struct {
    context_size : c.size_t;
    check_length : (ctx: **br_sslrec_in_class, record_len: c.size_t) -> c.int #c_call;
    decrypt      : (ctx: **br_sslrec_in_class, record_type: c.int, version: c.unsigned, payload: *void, len: *c.size_t) -> *c.unsigned_char #c_call;
}

br_block_cbcdec_class :: struct {
    context_size   : c.size_t;
    block_size     : c.unsigned;
    log_block_size : c.unsigned;

    init : (ctx: **br_block_cbcdec_class, key: *void, key_len: c.size_t) #c_call;
    run  : (ctx: **br_block_cbcdec_class, iv: *void, data: *void, len: c.size_t) #c_call;
}

br_sslrec_in_cbc_class :: struct {
    inner : br_sslrec_in_class;
    init  : (ctx: **br_sslrec_in_cbc_class, bc_impl: *br_block_cbcdec_class, bc_key: *void, bc_key_len: c.size_t, dig_impl: *br_hash_class, mac_key: *void, mac_key_len: c.size_t, mac_out_len: c.size_t, iv: *void) #c_call;
}

br_aes_big_cbcdec_keys :: struct {
    vtable     : *br_block_cbcdec_class;
    skey       : [60]u32;
    num_rounds : c.unsigned;
}

br_aes_small_cbcdec_keys :: struct {
    vtable     : *br_block_cbcdec_class;
    skey       : [60]u32;
    num_rounds : c.unsigned;
}

br_aes_ct_cbcdec_keys :: struct {
    vtable     : *br_block_cbcdec_class;
    skey       : [60]u32;
    num_rounds : c.unsigned;
}

br_aes_ct64_cbcdec_keys :: struct {
    vtable     : *br_block_cbcdec_class;
    skey       : [30]u64;
    num_rounds : c.unsigned;
}

br_aes_x86ni_cbcdec_keys :: struct {
    vtable: *br_block_cbcdec_class;

    skey: union {
        skni: [16 * 15]c.unsigned_char;
    };

    num_rounds: c.unsigned;
}

br_aes_pwr8_cbcdec_keys :: struct {
    vtable: *br_block_cbcdec_class;

    skey: union {
        skni: [16 * 15]c.unsigned_char;
    };

    num_rounds: c.unsigned;
}

br_aes_gen_cbcdec_keys :: union {
    vtable  : *br_block_cbcdec_class;
    c_big   : br_aes_big_cbcdec_keys;
    c_small : br_aes_small_cbcdec_keys;
    c_ct    : br_aes_ct_cbcdec_keys;
    c_ct64  : br_aes_ct64_cbcdec_keys;
    c_x86ni : br_aes_x86ni_cbcdec_keys;
    c_pwr8  : br_aes_pwr8_cbcdec_keys;
}

br_des_tab_cbcdec_keys :: struct {
    vtable     : *br_block_cbcdec_class;
    skey       : [96]u32;
    num_rounds : c.unsigned;
}

br_des_ct_cbcdec_keys :: struct {
    vtable     : *br_block_cbcdec_class;
    skey       : [96]u32;
    num_rounds : c.unsigned;
}

br_des_gen_cbcdec_keys :: union {
    vtable : *br_block_cbcdec_class;
    c_tab  : br_des_tab_cbcdec_keys;
    c_ct   : br_des_ct_cbcdec_keys;
}

br_sslrec_in_cbc_context :: struct {
    vtable : *br_sslrec_in_cbc_class;
    seq    : u64;

    bc: union {
        vtable : *br_block_cbcdec_class;
        aes    : br_aes_gen_cbcdec_keys;
        des    : br_des_gen_cbcdec_keys;
    };

    mac         : br_hmac_key_context;
    mac_len     : c.size_t;
    iv          : [16]c.unsigned_char;
    explicit_IV : c.int;
}

br_block_ctr_class :: struct {
    context_size   : c.size_t;
    block_size     : c.unsigned;
    log_block_size : c.unsigned;

    init: (ctx: **br_block_ctr_class, key: *void, key_len: c.size_t) #c_call;
    run: (ctx: **br_block_ctr_class, iv: *void, cc: u32, data: *void, len: c.size_t) -> u32 #c_call;
}

br_aes_big_ctr_keys :: struct {
    vtable     : *br_block_ctr_class;
    skey       : [60]u32;
    num_rounds : c.unsigned;
}

br_aes_small_ctr_keys :: struct {
    vtable     : *br_block_ctr_class;
    skey       : [60]u32;
    num_rounds : c.unsigned;
}

br_aes_ct_ctr_keys :: struct {
    vtable     : *br_block_ctr_class;
    skey       : [60]u32;
    num_rounds : c.unsigned;
}

br_aes_ct64_ctr_keys :: struct {
    vtable     : *br_block_ctr_class;
    skey       : [30]u64;
    num_rounds : c.unsigned;
}

br_aes_x86ni_ctr_keys :: struct {
    vtable: *br_block_ctr_class;

    skey: union {
        skni: [16 * 15]c.unsigned_char;
    };

    num_rounds: c.unsigned;
}

br_aes_pwr8_ctr_keys :: struct {
    vtable: *br_block_ctr_class;

    skey: union {
        skni: [16 * 15]c.unsigned_char;
    };

    num_rounds: c.unsigned;
}

br_aes_gen_ctr_keys :: union {
    vtable  : *br_block_ctr_class;
    c_big   : br_aes_big_ctr_keys;
    c_small : br_aes_small_ctr_keys;
    c_ct    : br_aes_ct_ctr_keys;
    c_ct64  : br_aes_ct64_ctr_keys;
    c_x86ni : br_aes_x86ni_ctr_keys;
    c_pwr8  : br_aes_pwr8_ctr_keys;
}

br_sslrec_in_gcm_class :: struct {
    inner : br_sslrec_in_class;
    init  : (ctx: **br_sslrec_in_gcm_class, bc_impl: *br_block_ctr_class, key: *void, key_len: c.size_t, gh_impl: br_ghash, iv: *void) #c_call;
}

br_sslrec_out_class :: struct {
    context_size: c.size_t;

    max_plaintext : (ctx: **br_sslrec_out_class, start: *c.size_t, end: *c.size_t) #c_call;
    encrypt       : (ctx: **br_sslrec_out_class, record_type: c.int, version: c.unsigned, plaintext: *void, len: *c.size_t) -> *c.unsigned_char #c_call;
}

br_sslrec_out_gcm_class :: struct {
    inner : br_sslrec_out_class;
    init  : (ctx: **br_sslrec_out_gcm_class, bc_impl: *br_block_ctr_class, key: *void, key_len: c.size_t, gh_impl: br_ghash, iv: *void) #c_call;
}

br_sslrec_gcm_context :: struct {
    vtable: union {
        gen : *void;
        in  : *br_sslrec_in_gcm_class;
        out : *br_sslrec_out_gcm_class;
    };

    seq: u64;
    bc: union {
        vtable : *br_block_ctr_class;
        aes    : br_aes_gen_ctr_keys;
    };

    gh : br_ghash;
    iv : [4]c.unsigned_char;
    h  : [16]c.unsigned_char;
} 

br_poly1305_run :: #type (key: *void, iv: *void, data: *void, len: c.size_t, aad: *void, aad_len: c.size_t, tag: *void, ichacha: br_chacha20_run, encrypt: c.int) #c_call;
br_chacha20_run :: #type (key: *void, iv: *void, cc: u32, data: *void, len: c.size_t) -> u32 #c_call;

br_sslrec_chapol_context :: struct {
    vtable: union {
        gen : *void;
        in  : *br_sslrec_in_chapol_class;
        out : *br_sslrec_out_chapol_class;
    };

    seq     : u64;
    key     : [32]c.unsigned_char;
    iv      : [12]c.unsigned_char;
    ichacha : br_chacha20_run;
    ipoly   : br_poly1305_run;
}

br_sslrec_in_chapol_class :: struct {
    inner : br_sslrec_in_class;
    init  : (ctx: **br_sslrec_in_chapol_class, ichacha: br_chacha20_run, ipoly: br_poly1305_run, key: *void, iv: *void) #c_call;
}

br_sslrec_out_chapol_class :: struct {
    inner : br_sslrec_out_class;
    init  : (ctx: **br_sslrec_out_chapol_class, ichacha: br_chacha20_run, ipoly: br_poly1305_run, key: *void, iv: *void) #c_call;
}

br_block_ctrcbc_class :: struct {
    context_size   : c.size_t;
    block_size     : c.unsigned;
    log_block_size : c.unsigned;

    init    : (ctx: **br_block_ctrcbc_class, key: *void, key_len: c.size_t) #c_call;
    encrypt : (ctx: **br_block_ctrcbc_class, ctr: *void, cbcmac: *void, data: *void, len: c.size_t) #c_call;
    decrypt : (ctx: **br_block_ctrcbc_class, ctr: *void, cbcmac: *void, data: *void, len: c.size_t) #c_call;
    ctr     : (ctx: **br_block_ctrcbc_class, ctr: *void, data: *void, len: c.size_t) #c_call;
    mac     : (ctx: **br_block_ctrcbc_class, cbcmac: *void, data: *void, len: c.size_t) #c_call;
}

br_aes_big_ctrcbc_keys :: struct {
    vtable     : *br_block_ctrcbc_class;
    skey       : [60]u32;
    num_rounds : c.unsigned;
}

br_aes_small_ctrcbc_keys :: struct {
    vtable     : *br_block_ctrcbc_class;
    skey       : [60]u32;
    num_rounds : c.unsigned;
}

br_aes_ct_ctrcbc_keys :: struct {
    vtable     : *br_block_ctrcbc_class;
    skey       : [60]u32;
    num_rounds : c.unsigned;
}

br_aes_ct64_ctrcbc_keys :: struct {
    vtable     : *br_block_ctrcbc_class;
    skey       : [30]u64;
    num_rounds : c.unsigned;
}

br_aes_x86ni_ctrcbc_keys :: struct {
    vtable: *br_block_ctrcbc_class;

    skey: union {
        skni: [16 * 15]c.unsigned_char;
    };

    num_rounds: c.unsigned;
}

 br_aes_pwr8_ctrcbc_keys :: struct {
    vtable: *br_block_ctrcbc_class;

    skey: union {
        skni: [16 * 15]c.unsigned_char;
    };

    num_rounds: c.unsigned;
}

br_aes_gen_ctrcbc_keys :: union {
    vtable  : *br_block_ctrcbc_class;
    c_big   : br_aes_big_ctrcbc_keys;
    c_small : br_aes_small_ctrcbc_keys;
    c_ct    : br_aes_ct_ctrcbc_keys;
    c_ct64  : br_aes_ct64_ctrcbc_keys;
    c_x86ni : br_aes_x86ni_ctrcbc_keys;
    c_pwr8  : br_aes_pwr8_ctrcbc_keys;
}

br_sslrec_in_ccm_class :: struct {
    inner : br_sslrec_in_class;
    init  : (ctx: **br_sslrec_in_ccm_class, bc_impl: *br_block_ctrcbc_class, key: *void, key_len: c.size_t, iv: *void, tag_len: c.size_t) #c_call;
}

br_sslrec_out_ccm_class :: struct {
    inner : br_sslrec_out_class;
    init  : (ctx: **br_sslrec_out_ccm_class, bc_impl: *br_block_ctrcbc_class, key: *void, key_len: c.size_t, iv: *void, tag_len: c.size_t) #c_call;
}

br_sslrec_ccm_context :: struct {
    vtable: union {
        gen : *void;
        in  : *br_sslrec_in_ccm_class;
        out : *br_sslrec_out_ccm_class;
    };

    seq: u64;

    bc: union {
        vtable : *br_block_ctrcbc_class;
        aes    : br_aes_gen_ctrcbc_keys;
    };

    iv      : [4]c.unsigned_char;
    tag_len : c.size_t;
}

br_sslrec_out_clear_context :: struct {
    vtable: *br_sslrec_out_class;
}

br_block_cbcenc_class :: struct {
    context_size   : c.size_t;
    block_size     : c.unsigned;
    log_block_size : c.unsigned;

    init : (ctx: **br_block_cbcenc_class, key: *void, key_len: c.size_t) #c_call;
    run  : (ctx: **br_block_cbcenc_class, iv: *void, data: *void, len: c.size_t) #c_call;
}

br_sslrec_out_cbc_class :: struct {
    inner : br_sslrec_out_class;
    init  : (ctx: **br_sslrec_out_cbc_class, bc_impl: *br_block_cbcenc_class, bc_key: *void, bc_key_len: c.size_t, dig_impl: *br_hash_class, mac_key: *void, mac_key_len: c.size_t, mac_out_len: c.size_t, iv: *void) #c_call;
}

br_aes_big_cbcenc_keys :: struct {
    vtable     : *br_block_cbcenc_class;
    skey       : [60]u32;
    num_rounds : c.unsigned;
}

br_aes_small_cbcenc_keys :: struct {
    vtable     : *br_block_cbcenc_class;
    skey       : [60]u32;
    num_rounds : c.unsigned;
}

br_aes_ct_cbcenc_keys :: struct {
    vtable     : *br_block_cbcenc_class;
    skey       : [60]u32;
    num_rounds : c.unsigned;
}

br_aes_ct64_cbcenc_keys :: struct {
    vtable     : *br_block_cbcenc_class;
    skey       : [30]u64;
    num_rounds : c.unsigned;
}

br_aes_x86ni_cbcenc_keys :: struct {
    vtable: *br_block_cbcenc_class;

    skey: union {
        skni: [16 * 15]c.unsigned_char;
    };

    num_rounds: c.unsigned;
}

br_aes_pwr8_cbcenc_keys :: struct {
    vtable: *br_block_cbcenc_class;

    skey: union {
        skni: [16 * 15]c.unsigned_char;
    };

    num_rounds: c.unsigned;
}

br_aes_gen_cbcenc_keys :: union {
    vtable  : *br_block_cbcenc_class;
    c_big   : br_aes_big_cbcenc_keys;
    c_small : br_aes_small_cbcenc_keys;
    c_ct    : br_aes_ct_cbcenc_keys;
    c_ct64  : br_aes_ct64_cbcenc_keys;
    c_x86ni : br_aes_x86ni_cbcenc_keys;
    c_pwr8  : br_aes_pwr8_cbcenc_keys;
}

br_des_tab_cbcenc_keys :: struct {
    vtable     : *br_block_cbcenc_class;
    skey       : [96]u32;
    num_rounds : c.unsigned;
}

br_des_ct_cbcenc_keys :: struct {
    vtable     : *br_block_cbcenc_class;
    skey       : [96]u32;
    num_rounds : c.unsigned;
}

br_des_gen_cbcenc_keys :: union {
    vtable : *br_block_cbcenc_class;
    tab    : br_des_tab_cbcenc_keys;
    ct     : br_des_ct_cbcenc_keys;
}

br_sslrec_out_cbc_context :: struct {
    vtable : *br_sslrec_out_cbc_class;
    seq    : u64;

    bc: union {
        vtable : *br_block_cbcenc_class;
        aes    : br_aes_gen_cbcenc_keys;
        des    : br_des_gen_cbcenc_keys;
    };

    mac         : br_hmac_key_context;
    mac_len     : c.size_t;
    iv          : [16]c.unsigned_char;
    explicit_IV : c.int;
}

br_x509_certificate :: struct {
    data: *c.unsigned_char;
    data_len: c.size_t;
}

br_rsa_public_key :: struct {
    n    : *c.unsigned_char;
    nlen : c.size_t;
    e    : *c.unsigned_char;
    elen : c.size_t;
}

br_ec_public_key :: struct {
    curve : c.int;
    q     : *c.unsigned_char;
    qlen  : c.size_t;
}

br_tls_prf_impl :: #type (dst: *void, len: c.size_t, secret: *void, secret_len: c.size_t, label: *c.char, seed_num: c.size_t, seed: *br_tls_prf_seed_chunk) #c_call;

br_tls_prf_seed_chunk :: struct {
    data : *void;
    len  : c.size_t;
}

br_rsa_pkcs1_vrfy :: #type (x: *c.unsigned_char, xlen: c.size_t, hash_oid: *c.unsigned_char, hash_len: c.size_t, pk: *br_rsa_public_key, hash_out: *c.unsigned_char) -> u32 #c_call;

br_ec_impl :: struct {
    supported_curves: u32;

    generator : (curve: c.int, len: *c.size_t) -> *c.unsigned_char #c_call;
    order     : (curve: c.int, len: *c.size_t) -> *c.unsigned_char #c_call;
    xoff      : (curve: c.int, len: *c.size_t) -> c.size_t #c_call;
    mul       : (G: *c.unsigned_char, Glen: c.size_t, x: *c.unsigned_char, xlen: c.size_t, curve: c.int) -> u32 #c_call;
    mulgen    : (R: *c.unsigned_char, x: *c.unsigned_char, xlen: c.size_t, curve: c.int) -> c.size_t #c_call;
    muladd    : (A: *c.unsigned_char, B: *c.unsigned_char, len: c.size_t, x: *c.unsigned_char, xlen: c.size_t, y: *c.unsigned_char, ylen: c.size_t, curve: c.int) -> u32 #c_call;
}

br_ecdsa_vrfy :: #type (impl: *br_ec_impl, hash: *void, hash_len: c.size_t, pk: *br_ec_public_key, sig: *void, sig_len: c.size_t) -> u32 #c_call;

br_sslio_context :: struct {
    engine        : *br_ssl_engine_context;
    low_read      : (read_context: *void, data: *c.unsigned_char, len: c.size_t) -> c.int #c_call;
    read_context  : *void;
    low_write     : (write_context: *void, data: *c.unsigned_char, len: c.size_t) -> c.int #c_call;
    write_context : *void;
}

br_rsa_private_key :: struct {
    n_bitlen : u32;

    p: *c.unsigned_char;
    plen: c.size_t;

    q: *c.unsigned_char;
    qlen: c.size_t;

    dp: *c.unsigned_char;
    dplen: c.size_t;

    dq: *c.unsigned_char;
    dqlen: c.size_t;

    iq: *c.unsigned_char;
    iqlen: c.size_t;
}

br_ec_private_key :: struct {
    curve : c.int;
    x     : *c.unsigned_char;
    xlen  : c.size_t;
}

br_rsa_pkcs1_sign :: #type (hash_oid: *c.unsigned_char, hash: *c.unsigned_char, hash_len: c.size_t, sk: *br_rsa_private_key, x: *c.unsigned_char) -> u32 #c_call;
br_ecdsa_sign     :: #type (impl: *br_ec_impl, hf: *br_hash_class, hash_value: *void, sk: *br_ec_private_key, sig: *void) -> c.size_t #c_call;

br_name_element :: struct {
    oid    : *c.unsigned_char;
    buf    : *c.char;
    len    : c.size_t;
    status : c.int;
}

br_rsa_public :: #type (x: *c.unsigned_char, xlen: c.size_t, pk: *br_rsa_public_key) -> u32 #c_call;

run_until                        :: (ctx: *br_sslio_context, target: c.unsigned) -> c.int                                                                                                                                                                                                                 #foreign BearSSL;
br_sslio_init                    :: (ctx: *br_sslio_context, engine: *br_ssl_engine_context, low_read: (read_context: *void, data: *c.unsigned_char, len: c.size_t) #c_call, read_context: *void, low_write: (write_context: *void, data: *c.unsigned_char, len: c.size_t) #c_call, write_context: *void) #foreign BearSSL;
br_sslio_read                    :: (ctx: *br_sslio_context, dst: *void, len: c.size_t) -> c.int                                                                                                                                                                                                          #foreign BearSSL;
br_sslio_read_all                :: (ctx: *br_sslio_context, dst: *void, len: c.size_t) -> c.int                                                                                                                                                                                                          #foreign BearSSL;
br_sslio_write                   :: (ctx: *br_sslio_context, src: *void, len: c.size_t) -> c.int                                                                                                                                                                                                          #foreign BearSSL;
br_sslio_write_all               :: (ctx: *br_sslio_context, src: *void, len: c.size_t) -> c.int                                                                                                                                                                                                          #foreign BearSSL;
br_sslio_flush                   :: (ctx: *br_sslio_context) -> c.int                                                                                                                                                                                                                                     #foreign BearSSL;
br_sslio_close                   :: (ctx: *br_sslio_context) -> c.int                                                                                                                                                                                                                                     #foreign BearSSL;
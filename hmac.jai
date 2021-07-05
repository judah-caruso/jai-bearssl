br_hmac_context :: struct {
    dig     : br_hash_compat_context;
    kso     : [64]u8;
    out_len : s64;
}

br_hmac_key_context :: struct {
    using dig_vtable: *br_hash_class;
    ksi: [64]u8;
    kso: [64]u8;
}

br_prng_class :: struct {
    context_size: c.size_t;
    init     : (ctx: **br_prng_class, params: *void, seed: *void, seed_len: c.size_t) #c_call;
    generate : (ctx: **br_prng_class, out: *void, len: c.size_t) #c_call;
    update   : (ctx: **br_prng_class, seed: *void, seed_len: c.size_t) #c_call;
}

br_hmac_drbg_context :: struct {
    using vtable: *br_prng_class;

    K: [64]c.unsigned_char;
    V: [64]c.unsigned_char;
    digest_class: *br_hash_class;
}

br_hmac_size :: inline (ctx: *br_hmac_context) -> s64 {
    return ctx.out_len;
}

br_hmac_key_get_digest :: inline (kc: *br_hmac_key_context) -> *br_hash_class {
    return kc.dig_vtable;
}

br_hmac_get_digest :: inline (hc: *br_hmac_context) -> *br_hash_class {
    return hc.dig.vtable;
}

br_hmac_init     :: (ctx: *br_hmac_context, kc: *br_hmac_key_context, out_len: s64)                               #foreign BearSSL;
br_hmac_key_init :: (kc: *br_hmac_key_context, digest_vtable: *br_hash_class, key: *void, key_len: s64)           #foreign BearSSL;
br_hmac_update   :: (ctx: *br_hmac_context, data: *void, len: s64)                                                #foreign BearSSL;
br_hmac_out      :: (ctx: *br_hmac_context, out: *void) -> s64                                                    #foreign BearSSL;
br_hmac_outCT    :: (ctx: *br_hmac_context, data: *void, len: s64, min_len: s64, max_len: s64, out: *void) -> s64 #foreign BearSSL;

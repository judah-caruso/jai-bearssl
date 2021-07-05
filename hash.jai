BR_HASHDESC_ID_OFF         :: 0;
BR_HASHDESC_OUT_OFF        :: 8;
BR_HASHDESC_ID_MASK        :: 0xFF;
BR_HASHDESC_OUT_MASK       :: 0x7F;
BR_HASHDESC_STATE_OFF      :: 15;
BR_HASHDESC_STATE_MASK     :: 0xFF;
BR_HASHDESC_LBLEN_OFF      :: 23;
BR_HASHDESC_LBLEN_MASK     :: 0x0F;
BR_HASHDESC_MD_PADDING     :: 1 << 28;
BR_HASHDESC_MD_PADDING_128 :: 1 << 29;
BR_HASHDESC_MD_PADDING_BE  :: 1 << 30;

br_hash_class :: struct {
    context_size : s64;
    desc         : u32;

    init      : (ctx: **br_hash_class) #c_call;
    update    : (ctx: **br_hash_class, data: *void, len: s64) #c_call;
    out       : (ctx: **br_hash_class, dst: *void) #c_call;
    state     : (ctx: **br_hash_class, dst: *void) -> u64 #c_call;
    set_state : (ctx: **br_hash_class, stb: *void, count: u64) #c_call;
}

BR_HASHDESC_ID :: inline (id: u32) -> u32 #expand {
    return id << BR_HASHDESC_ID_OFF;
}

BR_HASHDESC_OUT :: inline (size: u32) -> u32 #expand {
    return size << BR_HASHDESC_OUT_OFF;
}

BR_HASHDESC_STATE :: inline (size: u32) -> u32 #expand {
    return size << BR_HASHDESC_STATE_OFF;
}

BR_HASHDESC_LBLEN :: (ls: u32) -> u32 #expand {
    return ls << BR_HASHDESC_LBLEN_OFF;
}

/// --- MD5
br_md5_ID   :: 1;
br_md5_SIZE :: 16;
br_md5_vtable: br_hash_class;

br_md5_context :: struct {
    using vtable: *br_hash_class;

    buf   : [64]u8;
    count : u64;
    val   : [4]u32;
}

br_hash_compat_context :: union {
    using vtable: *br_hash_class;

    md5     : br_md5_context;
    sha1    : br_sha1_context;
    sha224  : br_sha224_context;
    sha256  : br_sha256_context;
    sha384  : br_sha384_context;
    sha512  : br_sha512_context;
    md5sha1 : br_md5sha1_context;
}

br_md5_init      :: (ctx: *br_md5_context)                         #foreign BearSSL;
br_md5_update    :: (ctx: *br_md5_context, data: *void, len: s64)  #foreign BearSSL;
br_md5_out       :: (ctx: *br_md5_context, out: *void)             #foreign BearSSL;
br_md5_state     :: (ctx: *br_md5_context, out: *void) -> u64      #foreign BearSSL;
br_md5_set_state :: (ctx: *br_md5_context, stb: *void, count: u64) #foreign BearSSL;


/// --- SHA1
br_sha1_ID   :: 2;
br_sha1_SIZE :: 20;
br_sha1_vtable: br_hash_class;

br_sha1_context :: struct {
    using vtable: *br_hash_class;

    buf   : [64]u8;
    count : u64;
    val   : [5]u32;
} 

br_sha1_init      :: (ctx: *br_sha1_context)                         #foreign BearSSL;
br_sha1_update    :: (ctx: *br_sha1_context, data: *void, len: s64)  #foreign BearSSL;
br_sha1_out       :: (ctx: *br_sha1_context, out: *void)             #foreign BearSSL;
br_sha1_state     :: (ctx: *br_sha1_context, out: *void) -> u64      #foreign BearSSL;
br_sha1_set_state :: (ctx: *br_sha1_context, stb: *void, count: u64) #foreign BearSSL;


/// --- SHA224
br_sha224_ID   :: 3;
br_sha224_SIZE :: 28;
br_sha224_vtable: br_hash_class;

br_sha224_context :: struct {
    using vtable: *br_hash_class;

    buf   : [64]u8;
    count : u64;
    val   : [8]u32;
}

br_sha224_init      :: (ctx: *br_sha224_context)                         #foreign BearSSL;
br_sha224_update    :: (ctx: *br_sha224_context, data: *void, len: s64)  #foreign BearSSL;
br_sha224_out       :: (ctx: *br_sha224_context, out: *void)             #foreign BearSSL;
br_sha224_state     :: (ctx: *br_sha224_context, out: *void) -> u64      #foreign BearSSL;
br_sha224_set_state :: (ctx: *br_sha224_context, stb: *void, count: u64) #foreign BearSSL;


/// --- SHA256
br_sha256_ID   :: 4;
br_sha256_SIZE :: 32;
br_sha256_vtable: br_hash_class;

br_sha256_context :: struct {
    using vtable: *br_hash_class;
}

br_sha256_init      :: (ctx: *br_sha256_context)             #foreign BearSSL;
br_sha256_out       :: (ctx: *br_sha256_context, out: *void) #foreign BearSSL;
br_sha256_update    :: br_sha224_update;
br_sha256_state     :: br_sha224_state;
br_sha256_set_state :: br_sha224_set_state;
// br_sha256_update    :: (ctx: *br_sha256_context, data: *void, len: s64)  #foreign BearSSL;
// br_sha256_state     :: (ctx: *br_sha256_context, out: *void) -> u64      #foreign BearSSL;
// br_sha256_set_state :: (ctx: *br_sha256_context, stb: *void, count: u64) #foreign BearSSL;


/// --- SHA384
br_sha384_ID   :: 5;
br_sha384_SIZE :: 48;
br_sha384_vtable: br_hash_class;

br_sha384_context :: struct {
    using vtable: *br_hash_class;

    buf   : [128]u8;
    count : u64;
    val   : [8]u64;
}

br_sha384_init      :: (ctx: *br_sha384_context)                         #foreign BearSSL;
br_sha384_update    :: (ctx: *br_sha384_context, data: *void, len: s64)  #foreign BearSSL;
br_sha384_out       :: (ctx: *br_sha384_context, out: *void)             #foreign BearSSL;
br_sha384_state     :: (ctx: *br_sha384_context, out: *void) -> u64      #foreign BearSSL;
br_sha384_set_state :: (ctx: *br_sha384_context, stb: *void, count: u64) #foreign BearSSL;


/// --- SHA512
br_sha512_ID   :: 6;
br_sha512_SIZE :: 64;
br_sha512_vtable: br_hash_class;

br_sha512_context :: struct {
    using vtable: *br_hash_class;
}

br_sha512_init      :: (ctx: *br_sha512_context)                         #foreign BearSSL;
br_sha512_out       :: (ctx: *br_sha512_context, out: *void)             #foreign BearSSL;
br_sha512_update    :: br_sha384_update;
br_sha512_state     :: br_sha384_state;
br_sha512_set_state :: br_sha384_set_state;
// br_sha512_update    :: (ctx: *br_sha512_context, data: *void, len: s64)  #foreign BearSSL;
// br_sha512_state     :: (ctx: *br_sha512_context, out: *void) -> u64      #foreign BearSSL;
// br_sha512_set_state :: (ctx: *br_sha512_context, stb: *void, count: u64) #foreign BearSSL;


/// --- MD5SHA1
br_md5sha1_ID   :: 0;
br_md5sha1_SIZE :: 36;
br_md5sha1_vtable: br_hash_class;

br_md5sha1_context :: struct {
    using vtable: *br_hash_class;

    buf     : [64]u8;
    count   : u64;
    val_md5 : [4]u32;
    val_sha1: [5]u32;
}

br_md5sha1_init      :: (ctx: *br_md5sha1_context)                         #foreign BearSSL;
br_md5sha1_update    :: (ctx: *br_md5sha1_context, data: *void, len: s64)  #foreign BearSSL;
br_md5sha1_out       :: (ctx: *br_md5sha1_context, out: *void)             #foreign BearSSL;
br_md5sha1_state     :: (ctx: *br_md5sha1_context, out: *void) -> u64      #foreign BearSSL;
br_md5sha1_set_state :: (ctx: *br_md5sha1_context, stb: *void, count: u64) #foreign BearSSL;


/// --- Multihash
br_multihash_context :: struct {
    buf    : [128]u8;
    count  : u64;
    val_32 : [25]u32;
    val_64 : [16]u64;
    impl   : [6]*br_hash_class;
}

br_multihash_setimpl :: inline (ctx: *br_multihash_context, id: int, impl: *br_hash_class) {
    assert(id >= 1 && id <= 6, "% was an invalid ID", id);
    ctx.impl[id - 1] = impl;
}

br_multihash_getimpl :: inline (ctx: *br_multihash_context, id: int) -> *br_hash_class {
    assert(id >= 1 && id <= 6, "% was an invalid ID", id);
    return ctx.impl[id - 1];
}

br_ghash :: #type (y: *void, h: *void, data: *void, len: s64) #c_call;

br_multihash_zero   :: (ctx: *br_multihash_context)                             #foreign BearSSL;
br_multihash_init   :: (ctx: *br_multihash_context)                             #foreign BearSSL;
br_multihash_update :: (ctx: *br_multihash_context, data: *void, len: s64)      #foreign BearSSL;
br_multihash_out    :: (ctx: *br_multihash_context, id: s32, dst: *void) -> s64 #foreign BearSSL;
br_ghash_ctmul      :: (y: *void, h: *void, data: *void, len: s64)              #foreign BearSSL;
br_ghash_ctmul32    :: (y: *void, h: *void, data: *void, len: s64)              #foreign BearSSL;
br_ghash_ctmul64    :: (y: *void, h: *void, data: *void, len: s64)              #foreign BearSSL;
br_ghash_pclmul     :: (y: *void, h: *void, data: *void, len: s64)              #foreign BearSSL;
br_ghash_pclmul_get :: () -> br_ghash                                           #foreign BearSSL;
br_ghash_pwr8       :: (y: *void, h: *void, data: *void, len: s64)              #foreign BearSSL;
br_ghash_pwr8_get   :: () -> br_ghash                                           #foreign BearSSL;


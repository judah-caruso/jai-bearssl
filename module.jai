// This MUST be called to initialize the br_XXX_vtable global variables.
// Until these can be bound directly, this is the workaround.
initialize_global_vtables :: () {
    {
        using br_md5_vtable;

        context_size = size_of(br_md5_context);
        desc = BR_HASHDESC_ID(br_md5_ID) |
               BR_HASHDESC_OUT(16)       |
               BR_HASHDESC_STATE(16)     |
               BR_HASHDESC_LBLEN(6)      |
               BR_HASHDESC_MD_PADDING;

        init      = xx br_md5_init;
        update    = xx br_md5_update;
        out       = xx br_md5_out;
        state     = xx br_md5_state;
        set_state = xx br_md5_set_state;
    }

    {
        using br_sha1_vtable;

        context_size = size_of(br_sha1_context);
        desc = BR_HASHDESC_ID(br_sha1_ID) |
               BR_HASHDESC_OUT(20)        |
               BR_HASHDESC_STATE(20)      |
               BR_HASHDESC_LBLEN(6)       |
               BR_HASHDESC_MD_PADDING     |
               BR_HASHDESC_MD_PADDING_BE;

        init      = xx br_sha1_init;
        update    = xx br_sha1_update;
        out       = xx br_sha1_out;
        state     = xx br_sha1_state;
        set_state = xx br_sha1_set_state;
    }

    {
        using br_sha224_vtable;

        context_size = size_of(br_sha224_context);
        desc = BR_HASHDESC_ID(br_sha224_ID) |
               BR_HASHDESC_OUT(28)          |
               BR_HASHDESC_STATE(32)        |
               BR_HASHDESC_LBLEN(6)         |
               BR_HASHDESC_MD_PADDING       |
               BR_HASHDESC_MD_PADDING_BE;

        init      = xx br_sha224_init;
        update    = xx br_sha224_update;
        out       = xx br_sha224_out;
        state     = xx br_sha224_state;
        set_state = xx br_sha224_set_state;
    }

    {
        using br_sha256_vtable;

        context_size = size_of(br_sha256_context);
        desc = BR_HASHDESC_ID(br_sha256_ID) |
               BR_HASHDESC_OUT(32)          |
               BR_HASHDESC_STATE(32)        |
               BR_HASHDESC_LBLEN(6)         |
               BR_HASHDESC_MD_PADDING       |
               BR_HASHDESC_MD_PADDING_BE;

        init      = xx br_sha256_init;
        update    = xx br_sha256_update;
        out       = xx br_sha256_out;
        state     = xx br_sha256_state;
        set_state = xx br_sha256_set_state;
    }

    {
        using br_sha384_vtable;

        context_size = size_of(br_sha512_context);
        desc = BR_HASHDESC_ID(br_sha512_ID) |
               BR_HASHDESC_OUT(48)          |
               BR_HASHDESC_STATE(64)        |
               BR_HASHDESC_LBLEN(7)         |
               BR_HASHDESC_MD_PADDING       |
               BR_HASHDESC_MD_PADDING_BE    |
               BR_HASHDESC_MD_PADDING_128;

        init      = xx br_sha512_init;
        update    = xx br_sha512_update;
        out       = xx br_sha512_out;
        state     = xx br_sha512_state;
        set_state = xx br_sha512_set_state;
    }

    {
        using br_sha512_vtable;

        context_size = size_of(br_sha512_context);
        desc = BR_HASHDESC_ID(br_sha512_ID) |
               BR_HASHDESC_OUT(64)          |
               BR_HASHDESC_STATE(64)        |
               BR_HASHDESC_LBLEN(7)         |
               BR_HASHDESC_MD_PADDING       |
               BR_HASHDESC_MD_PADDING_BE    |
               BR_HASHDESC_MD_PADDING_128;

        init      = xx br_sha512_init;
        update    = xx br_sha512_update;
        out       = xx br_sha512_out;
        state     = xx br_sha512_state;
        set_state = xx br_sha512_set_state;
    }

    {
        using br_md5sha1_vtable;

        context_size = size_of(br_md5sha1_context);
        desc = BR_HASHDESC_ID(br_md5sha1_ID) |
               BR_HASHDESC_OUT(36)           |
               BR_HASHDESC_STATE(36)         |
               BR_HASHDESC_LBLEN(6);

        init      = xx br_md5sha1_init;
        update    = xx br_md5sha1_update;
        out       = xx br_md5sha1_out;
        state     = xx br_md5sha1_state;
        set_state = xx br_md5sha1_set_state;
    }
}

#if OS == .WINDOWS {
    BearSSL :: #foreign_library, no_dll "win/bearssls";
}

#load "c.jai";
#load "hash.jai";
#load "hmac.jai";
#load "ssl.jai";
#load "io.jai";
#load "x509.jai";
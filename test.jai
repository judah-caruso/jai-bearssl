test_hmac_ct :: () {
    print("HMAC CT... ");
    key := "test HMAC key";

    data: [1000]u8;
    buf1, buf2: [64]u8;

    kc: br_hmac_key_context;
    hc1, hc2: br_hmac_context;

    br_hmac_key_init(*kc, *br_md5_vtable, key.data, key.count);

    for u: 0..2 {
        for v: 0..130 {
            min_len := v;
            max_len := v + 256;

            for w: min_len..max_len {
                br_hmac_init(*hc1, *kc, 0);
                br_hmac_update(*hc1, data.data, u + w);
                hlen1 := br_hmac_out(*hc1, buf1.data);

                br_hmac_init(*hc2, *kc, 0);
                br_hmac_update(*hc2, data.data, u);
                hlen2 := br_hmac_outCT(*hc2, data.data + u, w, min_len, max_len, buf2.data);

                if hlen1 != hlen2 {
                    print("HMAC length mismatch: % / %\n", hlen1, hlen2);
                    return;
                }

                tmp := tprint("HMAC CT %,%,%", u, v, w);
                if !test_equality(tmp, buf1.data, buf2.data, hlen1) {
                    print("Failed!\n");
                    return;
                }
            }
        }
    }

    print("Passed!\n");
}

do_hash :: (id: int, data: *void, len: s64, out: *void) -> s64 {
    cmd5    : br_md5_context;
    csha1   : br_sha1_context;
    csha224 : br_sha224_context;
    csha256 : br_sha256_context;
    csha384 : br_sha384_context;
    csha512 : br_sha512_context;

    if id == {
        case br_md5_ID;
            br_md5_init(*cmd5);
            br_md5_update(*cmd5, data, len);
            br_md5_out(*cmd5, out);
            return 16;

        case br_sha1_ID;
            br_sha1_init(*csha1);
            br_sha1_update(*csha1, data, len);
            br_sha1_out(*csha1, out);
            return 20;

        case br_sha224_ID;
            br_sha224_init(*csha224);
            br_sha224_update(*csha224, data, len);
            br_sha224_out(*csha224, out);
            return 28;

        case br_sha256_ID;
            br_sha256_init(xx *csha256);
            br_sha256_update(xx *csha256, data, len);
            br_sha256_out(xx *csha256, out);
            return 32;

        case br_sha384_ID;
            br_sha384_init(xx *csha384);
            br_sha384_update(xx *csha384, data, len);
            br_sha384_out(xx *csha384, out);
            return 48;

        case br_sha512_ID;
            br_sha512_init(xx *csha512);
            br_sha512_update(xx *csha512, data, len);
            br_sha512_out(xx *csha512, out);
            return 64;

        case;
            print("Unknown hash function %\n", id);
            return 0;
    }
}

test_multihash :: () {
    test_multihash_inner :: (mc: *br_multihash_context) -> int {
        len := 0;
        buf: [258]u8;
        tcount := 0;

        while len < buf.count {
            tmp: [20]u8;

            sc: br_sha1_context;
            br_sha1_init(*sc);
            br_sha1_update(*sc, buf.data, len);
            br_sha1_out(*sc, tmp.data);
            buf[len] = tmp[0];

            len += 1;
        }

        len = 0;
        while len <= 257 {
            br_multihash_init(mc);
            br_multihash_update(mc, buf.data, len);

            for < i: 1..6 {
                tmp, tmp2: [64]u8;

                olen := br_multihash_out(mc, xx i, tmp.data);
                if olen == 0 continue;

                olen2 := do_hash(i, buf.data, len, tmp2.data);
                if olen != olen2 return 0;

                if !test_equality("Hash output", tmp.data, tmp2.data, olen) {
                    return 0;
                }

                tcount += 1;
            }

            br_multihash_init(mc);

            u := 0;
            while u < len {
                br_multihash_update(mc, buf.data + u, 1);

                for i: 1..6 {
                    tmp, tmp2: [64]u8;

                    olen := br_multihash_out(mc, xx i, tmp.data);
                    if olen == 0 continue;

                    olen2 := do_hash(i, buf.data, u + 1, tmp2.data);
                    if olen != olen2 return 0;

                    if !test_equality("Hash output", tmp.data, tmp2.data, olen) {
                        return 0;
                    } 
                }

                u += 1;
            }

            len += 1;
        }

        return tcount;
    }

    print("Multihash...");
    mc: br_multihash_context;

    br_multihash_zero(*mc);
    br_multihash_setimpl(*mc, br_md5_ID, *br_md5_vtable);
    if (test_multihash_inner(*mc) != 258) {
        print("Md5 failed!\n");
        return;
    }

    br_multihash_zero(*mc);
    br_multihash_setimpl(*mc, br_sha1_ID, *br_sha1_vtable);
    if (test_multihash_inner(*mc) != 258) {
        print("Sha1 failed!\n");
        return;
    }

    br_multihash_zero(*mc);
    br_multihash_setimpl(*mc, br_sha224_ID, *br_sha224_vtable);
    if (test_multihash_inner(*mc) != 258) {
        print("Sha224 failed!\n");
        return;
    }

    br_multihash_zero(*mc);
    br_multihash_setimpl(*mc, br_sha256_ID, *br_sha256_vtable);
    if (test_multihash_inner(*mc) != 258) {
        print("Sha256 failed!\n");
        return;
    }

    br_multihash_zero(*mc);
    br_multihash_setimpl(*mc, br_sha384_ID, *br_sha384_vtable);
    if (test_multihash_inner(*mc) != 258) {
        print("Sha384 failed!\n");
        return;
    }

    br_multihash_zero(*mc);
    br_multihash_setimpl(*mc, br_sha512_ID, *br_sha512_vtable);
    if (test_multihash_inner(*mc) != 258) {
        print("Sha512 failed!\n");
        return;
    }

    br_multihash_zero(*mc);
    br_multihash_setimpl(*mc, br_md5_ID, *br_md5_vtable);
    br_multihash_setimpl(*mc, br_sha1_ID, *br_sha1_vtable);
    br_multihash_setimpl(*mc, br_sha224_ID, *br_sha224_vtable);
    br_multihash_setimpl(*mc, br_sha256_ID, *br_sha256_vtable);
    br_multihash_setimpl(*mc, br_sha384_ID, *br_sha384_vtable);
    br_multihash_setimpl(*mc, br_sha512_ID, *br_sha512_vtable);

    if (test_multihash_inner(*mc) != 258 * 6) {
        print("Failed!\n");
        return;
    }

    print("Passed!\n");
}

test_equality :: (banner: string, v1: *void, v2: *void, len: s64) -> bool {
    if memcmp(v1, v2, len) == 0 return true;

    print("\n% failed!\n", banner);
    print("v1: ");
    print_bytes(v1, len);
    print("\n");

    print("v2: ");
    print_bytes(v2, len);
    print("\n");

    return false;
}

main :: () {
    initialize_global_vtables();
    test_hmac_ct();
    // test_multihash();
}

#import "Basic";
#load "module.jai";

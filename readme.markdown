# BearSSL

BearSSL bindings for the Jai language.

# Usage

This depends on the static version of my [C interop module](https://github.com/judah-caruso/C) (already included).

```shell
# Manual management
mkdir vendor && cd vendor/
git clone https://github.com/judah-caruso/jai-bearssl BearSSL
```

# Notes

* Due to a temporary limitation in bindings for Jai, `initialize_global_vtables` must be called before BearSSL can be used.
* This isn't entirely finished. Only a few of the hashing algorithms + SSL/IO have been bound.

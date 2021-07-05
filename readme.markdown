# BearSSL

BearSSL bindings for the Jai language.

# Usage

This depends on the static version of my [C interop module](https://github.com/judah-caruso/C) (already included).

```shell
# Manual management
mkdir vendor && cd vendor/
git clone https://github.com/judah-caruso/jai-bearssl BearSSL
```

# Note

This isn't entirely finished. Only a few of the hashing algorithms + SSL/IO have been bound.
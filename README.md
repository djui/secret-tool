**WIP**

secret-tool
===========

OS X port of Gnome's [secret-tool](https://www.mankier.com/1/secret-tool).

Implements the same interface but uses Keychain as backend.

Installation
------------

    $ go get -v -u github.com/djui/secret-tool


TODO
----

- The interface is not quiet identical. For example only one attribute key value
  pair is supported, the rest is ignored.
- Error codes and messages are not identical
- The `--all` and `--unlock` flag for `search` are not supported.

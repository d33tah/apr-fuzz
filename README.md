apr-fuzz
========

This is an attempt at building a fuzzer that uses American Fuzzy Lop's
instrumentation, but in Python. Currently it doesn't do much.

Usage
=====

As of today, I hadn't rewritten afl-gcc/afl-as, so you need to use American
Fuzzy Lop's compiler/assembler wrappers to build an instrumented version
of your binaries. Once you do that, you can run them like this (assuming
that you're fuzzing GNU bison):

```
$ ./afr-fuzz /path/to/instrumented/bison /dev/stdin
New max score: 993
New max score: 1006
(list goes on...)
```

Yup! That's it. As I said, it currently doesn't do much.

Support
=======

My aim is to create an alternate implementation of AFL that is easier to
extend. If you know enough about AFL's fuzzing engine to help me rewrite it,
I'll be more than happy to accept a pull request.

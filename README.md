[![Build Status](https://travis-ci.org/d33tah/apr-fuzz.svg?branch=master)](https://travis-ci.org/d33tah/apr-fuzz)

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
max=1038   execs/s=457.37     execs=458        crashes=0      hangs=2      elapsed=a second
max=1042   execs/s=511.20     execs=1024       crashes=0      hangs=3      elapsed=2 seconds
max=1042   execs/s=454.00     execs=1364       crashes=0      hangs=7      elapsed=3 seconds
max=1042   execs/s=465.60     execs=1865       crashes=0      hangs=9      elapsed=4 seconds
max=1060   execs/s=488.54     execs=2446       crashes=0      hangs=10     elapsed=5 seconds
(list goes on...)
```

Yup! That's it. As I said, it currently doesn't do much.

Support
=======

My aim is to create an alternate implementation of AFL that is easier to
extend. If you know enough about AFL's fuzzing engine to help me rewrite it,
I'll be more than happy to accept a pull request.

#! /bin/sh
patchelf --set-interpreter libs/ld-2.23.so ./tvmc
patchelf --replace-needed libc.so.6 libs/libc-2.23.so ./tvmc
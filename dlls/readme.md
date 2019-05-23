These DLLS are know to work with this jwt library on this nim version on windows 64bit:

nim: Nim Compiler Version 0.19.9 Compiled at 2019-05-15
libcrypto-1_1-x64.dll - openssl-1.1.1b-win64-mingw - https://bintray.com/vszakats/generic/openssl/1.1.1b
libssl-1_1-x64.dll - openssl-1.1.1b-win64-mingw - https://bintray.com/vszakats/generic/openssl/1.1.1b
libeay32.dll - openssl-1.0.2r - https://indy.fulgan.com/SSL/

DLLs that ship with nim on 2019-05-15 are know to not work and crash during DLL load.
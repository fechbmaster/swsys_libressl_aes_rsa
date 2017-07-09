# swsys_libressl_aes_rsa
A little program that encrypt and decrypt messages using aes and rsa with LibreSSL library.

## Usage
To compile programs with LibreSSL, you simply add the include files and libraries to the compiler options. If you run the program and you have system-wide installation of LibreSSL, there are no further steps required, otherwise, you must inform the dynamic linker to add the OpenSSL libraries. Assuming, that LibreSSL is installed under /opt/libressl the command will be: LD_LIBRARY_PATH="/opt/libressl/lib" ./foo.  

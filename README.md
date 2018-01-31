# tinyca2
A modified version of TinyCA2
- based on the Debian version of the tinyca2
- Includes some changes in the signing hash selection
- Tweaked openssl.cnf template, at least to include URL for: CRL, AIA, OCSP
- deleted obsoleted entries from openssl.cnf , like ns*
- long random serial for every certificate
- compatible with openssl 1.x.x
- addedd support for certificate dates > 2039 (support long date format in index.txt)
- addedd support for ENV based DNS SAN entries
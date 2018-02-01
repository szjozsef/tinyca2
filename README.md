# tinyca2
A modified version of TinyCA2
- based on the Debian version of the tinyca2
- Includes some changes in the signing hash selection
- Tweaked openssl.cnf template, at least to include URL for: CRL, AIA, OCSP
- deleted obsoleted entries from openssl.cnf , like ns*
- long random serial for every certificate, serial always presented as hexa
- compatible with openssl 1.x.x
- added support for certificate dates > 2039 (support long date format in index.txt)
- added support for ENV based DNS SAN entries
- added crlnumber option to openssl.cnf (serial file for crl)

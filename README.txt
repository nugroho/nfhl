Nugroho Free Hash Library (NFHL)

* support SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 (FIPS-180)
* support MD4 (RFC-1320), MD5 (RFC-1321)
* support RMD-128, RMD-160 (Race Integrity Primitives Evaluation - RIPE)

The C implementation are implemented to verify the data flow as if it
were implemented in hardware design language. As most computer are
sequential machine then the implementation probably will have comparable
performance with other implementation. As there is no parallel execution
on most PC even though there is a multi processor machine but the kernel
probably will not process the code in parallel. The major design for the
implementation is base on shift register which implemented in C code.

API:

The hash functions ussually has three operand with the first operand is
a pointer to the message to be hashed then the second operand is the
message hash that will be computed and the third operand is a flag which
0 indicate initial hash operation and flag 1 indicate the next step for
hash operation. Its possible to always use 1 as the third operation with
condition that the message hash were initialized by standard initial
value not zero message hash.

SHA-224 and SHA-384 is just a variation of SHA-256 and SHA-512 the
different between the them are just from initial value assigned for
these standard. For SHA-224 and SHA-384 the fourth argument value is 8
and for SHA-256 and SHA-512 the fourth argument value is 0.

Endiannes:

SHA is implemented for big endian architecture therefore for little
endian machine that we commonly use we have to swap the 32-bit word
after reading the message from the machine. There is no need to swap for
algorithm in MD family, which apply for: MD4, MD5, RMD128, and RMD160.

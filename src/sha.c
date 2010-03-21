/* ------------------------------------------------------------------------
 * Copyright (c) 2010 Arif Endro Nugroho
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of Arif Endro Nugroho may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY ARIF ENDRO NUGROHO "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL ARIF ENDRO NUGROHO BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * End Of License.
 * ------------------------------------------------------------------------
 */
/*
 * Warning ISO STD C89 doesn't support long long use ISO STD C99
 * add options '-std=c99' in gcc.
 * mode: shift value `0' equal SHA-512
 *       shift value `8' equal SHA-384
 *       don't use other value that `0' or '8'
 */

#include "sha.h"

/*
#define ROTL (x,n) (unsigned long long)((x<<n)|(x>>(64-n)))
#define ROTR (x,n) (unsigned long long)((x>>n)|(x<<(64-n)))
#define Sigma0 (x) (unsigned long long)(ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
#define Sigma1 (x) (unsigned long long)(ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))
#define Tetha0 (x) (unsigned long long)(ROTR(x, 1) ^ ROTR(x, 8) ^ x>>7      )
#define Tetha1 (x) (unsigned long long)(ROTR(x,19) ^ ROTR(x,61) ^ x>>6      )
*/
#define SHA512Ch(x,y,z)  (unsigned long long)( (x & y)                ^ (~x & z)                                        )
#define SHA512Maj(x,y,z) (unsigned long long)( (x & y)                ^ ( x & z)               ^ (y & z)                )
#define SHA512Sigma0(x)  (unsigned long long)( ((x>>28)|(x<<(64-28))) ^ ((x>>34)|(x<<(64-34))) ^ ((x>>39)|(x<<(64-39))) )
#define SHA512Sigma1(x)  (unsigned long long)( ((x>>14)|(x<<(64-14))) ^ ((x>>18)|(x<<(64-18))) ^ ((x>>41)|(x<<(64-41))) )
#define SHA512Tetha0(x)  (unsigned long long)( ((x>> 1)|(x<<(64- 1))) ^ ((x>> 8)|(x<<(64- 8))) ^        x>>7            )
#define SHA512Tetha1(x)  (unsigned long long)( ((x>>19)|(x<<(64-19))) ^ ((x>>61)|(x<<(64-61))) ^        x>>6            )

void sha512(const unsigned long long *M, unsigned long long *IH, const unsigned long init, const unsigned long mode)
{
   const unsigned long long H[0x10] = {
      /* SHA-512 constant */
      0x6a09e667f3bcc908ULL,
      0xbb67ae8584caa73bULL,
      0x3c6ef372fe94f82bULL,
      0xa54ff53a5f1d36f1ULL,
      0x510e527fade682d1ULL,
      0x9b05688c2b3e6c1fULL,
      0x1f83d9abfb41bd6bULL,
      0x5be0cd19137e2179ULL,
      /* SHA-384 constant */
      0xcbbb9d5dc1059ed8ULL,
      0x629a292a367cd507ULL,
      0x9159015a3070dd17ULL,
      0x152fecd8f70e5939ULL,
      0x67332667ffc00b31ULL,
      0x8eb44a8768581511ULL,
      0xdb0c2e0d64f98fa7ULL,
      0x47b5481dbefa4fa4ULL
   };
   const unsigned long long K[0x50] = {
      0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
      0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
      0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
      0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
      
      0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
      0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
      0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
      0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
      
      0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
      0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
      0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
      0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
      
      0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
      0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
      0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
      0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
      
      0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
      0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
      0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
      0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
   };
   unsigned long long T1     = 0x0000000000000000ULL;
   unsigned long long T2     = 0x0000000000000000ULL;
   unsigned long long W[0x11]= {
   0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
   0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
   0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
   0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
   0x0000000000000000ULL
   };
   unsigned long long a      = 0x0000000000000000ULL;
   unsigned long long b      = 0x0000000000000000ULL;
   unsigned long long c      = 0x0000000000000000ULL;
   unsigned long long d      = 0x0000000000000000ULL;
   unsigned long long e      = 0x0000000000000000ULL;
   unsigned long long f      = 0x0000000000000000ULL;
   unsigned long long g      = 0x0000000000000000ULL;
   unsigned long long h      = 0x0000000000000000ULL;
   unsigned      long i      = 0;

   if(init) {
      a  =  H[0x0+mode];
      b  =  H[0x1+mode];
      c  =  H[0x2+mode];
      d  =  H[0x3+mode];
      e  =  H[0x4+mode];
      f  =  H[0x5+mode];
      g  =  H[0x6+mode];
      h  =  H[0x7+mode];
   } else {
      a  = IH[0x0];
      b  = IH[0x1];
      c  = IH[0x2];
      d  = IH[0x3];
      e  = IH[0x4];
      f  = IH[0x5];
      g  = IH[0x6];
      h  = IH[0x7];
   }

   for (i=0; i< 0x50; i++) {
      W[0x10] = W[0x0f];
      W[0x0f] = W[0x0e];
      W[0x0e] = W[0x0d];
      W[0x0d] = W[0x0c];
      W[0x0c] = W[0x0b];
      W[0x0b] = W[0x0a];
      W[0x0a] = W[0x09];
      W[0x09] = W[0x08];
      W[0x08] = W[0x07];
      W[0x07] = W[0x06];
      W[0x06] = W[0x05];
      W[0x05] = W[0x04];
      W[0x04] = W[0x03];
      W[0x03] = W[0x02];
      W[0x02] = W[0x01];
      W[0x01] = W[0x00];
      if (i < 0x10) { 
         W[0x00] = M[i%0x10];
      } else { 
         W[0x00] = SHA512Tetha1(W[0x02]) + W[0x07] + SHA512Tetha0(W[0x0f]) + W[0x10]; 
      }
      T1 = h  + SHA512Sigma1(e) +  SHA512Ch(e, f, g) + K[i] + W[0x00];
      T2 =      SHA512Sigma0(a) + SHA512Maj(a, b, c);
      h  = g;
      g  = f;
      f  = e;
      e  = d  + T1;
      d  = c;
      c  = b;
      b  = a;
      a  = T1 + T2;
   }

   if(init) {
      IH[0x0] = a  +  H[0x0+mode];
      IH[0x1] = b  +  H[0x1+mode];
      IH[0x2] = c  +  H[0x2+mode];
      IH[0x3] = d  +  H[0x3+mode];
      IH[0x4] = e  +  H[0x4+mode];
      IH[0x5] = f  +  H[0x5+mode];
      IH[0x6] = g  +  H[0x6+mode];
      IH[0x7] = h  +  H[0x7+mode];
   } else {
      IH[0x0] = a  + IH[0x0];
      IH[0x1] = b  + IH[0x1];
      IH[0x2] = c  + IH[0x2];
      IH[0x3] = d  + IH[0x3];
      IH[0x4] = e  + IH[0x4];
      IH[0x5] = f  + IH[0x5];
      IH[0x6] = g  + IH[0x6];
      IH[0x7] = h  + IH[0x7];
   }
}

#define SHA256Ch(x,y,z)  (unsigned long)( (x & y)                ^ (~x & z)                                        )
#define SHA256Maj(x,y,z) (unsigned long)( (x & y)                ^ ( x & z)               ^ (y & z)                )
#define SHA256Sigma0(x)  (unsigned long)( ((x>> 2)|(x<<(32- 2))) ^ ((x>>13)|(x<<(32-13))) ^ ((x>>22)|(x<<(32-22))) )
#define SHA256Sigma1(x)  (unsigned long)( ((x>> 6)|(x<<(32- 6))) ^ ((x>>11)|(x<<(32-11))) ^ ((x>>25)|(x<<(32-25))) )
#define SHA256Tetha0(x)  (unsigned long)( ((x>> 7)|(x<<(32- 7))) ^ ((x>>18)|(x<<(32-18))) ^        x>>3            )
#define SHA256Tetha1(x)  (unsigned long)( ((x>>17)|(x<<(32-17))) ^ ((x>>19)|(x<<(32-19))) ^        x>>10           )

void sha256(const unsigned long *M, unsigned long *IH, const unsigned long init, const unsigned long mode)
{
   const unsigned long H[0x10] = {
      /* SHA-256 constant */
      0x6a09e667UL,
      0xbb67ae85UL,
      0x3c6ef372UL,
      0xa54ff53aUL,
      0x510e527fUL,
      0x9b05688cUL,
      0x1f83d9abUL,
      0x5be0cd19UL,
      /* SHA-224 constant */
      0xc1059ed8UL,
      0x367cd507UL,
      0x3070dd17UL,
      0xf70e5939UL,
      0xffc00b31UL,
      0x68581511UL,
      0x64f98fa7UL,
      0xbefa4fa4UL
   };
   const unsigned long K[0x40] = {
      0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
      0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
      0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
      0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
      
      0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
      0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
      0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
      0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
      
      0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
      0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
      0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
      0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
      
      0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
      0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
      0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
      0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
   };
   unsigned long T1     = 0x00000000UL;
   unsigned long T2     = 0x00000000UL;
   unsigned long W[0x11]= {
      0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
      0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
      0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
      0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
      0x00000000UL
   };
   unsigned long a      = 0x00000000UL;
   unsigned long b      = 0x00000000UL;
   unsigned long c      = 0x00000000UL;
   unsigned long d      = 0x00000000UL;
   unsigned long e      = 0x00000000UL;
   unsigned long f      = 0x00000000UL;
   unsigned long g      = 0x00000000UL;
   unsigned long h      = 0x00000000UL;
   unsigned long i      = 0;


   if(init) {
      a  =  H[0x0+mode];
      b  =  H[0x1+mode];
      c  =  H[0x2+mode];
      d  =  H[0x3+mode];
      e  =  H[0x4+mode];
      f  =  H[0x5+mode];
      g  =  H[0x6+mode];
      h  =  H[0x7+mode];
   } else {
      a  = IH[0x0];
      b  = IH[0x1];
      c  = IH[0x2];
      d  = IH[0x3];
      e  = IH[0x4];
      f  = IH[0x5];
      g  = IH[0x6];
      h  = IH[0x7];
   }

   for (i=0; i< 0x40; i++) {
      W[0x10] = W[0x0f];
      W[0x0f] = W[0x0e];
      W[0x0e] = W[0x0d];
      W[0x0d] = W[0x0c];
      W[0x0c] = W[0x0b];
      W[0x0b] = W[0x0a];
      W[0x0a] = W[0x09];
      W[0x09] = W[0x08];
      W[0x08] = W[0x07];
      W[0x07] = W[0x06];
      W[0x06] = W[0x05];
      W[0x05] = W[0x04];
      W[0x04] = W[0x03];
      W[0x03] = W[0x02];
      W[0x02] = W[0x01];
      W[0x01] = W[0x00];
      if (i < 0x10) { 
         W[0x00] = M[i%0x10];
      } else { 
         W[0x00] = SHA256Tetha1(W[0x02]) + W[0x07] + SHA256Tetha0(W[0x0f]) + W[0x10]; 
      }
      T1 = h  + SHA256Sigma1(e) +  SHA256Ch(e, f, g) + K[i] + W[0x00];
      T2 =      SHA256Sigma0(a) + SHA256Maj(a, b, c);
      h  = g;
      g  = f;
      f  = e;
      e  = d  + T1;
      d  = c;
      c  = b;
      b  = a;
      a  = T1 + T2;
   }

   if(init) {
      IH[0x0] = a  +  H[0x0+mode];
      IH[0x1] = b  +  H[0x1+mode];
      IH[0x2] = c  +  H[0x2+mode];
      IH[0x3] = d  +  H[0x3+mode];
      IH[0x4] = e  +  H[0x4+mode];
      IH[0x5] = f  +  H[0x5+mode];
      IH[0x6] = g  +  H[0x6+mode];
      IH[0x7] = h  +  H[0x7+mode];
   } else {
      IH[0x0] = a  + IH[0x0];
      IH[0x1] = b  + IH[0x1];
      IH[0x2] = c  + IH[0x2];
      IH[0x3] = d  + IH[0x3];
      IH[0x4] = e  + IH[0x4];
      IH[0x5] = f  + IH[0x5];
      IH[0x6] = g  + IH[0x6];
      IH[0x7] = h  + IH[0x7];
   }
}

#define SHA1ROTL(x,n)      (unsigned long)((x<<n)|(x>>(32-n)))
#define SHA1ROTR(x,n)      (unsigned long)((x>>n)|(x<<(32-n)))
#define SHA1Ch(x,y,z)      (unsigned long)((x & y)  ^ (~x & z)           )
#define SHA1Maj(x,y,z)     (unsigned long)((x & y)  ^ ( x & z) ^ (y & z) )
#define SHA1Parity(x,y,z)  (unsigned long)(   x     ^     y    ^    z    )

void sha1(const unsigned long *M, unsigned long *IH, const unsigned long init)
{
   const unsigned long H[0x05] = {
      0x67452301UL,
      0xefcdab89UL,
      0x98badcfeUL,
      0x10325476UL,
      0xc3d2e1f0UL,
   };
   const unsigned long K[0x04] = {
      0x5a827999UL, /*  0 <= t <= 19 */
      0x6ed9eba1UL, /* 20 <= t <= 39 */
      0x8f1bbcdcUL, /* 40 <= t <= 59 */
      0xca62c1d6UL  /* 60 <= t <= 79 */
   };
   unsigned long T      = 0x00000000UL;
   unsigned long W[0x11]= {
      0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
      0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
      0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
      0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
      0x00000000UL
   };
   unsigned long a      = 0x00000000UL;
   unsigned long b      = 0x00000000UL;
   unsigned long c      = 0x00000000UL;
   unsigned long d      = 0x00000000UL;
   unsigned long e      = 0x00000000UL;
   unsigned long i      = 0;


   if(init) {
      a  =  H[0x0];
      b  =  H[0x1];
      c  =  H[0x2];
      d  =  H[0x3];
      e  =  H[0x4];
   } else {
      a  = IH[0x0];
      b  = IH[0x1];
      c  = IH[0x2];
      d  = IH[0x3];
      e  = IH[0x4];
   }

   for (i=0; i< 0x50; i++) { /* 80 round equal 0x50 */
      W[0x10] = W[0x0f];
      W[0x0f] = W[0x0e];
      W[0x0e] = W[0x0d];
      W[0x0d] = W[0x0c];
      W[0x0c] = W[0x0b];
      W[0x0b] = W[0x0a];
      W[0x0a] = W[0x09];
      W[0x09] = W[0x08];
      W[0x08] = W[0x07];
      W[0x07] = W[0x06];
      W[0x06] = W[0x05];
      W[0x05] = W[0x04];
      W[0x04] = W[0x03];
      W[0x03] = W[0x02];
      W[0x02] = W[0x01];
      W[0x01] = W[0x00];
      if (i < 0x10) { 
         W[0x00] = M[i%0x10];
      } else { 
         W[0x00] = SHA1ROTL((W[0x03] ^ W[0x08] ^ W[0x0e] ^ W[0x10]),  1); 
      }
      if        (i < 20) { 
      T  = SHA1ROTL(a,  5) +      SHA1Ch(b, c, d) + e + K[0x0] + W[0x00];
      } else if (i < 40) { 
      T  = SHA1ROTL(a,  5) +  SHA1Parity(b, c, d) + e + K[0x1] + W[0x00];
      } else if (i < 60) { 
      T  = SHA1ROTL(a,  5) +     SHA1Maj(b, c, d) + e + K[0x2] + W[0x00];
      } else if (i < 80) { 
      T  = SHA1ROTL(a,  5) +  SHA1Parity(b, c, d) + e + K[0x3] + W[0x00];
      }
      e  = d;
      d  = c;
      c  = SHA1ROTL(b, 30);
      b  = a;
      a  = T;
   }

   if(init) {
      IH[0x0] = a  +  H[0x0];
      IH[0x1] = b  +  H[0x1];
      IH[0x2] = c  +  H[0x2];
      IH[0x3] = d  +  H[0x3];
      IH[0x4] = e  +  H[0x4];
   } else {
      IH[0x0] = a  + IH[0x0];
      IH[0x1] = b  + IH[0x1];
      IH[0x2] = c  + IH[0x2];
      IH[0x3] = d  + IH[0x3];
      IH[0x4] = e  + IH[0x4];
   }
}

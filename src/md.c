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

#include "md.h"

#define MD4ROTL(x,n)  (unsigned long)((x<<n)|(x>>(32-n)))
#define MD4F(X,Y,Z)   (unsigned long)((X & Y) | (~X & Z))
#define MD4G(X,Y,Z)   (unsigned long)((X & Y) | (X & Z) | (Y & Z))
#define MD4H(X,Y,Z)   (unsigned long)( X ^ Y  ^       Z )

void md4(const unsigned long *X, unsigned long *IH, const unsigned long init)
{
   const unsigned long H[0x04] = {
      0x67452301UL,
      0xefcdab89UL,
      0x98badcfeUL,
      0x10325476UL
   };

   unsigned long A           = 0x00000000UL;
   unsigned long B           = 0x00000000UL;
   unsigned long C           = 0x00000000UL;
   unsigned long D           = 0x00000000UL;

   unsigned long k           =            0;
   unsigned long s           =            0;
   unsigned long i           =            0;

   unsigned long T           = 0x00000000UL;

   const unsigned int  K[0x30] = {
   0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
   0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
   
   0x0, 0x4, 0x8, 0xc, 0x1, 0x5, 0x9, 0xd,
   0x2, 0x6, 0xa, 0xe, 0x3, 0x7, 0xb, 0xf,
   
   0x0, 0x8, 0x4, 0xc, 0x2, 0xa, 0x6, 0xe,
   0x1, 0x9, 0x5, 0xd, 0x3, 0xb, 0x7, 0xf
   };

   if(init) {
      A  =  H[0x0];
      B  =  H[0x1];
      C  =  H[0x2];
      D  =  H[0x3];
   } else {
      A  = IH[0x0];
      B  = IH[0x1];
      C  = IH[0x2];
      D  = IH[0x3];
   }

   for (i=0; i< 0x30; i++) {
      if        (i < 0x10) { /* s =  3  7 11 19 = 3 3+4 3+4+4 3+4+4+7 */
      switch(i%0x04) {
         case 0x00: s =  3; break;
         case 0x01: s =  7; break;
         case 0x02: s = 11; break;
         case 0x03: s = 19; break;
      }
      k  = K[i];
      T  = MD4ROTL((A + MD4F(B,C,D) + X[k] + 0x00000000), s);
      } else if (i < 0x20) { /* s =  3  5  9 13 = 3 3+2 3+2+4 3+2+4+4 */
      switch(i%0x04) {
         case 0x00: s =  3; break;
         case 0x01: s =  5; break;
         case 0x02: s =  9; break;
         case 0x03: s = 13; break;
      }
      k  = K[i];
      T  = MD4ROTL((A + MD4G(B,C,D) + X[k] + 0x5a827999), s);
      } else if (i < 0x30) { /* s =  3  9 11 15 = 3 3+6 3+6+2 3+6+2+4 */
      switch(i%0x04) {
         case 0x00: s =  3; break;
         case 0x01: s =  9; break;
         case 0x02: s = 11; break;
         case 0x03: s = 15; break;
      }
      k  = K[i];
      T  = MD4ROTL((A + MD4H(B,C,D) + X[k] + 0x6ed9eba1), s);
      }
      A  = D;
      D  = C;
      C  = B;
      B  = T;
   }

   if(init) {
      IH[0x0] = A  +  H[0x0];
      IH[0x1] = B  +  H[0x1];
      IH[0x2] = C  +  H[0x2];
      IH[0x3] = D  +  H[0x3];
   } else {
      IH[0x0] = A  + IH[0x0];
      IH[0x1] = B  + IH[0x1];
      IH[0x2] = C  + IH[0x2];
      IH[0x3] = D  + IH[0x3];
   }
}

#define MD5ROTL(x,n)  (unsigned long)((x<<n)|(x>>(32-n)))
#define MD5F(X,Y,Z)   (unsigned long)((X & Y) | (~X & Z))
#define MD5G(X,Y,Z)   (unsigned long)((X & Z) | (~Z & Y))
#define MD5H(X,Y,Z)   (unsigned long)( X ^ Y  ^       Z )
#define MD5I(X,Y,Z)   (unsigned long)( Y ^      (~Z | X))

void md5(const unsigned long *X, unsigned long *IH, const unsigned long init)
{
   const unsigned long H[0x04] = {
      0x67452301UL,
      0xefcdab89UL,
      0x98badcfeUL,
      0x10325476UL
   };
   const unsigned long K[0x40] = {
      0xd76aa478UL, 0xe8c7b756UL, 0x242070dbUL, 0xc1bdceeeUL,
      0xf57c0fafUL, 0x4787c62aUL, 0xa8304613UL, 0xfd469501UL,
      0x698098d8UL, 0x8b44f7afUL, 0xffff5bb1UL, 0x895cd7beUL,
      0x6b901122UL, 0xfd987193UL, 0xa679438eUL, 0x49b40821UL,
   
      0xf61e2562UL, 0xc040b340UL, 0x265e5a51UL, 0xe9b6c7aaUL,
      0xd62f105dUL, 0x02441453UL, 0xd8a1e681UL, 0xe7d3fbc8UL,
      0x21e1cde6UL, 0xc33707d6UL, 0xf4d50d87UL, 0x455a14edUL,
      0xa9e3e905UL, 0xfcefa3f8UL, 0x676f02d9UL, 0x8d2a4c8aUL,
   
      0xfffa3942UL, 0x8771f681UL, 0x6d9d6122UL, 0xfde5380cUL,
      0xa4beea44UL, 0x4bdecfa9UL, 0xf6bb4b60UL, 0xbebfbc70UL,
      0x289b7ec6UL, 0xeaa127faUL, 0xd4ef3085UL, 0x04881d05UL,
      0xd9d4d039UL, 0xe6db99e5UL, 0x1fa27cf8UL, 0xc4ac5665UL,
   
      0xf4292244UL, 0x432aff97UL, 0xab9423a7UL, 0xfc93a039UL,
      0x655b59c3UL, 0x8f0ccc92UL, 0xffeff47dUL, 0x85845dd1UL,
      0x6fa87e4fUL, 0xfe2ce6e0UL, 0xa3014314UL, 0x4e0811a1UL,
      0xf7537e82UL, 0xbd3af235UL, 0x2ad7d2bbUL, 0xeb86d391UL
   };
   unsigned long A           = 0x00000000UL;
   unsigned long B           = 0x00000000UL;
   unsigned long C           = 0x00000000UL;
   unsigned long D           = 0x00000000UL;

   unsigned long k           =            0;
   unsigned long s           =            0;
   unsigned long i           =            0;

   unsigned long T           = 0x00000000UL;
   unsigned long ii          =            0;
   unsigned long iii         =            0;

   if(init) {
      A  =  H[0x0];
      B  =  H[0x1];
      C  =  H[0x2];
      D  =  H[0x3];
   } else {
      A  = IH[0x0];
      B  = IH[0x1];
      C  = IH[0x2];
      D  = IH[0x3];
   }

   for (i=0; i< 0x40; i++) {
      if        (i < 0x10) { /* s =  7 12 17 22 = 7 7+5 7+5+5 7+5+5+5 */
      s  = 7; iii = 5; for (ii=0; ii<(i%0x04); ii++) s += iii  ;
      k  = ((1*(i%0x10)) + 0) % 0x10;
      T  = B + MD5ROTL((A + MD5F(B,C,D) + X[k] + K[i]), s);
      } else if (i < 0x20) { /* s =  5  9 14 20 = 5 5+4 5+4+5 5+4+5+6 */
      s  = 5; iii = 4; for (ii=0; ii<(i%0x04); ii++) s += iii++;
      k  = ((5*(i%0x10)) + 1) % 0x10;
      T  = B + MD5ROTL((A + MD5G(B,C,D) + X[k] + K[i]), s);
      } else if (i < 0x30) { /* s =  4 11 16 23 = 4 4+7 4+7+5 4+7+5+7 */
      s  = 4;          for (ii=0; ii<(i%0x04); ii++) s += (ii%0x2) ? (unsigned long )5 : (unsigned long )7 ;
      k  = ((3*(i%0x10)) + 5) % 0x10;
      T  = B + MD5ROTL((A + MD5H(B,C,D) + X[k] + K[i]), s);
      } else               { /* s =  6 10 15 21 = 6 6+4 6+4+5 6+4+5+6 */
      s  = 6; iii = 4; for (ii=0; ii<(i%0x04); ii++) s += iii++;
      k  = ((7*(i%0x10)) + 0) % 0x10;
      T  = B + MD5ROTL((A + MD5I(B,C,D) + X[k] + K[i]), s);
      }
      A  = D;
      D  = C;
      C  = B;
      B  = T;
   }

   if(init) {
      IH[0x0] = A  +  H[0x0];
      IH[0x1] = B  +  H[0x1];
      IH[0x2] = C  +  H[0x2];
      IH[0x3] = D  +  H[0x3];
   } else {
      IH[0x0] = A  + IH[0x0];
      IH[0x1] = B  + IH[0x1];
      IH[0x2] = C  + IH[0x2];
      IH[0x3] = D  + IH[0x3];
   }
}

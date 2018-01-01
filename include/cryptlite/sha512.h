/*
The MIT License

Copyright (c) 2011 lyo.kato@gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#pragma once
#include <string>
#include <cassert>
#include <sstream>
#include <iomanip>
#include <cryptlite/base64.h>
#include <boost/cstdint.hpp>

namespace cryptlite {

#define SHA2_SHFR(bits,word)    ((word) >> (bits))
#define SHA2_ROTR(bits,word)   (((word) >> (bits)) | ((word) << ((sizeof(word) << 3) - (bits))))
#define SHA2_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA2_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA512_F1(x) (SHA2_ROTR(28, x) ^ SHA2_ROTR(34, x) ^ SHA2_ROTR(39, x))
#define SHA512_F2(x) (SHA2_ROTR(14, x) ^ SHA2_ROTR(18, x) ^ SHA2_ROTR(41, x))
#define SHA512_F3(x) (SHA2_ROTR( 1, x) ^ SHA2_ROTR( 8, x) ^ SHA2_SHFR( 7, x))
#define SHA512_F4(x) (SHA2_ROTR(19, x) ^ SHA2_ROTR(61, x) ^ SHA2_SHFR( 6, x))
#define SHA2_UNPACK32(x, str)                 \
{                                             \
    *((str) + 3) = static_cast<boost::uint8_t>((x)      );       \
    *((str) + 2) = static_cast<boost::uint8_t>((x) >>  8);       \
    *((str) + 1) = static_cast<boost::uint8_t>((x) >> 16);       \
    *((str) + 0) = static_cast<boost::uint8_t>((x) >> 24);       \
}
#define SHA2_UNPACK64(x, str)                 \
{                                             \
    *((str) + 7) = static_cast<boost::uint8_t>((x)      );       \
    *((str) + 6) = static_cast<boost::uint8_t>((x) >>  8);       \
    *((str) + 5) = static_cast<boost::uint8_t>((x) >> 16);       \
    *((str) + 4) = static_cast<boost::uint8_t>((x) >> 24);       \
    *((str) + 3) = static_cast<boost::uint8_t>((x) >> 32);       \
    *((str) + 2) = static_cast<boost::uint8_t>((x) >> 40);       \
    *((str) + 1) = static_cast<boost::uint8_t>((x) >> 48);       \
    *((str) + 0) = static_cast<boost::uint8_t>((x) >> 56);       \
}
#define SHA2_PACK64(str, x)                   \
{                                             \
    *(x) =   (static_cast<boost::uint64_t>(*((str) + 7))      )    \
           | (static_cast<boost::uint64_t>(*((str) + 6)) <<  8)    \
           | (static_cast<boost::uint64_t>(*((str) + 5)) << 16)    \
           | (static_cast<boost::uint64_t>(*((str) + 4)) << 24)    \
           | (static_cast<boost::uint64_t>(*((str) + 3)) << 32)    \
           | (static_cast<boost::uint64_t>(*((str) + 2)) << 40)    \
           | (static_cast<boost::uint64_t>(*((str) + 1)) << 48)    \
           | (static_cast<boost::uint64_t>(*((str) + 0)) << 56);   \
}

class sha512 {

 public:

  static constexpr unsigned int BLOCK_SIZE     = 128;
  static constexpr unsigned int HASH_SIZE      = 64;
  static constexpr unsigned int HASH_SIZE_BITS = HASH_SIZE * 8;

  static void hash(const std::string& s, boost::uint8_t digest[HASH_SIZE])
  {
    sha512 ctx;
    ctx.input(reinterpret_cast<const boost::uint8_t*>(s.c_str()), s.size());
    ctx.result(digest);
  }

  static std::string hash_hex(const std::string& s) 
  {
    int i;
    boost::uint8_t digest[HASH_SIZE];
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    sha512 ctx;
    ctx.input(reinterpret_cast<const boost::uint8_t*>(s.c_str()), s.size());
    ctx.result(digest);
    for (i = 0; i < HASH_SIZE; ++i)
      oss << std::setw(2) << (digest[i] & 0xff);
    oss << std::dec;
    return oss.str();
  }

  static std::string hash_base64(const std::string& s) {
    boost::uint8_t digest[HASH_SIZE];
    sha512 ctx;
    ctx.input(reinterpret_cast<const boost::uint8_t*>(s.c_str()), s.size());
    ctx.result(digest);
    return base64::encode_from_array(digest, HASH_SIZE);
  }

  sha512() 
    : computed_(false)
    , corrupted_(false)
    , len_(0)
    , tot_len_(0)
  {
    intermediate_hash_[0] = 0x6a09e667f3bcc908ULL; 
    intermediate_hash_[1] = 0xbb67ae8584caa73bULL;
    intermediate_hash_[2] = 0x3c6ef372fe94f82bULL; 
    intermediate_hash_[3] = 0xa54ff53a5f1d36f1ULL;
    intermediate_hash_[4] = 0x510e527fade682d1ULL; 
    intermediate_hash_[5] = 0x9b05688c2b3e6c1fULL; 
    intermediate_hash_[6] = 0x1f83d9abfb41bd6bULL; 
    intermediate_hash_[7] = 0x5be0cd19137e2179ULL;
  }

  ~sha512() { }

  void reset() 
  {
    computed_            = false;
    corrupted_           = false;
    len_                 = 0;
    tot_len_             = 0;

    intermediate_hash_[0] = 0x6a09e667f3bcc908ULL; 
    intermediate_hash_[1] = 0xbb67ae8584caa73bULL;
    intermediate_hash_[2] = 0x3c6ef372fe94f82bULL; 
    intermediate_hash_[3] = 0xa54ff53a5f1d36f1ULL;
    intermediate_hash_[4] = 0x510e527fade682d1ULL; 
    intermediate_hash_[5] = 0x9b05688c2b3e6c1fULL; 
    intermediate_hash_[6] = 0x1f83d9abfb41bd6bULL; 
    intermediate_hash_[7] = 0x5be0cd19137e2179ULL;
  }

  void input(const boost::uint8_t *message_array, unsigned int length)
  {
    assert(message_array);
    if (computed_ || corrupted_ || !length)
        return;

    unsigned int tmp_len = BLOCK_SIZE - len_;
    unsigned int rem_len = length < tmp_len ? length : tmp_len;
    memcpy(&message_block_[len_], message_array, rem_len);
    if (len_ + length < BLOCK_SIZE) {
        len_ += length;
        return;
    }
    unsigned int new_len = length - rem_len;
    unsigned int block_nb = new_len / BLOCK_SIZE;
    const boost::uint8_t *shifted_message = message_array + rem_len;
    transform(message_block_, 1);
    transform(shifted_message, block_nb);
    rem_len = new_len % BLOCK_SIZE;
    memcpy(message_block_, &shifted_message[block_nb << 7], rem_len);
    len_ = rem_len;
    tot_len_ += (block_nb + 1) << 7;
  }

  void result(boost::uint8_t digest[HASH_SIZE])
  {
    assert(digest);
    if (corrupted_)
      return;
    if (!computed_)
      finalize(0x80);

    for (int i = 0; i < 8; i++) {
        SHA2_UNPACK64(intermediate_hash_[i], &digest[i << 3]);
    }
  }

private:
  boost::uint64_t intermediate_hash_[HASH_SIZE/8];
  boost::uint32_t len_;
  boost::uint32_t tot_len_;
  boost::uint8_t message_block_[2 * BLOCK_SIZE];
  bool computed_;
  bool corrupted_;

  void finalize(boost::uint8_t pad_byte)
  {
    unsigned int block_nb = 1 + ((BLOCK_SIZE - 17) < (len_ % BLOCK_SIZE));
    unsigned int len_b = (tot_len_ + len_) << 3;
    unsigned int pm_len = block_nb << 7;
    memset(message_block_ + len_, 0, pm_len - len_);
    message_block_[len_] = pad_byte;
    SHA2_UNPACK32(len_b, message_block_ + pm_len - 4);
    transform(message_block_, block_nb);

    memset(message_block_, 0, sizeof(message_block_));
    len_ = 0;
    tot_len_ = 0;
    computed_ = true;
  }

  void transform(const boost::uint8_t *message_array, unsigned int block_nb)
  {
    static const boost::uint64_t K[80] = {
		 0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
		 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
		 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
		 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
		 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
		 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
		 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
		 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
		 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
		 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
		 0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
		 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
		 0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
		 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
		 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
		 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
		 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
		 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
		 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
		 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
		 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
		 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
		 0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
		 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
		 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
		 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
		 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
		 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
		 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
		 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
		 0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
		 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
		 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
		 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
		 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
		 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
		 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
		 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
		 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
		 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };
    boost::uint64_t w[80];
    boost::uint64_t wv[8];
    boost::uint64_t t1, t2;
    int j;
    for (int i = 0; i < (int) block_nb; i++) {
        const boost::uint8_t *sub_block = message_array + (i << 7);
        for (j = 0; j < 16; j++) {
            SHA2_PACK64(&sub_block[j << 3], &w[j]);
        }
        for (j = 16; j < 80; j++) {
            w[j] =  SHA512_F4(w[j -  2]) + w[j -  7] + SHA512_F3(w[j - 15]) + w[j - 16];
        }
        for (j = 0; j < 8; j++) {
            wv[j] = intermediate_hash_[j];
        }
        for (j = 0; j < 80; j++) {
            t1 = wv[7] + SHA512_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
                + K[j] + w[j];
            t2 = SHA512_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        for (j = 0; j < 8; j++) {
            intermediate_hash_[j] += wv[j];
        }
    }
  }
}; // end of class

}  // end of namespace

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

#ifndef _CRYPTLITE_MD5_H_
#define _CRYPTLITE_MD5_H_
#include <boost/cstdint.hpp>

namespace cryptlite {

class md5 {

 public:

  static const unsigned int BLOCK_SIZE     = 64;
  static const unsigned int HASH_SIZE      = 16;
  static const unsigned int HASH_SIZE_BITS = 128;

  md5() 
    : computed_(false)
    , length_low_(0)
    , length_high_(0)
    , message_block_index_(0)
  { 
    intermediate_hash_[0] = 0x67452301;
    intermediate_hash_[1] = 0xEFCDAB89;
    intermediate_hash_[2] = 0x98BADCFE;
    intermediate_hash_[3] = 0x10325476;
  }

  ~md5() { }

  void reset()
  {
    intermediate_hash_[0] = 0x67452301;
    intermediate_hash_[1] = 0xEFCDAB89;
    intermediate_hash_[2] = 0x98BADCFE;
    intermediate_hash_[3] = 0x10325476;

    computed_            = false;
    length_low_          = 0;
    length_high_         = 0;
    message_block_index_ = 0;
  }

  void input(const boost::uint8_t* message_array, unsigned int length)
  {
    while (length--) {
      message_block_[message_block_index_++] = (*message_array & 0xFF);
      if ()
        process_message_block();
      ++message_array;
    }
  }

  void final_bits(const boost::uint8_t message_bits, unsigned int length)
  {
    if (!length)
      return;
  }

  void result(boost::uint8_t digest[HASH_SIZE])
  {
    assert(digest);
    digest[ 0] = static_cast<boost::uint8_t>(intermediate_hash_[0] >> 24);
    digest[ 1] = static_cast<boost::uint8_t>(intermediate_hash_[0] >> 16);
    digest[ 2] = static_cast<boost::uint8_t>(intermediate_hash_[0] >>  8);
    digest[ 3] = static_cast<boost::uint8_t>(intermediate_hash_[0]      );
    digest[ 4] = static_cast<boost::uint8_t>(intermediate_hash_[1] >> 24);
    digest[ 5] = static_cast<boost::uint8_t>(intermediate_hash_[1] >> 16);
    digest[ 6] = static_cast<boost::uint8_t>(intermediate_hash_[1] >>  8);
    digest[ 7] = static_cast<boost::uint8_t>(intermediate_hash_[1]      );
    digest[ 8] = static_cast<boost::uint8_t>(intermediate_hash_[2] >> 24);
    digest[ 9] = static_cast<boost::uint8_t>(intermediate_hash_[2] >> 16);
    digest[10] = static_cast<boost::uint8_t>(intermediate_hash_[2] >>  8);
    digest[11] = static_cast<boost::uint8_t>(intermediate_hash_[2]      );
    digest[12] = static_cast<boost::uint8_t>(intermediate_hash_[3] >> 24);
    digest[13] = static_cast<boost::uint8_t>(intermediate_hash_[3] >> 16);
    digest[14] = static_cast<boost::uint8_t>(intermediate_hash_[3] >>  8);
    digest[15] = static_cast<boost::uint8_t>(intermediate_hash_[3]      );
  }

 private:
  boost::uint32_t intermediate_hash_[HASH_SIZE/4];
  boost::uint32_t length_low_;
  boost::uint32_t length_high_;
  boost::int_least16_t message_block_index_;
  boost::uint8_t message_block_[BLOCK_SIZE];
  bool computed_;

  void pad_message(boost::uint8_t pad_byte)
  {

  }

  void finalize(boost::uint8_t pad_byte)
  {
    int i;
    pad_message(pad_byte);
    for (i = 0; i < BLOCK_SIZE; ++i)
      message_block_[i] = 0;
    length_low_  = 0;
    length_high_ = 0;
    computed_    = true;
  }

  void process_message_block()
  {
    message_block_index_ = 0;
  }
}; // end of class

}  // end of namespace

#endif

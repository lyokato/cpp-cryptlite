#include "cryptlite/sha1.h"
#include "cryptlite/sha256.h"
#include "cryptlite/hmac.h"
#include <gtest/gtest.h>

using namespace cryptlite;

TEST(hmacTest, testCalc)
{
  EXPECT_EQ("2dd4349aa2f20d7a1d6bafbc5807fcb5c82520c1", hmac<sha1>::calc_hex("base", "key"));
  EXPECT_EQ("023ce1cd22309757263392d7b68c82405bf45daf686e825260e1edd1adb83578", hmac<sha256>::calc_hex("base", "key"));
}


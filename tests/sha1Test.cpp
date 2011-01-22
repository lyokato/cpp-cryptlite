#include "cryptlite/sha1.h"
#include <gtest/gtest.h>

using namespace cryptlite;

TEST(sha1Test, hash)
{
  EXPECT_EQ("3b2c6c10d0e78072d14e02cc4c587814d0f10f3a", sha1::hash_hex("hogehoge"));
  EXPECT_EQ("3773dea65156909838fa6c22825cafe090ff8030", sha1::hash_hex("foo bar"));

  EXPECT_EQ("N3PeplFWkJg4+mwiglyv4JD/gDA=", sha1::hash_base64("foo bar"));
}


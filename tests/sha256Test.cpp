#include "cryptlite/sha256.h"
#include <gtest/gtest.h>

using namespace cryptlite;

TEST(sha256Test, testHash)
{
  EXPECT_EQ("4c716d4cf211c7b7d2f3233c941771ad0507ea5bacf93b492766aa41ae9f720d", sha256::hash_hex("hogehoge"));
  EXPECT_EQ("fbc1a9f858ea9e177916964bd88c3d37b91a1e84412765e29950777f265c4b75", sha256::hash_hex("foo bar"));
  EXPECT_EQ("+8Gp+Fjqnhd5FpZL2Iw9N7kaHoRBJ2XimVB3fyZcS3U=", sha256::hash_base64("foo bar"));
}


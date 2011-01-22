#include "cryptlite/base64.h"
#include <gtest/gtest.h>

using namespace cryptlite;

TEST(base64Test, testEncode)
{
  EXPECT_EQ("aG9nZWhvZ2UgZm9vIGJhciBidXogZm9vIGJhciBidXogaGVsbG8sIHdvcmxkIQ==", base64::encode("hogehoge foo bar buz foo bar buz hello, world!"));
  EXPECT_EQ("hogehoge foo bar buz foo bar buz hello, world!", base64::decode("aG9nZWhvZ2UgZm9vIGJhciBidXogZm9vIGJhciBidXogaGVsbG8sIHdvcmxkIQ=="));
}


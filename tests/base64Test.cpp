#include "cryptlite/base64.h"
#include <gtest/gtest.h>
#include <boost/shared_array.hpp>
#include <boost/tuple/tuple.hpp>
#include <string>

using namespace cryptlite;

TEST(base64Test, testEncode)
{
  EXPECT_EQ("aG9nZWhvZ2UgZm9vIGJhciBidXogZm9vIGJhciBidXogaGVsbG8sIHdvcmxkIQ==", base64::encode_from_string("hogehoge foo bar buz foo bar buz hello, world!"));
  //EXPECT_EQ("hogehoge foo bar buz foo bar buz hello, world!", base64::decode("aG9nZWhvZ2UgZm9vIGJhciBidXogZm9vIGJhciBidXogaGVsbG8sIHdvcmxkIQ=="));

  std::string decoded_str;
  base64::decode("aG9nZWhvZ2UgZm9vIGJhciBidXogZm9vIGJhciBidXogaGVsbG8sIHdvcmxkIQ==", decoded_str);
  EXPECT_EQ("hogehoge foo bar buz foo bar buz hello, world!", decoded_str);

  std::vector<unsigned char> decoded_v;
  base64::decode("aG9nZWhvZ2UgZm9vIGJhciBidXogZm9vIGJhciBidXogaGVsbG8sIHdvcmxkIQ==", decoded_v);
  std::vector<unsigned char>::const_iterator iter = decoded_v.begin();
  unsigned char c1 = *iter++;
  unsigned char c2 = *iter++;
  unsigned char c3 = *iter++;
  unsigned char c4 = *iter++;
  EXPECT_EQ(46, decoded_v.size());
  EXPECT_EQ('h', c1);
  EXPECT_EQ('o', c2);
  EXPECT_EQ('g', c3);
  EXPECT_EQ('e', c4);

  boost::shared_array<unsigned char> arr;
  std::size_t len;
  boost::tie(arr, len) = base64::decode_to_array("aG9nZWhvZ2UgZm9vIGJhciBidXogZm9vIGJhciBidXogaGVsbG8sIHdvcmxkIQ==");
  EXPECT_EQ(46, len);
  EXPECT_EQ('h', static_cast<char>(arr[0]));
  EXPECT_EQ('o', static_cast<char>(arr[1]));
  EXPECT_EQ('g', static_cast<char>(arr[2]));
  EXPECT_EQ('e', static_cast<char>(arr[3]));
}


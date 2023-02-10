#pragma once

#include <string>
#include <vector>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <map>
#include "util.hpp"

namespace url
{
    namespace detail
    {
        inline char from_hex(char ch)
        {
          return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
        }
    }

    // Refactored from https://stackoverflow.com/a/32595923/12282075
    inline std::string decode(const std::string &text)
    {
      std::ostringstream escaped;
      escaped.fill('0');
      for (auto i = text.begin(), n = text.end(); i != n; ++i)
      {
        std::string::value_type c = (*i);
        if (c == '%' && i[1] && i[2])
        {
          char h = detail::from_hex(i[1]) << 4 | detail::from_hex(i[2]);
          escaped << h;
          i += 2;
        } else if (c == '+')
          escaped << ' ';
        else
          escaped << c;
      }
      return escaped.str();
    }

    // Taken from OpenSpot (my c++ lib)
    template<typename T>
    inline typename std::unordered_map<std::string, T>::const_iterator
    find_match(const std::string &uri, const std::unordered_map<std::string, T> &patterns, std::unordered_map<std::string, std::string> &params)
    {
      std::size_t proto_len = uri.find("://");
      if (proto_len == std::string::npos)
        return patterns.end();
      std::string proto = uri.substr(0, proto_len + 3);
      std::string urn = uri.substr(proto_len + 3);
      std::vector<std::string> urn_parts = util::split_str(urn, '/');
      std::size_t urn_parts_size = urn_parts.size();
      for (auto it = patterns.begin(); it != patterns.end(); it++)
      {
        if (it->first.find(proto) != 0)
          continue;
        std::vector<std::string> pattern_parts = util::split_str(it->first.substr(proto_len + 3), '/');
        if (pattern_parts.size() != urn_parts_size)
          continue;
        std::unordered_map<std::string, std::string> pattern_params;
        bool match = true;
        for (std::size_t i = 0; i < pattern_parts.size(); i++)
        {
          if (pattern_parts[i][0] == '[' && pattern_parts[i][pattern_parts[i].length() - 1] == ']')
          {
            std::string capture_name = pattern_parts[i].substr(1, pattern_parts[i].length() - 2);
            pattern_params.emplace(capture_name, decode(urn_parts[i]));
          } else if (pattern_parts[i] != urn_parts[i])
          {
            match = false;
            break;
          }
        }
        if (!match)
          continue;
        params = pattern_params;
        return it;
      }
      return patterns.end();
    };
}

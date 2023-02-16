#pragma once

#include <string>
#include <filesystem>

#ifdef UNICODE
#define LOGG_PATH(p) p.generic_wstring().c_str()
#else
#define LOGG_PATH(p) p.generic_string().c_str()
#endif

namespace logg
{
#ifdef UNICODE
    typedef std::wstring string;
    typedef std::wifstream ifstream;
    typedef std::wofstream ofstream;
    typedef std::wstringstream stringstream;
#else
    typedef std::string string;
    typedef std::ifstream ifstream;
    typedef std::ofstream ofstream;
    typedef std::stringstream stringstream;
#endif

    namespace detail
    {
        inline void fix_for_unicode(const char *str)
        {
#ifndef UNICODE
          return;
#endif
          bool is_escaped = false;
          char *c = const_cast<char *>(str);
          while (c)
          {
            if (*c == '%')
            {
              is_escaped = true;
            }
            if (is_escaped && *c == 's')
            {
              *c = 'S';
            }
            c++;
          }
        }
    }

    template<typename... Arg>
    inline void log(const char *fmt, Arg... args)
    {
      detail::fix_for_unicode(fmt);
      fprintf(stdout, fmt, std::forward<Arg>(args)...);
      fflush(stdout);
    };

    template<typename... Arg>
    inline void error(const char *fmt, Arg... args)
    {
      detail::fix_for_unicode(fmt);
      fprintf(stderr, fmt, std::forward<Arg>(args)...);
      fflush(stderr);
    };
}

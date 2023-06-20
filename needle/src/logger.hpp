#pragma once

#include <cstdio>
#include <utility>
#include <string>
#include <unordered_map>

#ifdef _WIN32

#include <windows.h>

#endif

namespace logger
{
  enum class option : std::uint64_t
  {
    DEFAULT = 1LL << 0,
    BOLD = 1LL << 1,
    UNDERLINE = 1LL << 2,
    NO_UNDERLINE = 1LL << 3,

    FG_BLACK = 1LL << 4,
    BG_BLACK = 1LL << 5,
    FG_WHITE = 1LL << 6,
    BG_WHITE = 1LL << 7,

    FG_DARK_RED = 1LL << 8,
    BG_DARK_RED = 1LL << 9,
    FG_LIGHT_RED = 1LL << 10,
    BG_LIGHT_RED = 1LL << 11,

    FG_DARK_GREEN = 1LL << 12,
    BG_DARK_GREEN = 1LL << 13,
    FG_LIGHT_GREEN = 1LL << 14,
    BG_LIGHT_GREEN = 1LL << 15,

    FG_DARK_YELLOW = 1LL << 16,
    BG_DARK_YELLOW = 1LL << 17,
    FG_LIGHT_YELLOW = 1LL << 18,
    BG_LIGHT_YELLOW = 1LL << 19,

    FG_DARK_BLUE = 1LL << 20,
    BG_DARK_BLUE = 1LL << 21,
    FG_LIGHT_BLUE = 1LL << 22,
    BG_LIGHT_BLUE = 1LL << 23,

    FG_DARK_MAGENTA = 1LL << 24,
    BG_DARK_MAGENTA = 1LL << 25,
    FG_LIGHT_MAGENTA = 1LL << 26,
    BG_LIGHT_MAGENTA = 1LL << 27,

    FG_DARK_CYAN = 1LL << 28,
    BG_DARK_CYAN = 1LL << 29,
    FG_LIGHT_CYAN = 1LL << 30,
    BG_LIGHT_CYAN = 1LL << 31,
    LAST = 1LL << 32
  };

  inline constexpr logger::option
  operator&(logger::option x, logger::option y)
  {
    return static_cast<logger::option>(static_cast<std::underlying_type_t<logger::option>>(x) &
                                       static_cast<std::underlying_type_t<logger::option>>(y));
  }

  inline constexpr logger::option
  operator|(logger::option x, logger::option y)
  {
    return static_cast<logger::option>(static_cast<std::underlying_type_t<logger::option>>(x) |
                                       static_cast<std::underlying_type_t<logger::option>>(y));
  }

  inline constexpr logger::option
  operator^(logger::option x, logger::option y)
  {
    return static_cast<logger::option>(static_cast<std::underlying_type_t<logger::option>>(x) ^
                                       static_cast<std::underlying_type_t<logger::option>>(y));
  }

  inline constexpr logger::option
  operator~(logger::option x)
  {
    return static_cast<logger::option>(~static_cast<std::underlying_type_t<logger::option>>(x));
  }

  inline logger::option &
  operator&=(logger::option &x, logger::option y)
  {
    x = x & y;
    return x;
  }

  inline logger::option &
  operator|=(logger::option &x, logger::option y)
  {
    x = x | y;
    return x;
  }

  inline logger::option &
  operator^=(logger::option &x, logger::option y)
  {
    x = x ^ y;
    return x;
  }

  namespace detail
  {
#ifdef _WIN32
    inline bool is_console_intitiated = false;
    inline FILE *our_out = nullptr;
    inline FILE *our_err = nullptr;

    inline const std::unordered_map<logger::option, WORD> option_codes = {
        {logger::option::DEFAULT, 0},
        {logger::option::BOLD, 0},
        {logger::option::UNDERLINE, COMMON_LVB_UNDERSCORE},
        {logger::option::NO_UNDERLINE, 0},

        {logger::option::FG_BLACK, 0},
        {logger::option::BG_BLACK, 0},
        {logger::option::FG_WHITE, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE},
        {logger::option::BG_WHITE, BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE},

        {logger::option::FG_DARK_RED, FOREGROUND_RED},
        {logger::option::BG_DARK_RED, BACKGROUND_RED},
        {logger::option::FG_LIGHT_RED, FOREGROUND_RED | FOREGROUND_INTENSITY},
        {logger::option::BG_LIGHT_RED, BACKGROUND_RED | BACKGROUND_INTENSITY},

        {logger::option::FG_DARK_GREEN, FOREGROUND_GREEN},
        {logger::option::BG_DARK_GREEN, BACKGROUND_GREEN},
        {logger::option::FG_LIGHT_GREEN, FOREGROUND_GREEN | FOREGROUND_INTENSITY},
        {logger::option::BG_LIGHT_GREEN, BACKGROUND_GREEN | BACKGROUND_INTENSITY},

        {logger::option::FG_DARK_YELLOW, FOREGROUND_RED | FOREGROUND_GREEN},
        {logger::option::BG_DARK_YELLOW, BACKGROUND_RED | BACKGROUND_GREEN},
        {logger::option::FG_LIGHT_YELLOW, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY},
        {logger::option::BG_LIGHT_YELLOW, BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_INTENSITY},

        {logger::option::FG_DARK_BLUE, FOREGROUND_BLUE},
        {logger::option::BG_DARK_BLUE, BACKGROUND_BLUE},
        {logger::option::FG_LIGHT_BLUE, FOREGROUND_BLUE | FOREGROUND_INTENSITY},
        {logger::option::BG_LIGHT_BLUE, BACKGROUND_BLUE | BACKGROUND_INTENSITY},

        {logger::option::FG_DARK_MAGENTA, FOREGROUND_RED | FOREGROUND_BLUE},
        {logger::option::BG_DARK_MAGENTA, BACKGROUND_RED | BACKGROUND_BLUE},
        {logger::option::FG_LIGHT_MAGENTA, FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY},
        {logger::option::BG_LIGHT_MAGENTA, FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY},

        {logger::option::FG_DARK_CYAN, FOREGROUND_GREEN | FOREGROUND_BLUE},
        {logger::option::BG_DARK_CYAN, BACKGROUND_GREEN | BACKGROUND_BLUE},
        {logger::option::FG_LIGHT_CYAN, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY},
        {logger::option::BG_LIGHT_CYAN, BACKGROUND_GREEN | BACKGROUND_BLUE | BACKGROUND_INTENSITY},
    };
#else
    inline bool is_console_intitiated = true;
    inline FILE *our_out = stdout;
    inline FILE *our_err = stderr;

    // https://ss64.com/nt/syntax-ansi.html
    inline const std::unordered_map<logger::option, std::string> option_codes = {
        {logger::option::DEFAULT, "\033[0m"},
        {logger::option::BOLD, "\033[1m"},
        {logger::option::UNDERLINE, "\033[4m"},
        {logger::option::NO_UNDERLINE, "\033[24m"},

        {logger::option::FG_BLACK, "\033[30m"},
        {logger::option::BG_BLACK, "\033[40m"},
        {logger::option::FG_WHITE, "\033[97m"},
        {logger::option::BG_WHITE, "\033[107m"},

        {logger::option::FG_DARK_RED, "\033[31m"},
        {logger::option::BG_DARK_RED, "\033[41m"},
        {logger::option::FG_LIGHT_RED, "\033[91m"},
        {logger::option::BG_LIGHT_RED, "\033[101m"},

        {logger::option::FG_DARK_GREEN, "\033[32m"},
        {logger::option::BG_DARK_GREEN, "\033[42m"},
        {logger::option::FG_LIGHT_GREEN, "\033[92m"},
        {logger::option::BG_LIGHT_GREEN, "\033[102m"},

        {logger::option::FG_DARK_YELLOW, "\033[33m"},
        {logger::option::BG_DARK_YELLOW, "\033[43m"},
        {logger::option::FG_LIGHT_YELLOW, "\033[93m"},
        {logger::option::BG_LIGHT_YELLOW, "\033[103m"},

        {logger::option::FG_DARK_BLUE, "\033[34m"},
        {logger::option::BG_DARK_BLUE, "\033[44m"},
        {logger::option::FG_LIGHT_BLUE, "\033[94m"},
        {logger::option::BG_LIGHT_BLUE, "\033[104m"},

        {logger::option::FG_DARK_MAGENTA, "\033[35m"},
        {logger::option::BG_DARK_MAGENTA, "\033[45m"},
        {logger::option::FG_LIGHT_MAGENTA, "\033[95m"},
        {logger::option::BG_LIGHT_MAGENTA, "\033[105m"},

        {logger::option::FG_DARK_CYAN, "\033[36m"},
        {logger::option::BG_DARK_CYAN, "\033[46m"},
        {logger::option::FG_LIGHT_CYAN, "\033[96m"},
        {logger::option::BG_LIGHT_CYAN, "\033[106m"},
    };
#endif

    inline void ensure_init()
    {
#ifdef _WIN32
      if (!detail::is_console_intitiated)
      {
        if (!AttachConsole(GetCurrentProcessId()))
        {
          AllocConsole();
        }
        SetConsoleTitleA("Spotify - Needle");
        SetConsoleCP(CP_UTF8);
        SetConsoleOutputCP(CP_UTF8);
        detail::is_console_intitiated = true;
      }

      if (detail::our_out == nullptr)
      {
        detail::our_out = std::fopen("CONOUT$", "w");
      }

      if (detail::our_err == nullptr)
      {
        detail::our_err = std::fopen("CONOUT$", "w");
      }
#endif
    }
  }

  void set_info_option(logger::option opts);

  void set_error_option(logger::option opts);

  template <class... Args>
  inline void info(const char *format, Args... args)
  {
    detail::ensure_init();
    fprintf(detail::our_out, format, std::forward<Args>(args)...);
    fflush(detail::our_out);
  }

  template <class... Args>
  inline void error(const char *format, Args... args)
  {
    detail::ensure_init();
    logger::set_error_option(option::FG_DARK_RED);
    fprintf(detail::our_err, format, std::forward<Args>(args)...);
    fflush(detail::our_err);
  }

  inline void set_info_option(logger::option opts)
  {
#ifdef _WIN32
    WORD options = 0;
    for (logger::option i = logger::option::DEFAULT;
         i < logger::option::LAST; i = logger::option(static_cast<std::underlying_type_t<logger::option>>(i) << 1))
    {
      if ((opts & i) == i)
      {
        const WORD code = detail::option_codes.at(i);
        options |= code;
      }
    }
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), options);
#else
    for (logger::option i = logger::option::DEFAULT;
         i < logger::option::LAST; i = logger::option(
                                       static_cast<std::underlying_type_t<logger::option>>(i) << 1))
    {
      if ((opts & i) == i)
      {
        const std::string &code = detail::option_codes.at(i);
        fprintf(detail::our_out, code.c_str());
      }
    }
#endif
  }

  inline void set_error_option(logger::option opts)
  {
#ifdef _WIN32
    WORD options = 0;
    for (logger::option i = logger::option::DEFAULT;
         i < logger::option::LAST; i = logger::option(static_cast<std::underlying_type_t<logger::option>>(i) << 1))
    {
      if ((opts & i) == i)
      {
        const WORD code = detail::option_codes.at(i);
        options |= code;
      }
    }
    SetConsoleTextAttribute(GetStdHandle(STD_ERROR_HANDLE), options);
#else
    for (logger::option i = logger::option::DEFAULT;
         i < logger::option::LAST; i = logger::option(
                                       static_cast<std::underlying_type_t<logger::option>>(i) << 1))
    {
      if ((opts & i) == i)
      {
        const std::string &code = detail::option_codes.at(i);
        fprintf(detail::our_err, code.c_str());
      }
    }
#endif
  }

  inline void set_option(logger::option opts)
  {
    logger::set_info_option(opts);
    logger::set_error_option(opts);
  }
}

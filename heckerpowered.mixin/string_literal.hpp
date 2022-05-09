#pragma once
#include <cstddef>
#include <string>
#include <utility>

namespace core
{
    template<typename T, std::size_t size>
    struct basic_string_literal
    {
        using char_type = T;
        constexpr static std::size_t length{ size };
        char_type data[length + 1]{};

        template<std::size_t _size = size, std::enable_if_t<_size == 0, std::size_t> = 0> constexpr basic_string_literal() :data{0}{}
        template<std::size_t _size = size, std::enable_if_t<_size == 1, std::size_t> = 0> constexpr basic_string_literal(char_type c) : data{ c,0 } {}
        constexpr basic_string_literal(std::basic_string_view<char_type> view)
        {
            for (std::size_t i{}; i < length; i++) { data[i] = view[i]; }
            data[size] = 0;
        }

        constexpr basic_string_literal(const char_type(&value)[size + 1])
        {
            for (std::size_t i{}; i < length; i++) { data[i] = value[i]; }
            data[size] = 0;
        }
    };

    template<typename T, std::size_t N>
    basic_string_literal(const T(&)[N])->basic_string_literal<T, N - 1>;

    template<basic_string_literal basic_string_literal_v>
    struct string_literal
    {
        using char_type = typename decltype(basic_string_literal_v)::char_type;
        static constexpr char_type* data() { return basic_string_literal_v.data; }
        static constexpr std::size_t length() { return basic_string_literal_v.length; }
        static constexpr std::basic_string_view<char_type> view() { return basic_string_literal_v.data; }
        constexpr operator std::basic_string_view<char_type>() { return view(); }
    };

    #define LITERAL(str) \
([]{constexpr std::basic_string_view s{str};\
    return core::string_literal<\
        core::basic_string_literal<typename decltype(s)::value_type,s.size()>\
            {str}>{};}\
())
}
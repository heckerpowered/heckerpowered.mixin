#pragma once
#include <iterator>

namespace core
{
		inline
		#if defined(__has_builtin) && __has_builtin(__builtin_memcpy)
		constexpr
		#endif
		void* memcpy(void* dest, void const* src, std::size_t count) noexcept
		{
			return
				#if defined(__has_builtin) && __has_builtin(__builtin_memcpy)
				__builtin_memcpy
				#else
				std::memcpy
				#endif
				(dest, src, count);
		}


		inline
		#if defined(__has_builtin) && __has_builtin(__builtin_memmove)
		constexpr
		#endif
		void* memmove(void* dest, void const* src, std::size_t count) noexcept
		{
			return
				#if defined(__has_builtin)
				#if __has_builtin(__builtin_memmove)
				__builtin_memmove
				#else
				std::memmove
				#endif
				#else
				std::memmove
				#endif
				(dest, src, count);
		}

	inline void* memset(void* dest, int val, std::size_t count) noexcept
	{
		return
			#if defined(__has_builtin) && __has_builtin(__builtin_memset)
			__builtin_memset
			#else
			std::memset
			#endif
			(dest, val, count);
	}

	template<std::input_iterator input_iterator, std::input_or_output_iterator output_iterator>
	inline constexpr output_iterator _Copy(input_iterator first, input_iterator last, output_iterator result)
	{
		while (first != last)
		{
			*result = *first;
			first++;
			result++;
		}
		return result;
	}

	template<std::input_iterator input_iterator, std::input_or_output_iterator output_iterator>
	inline constexpr output_iterator copy(input_iterator first, input_iterator last, output_iterator result)
	{
		#if __cpp_if_consteval >= 202106L || __cpp_lib_is_constant_evaluated >= 201811L
		#if __cpp_if_consteval >= 202106L
		if consteval
			#else
		if (__builtin_is_constant_evaluated())
			#endif
		{ return _Copy(first, last, result); }
		else
		#endif
		{
			using input_value_type = std::iter_value_t<input_iterator>;
			using output_value_type = std::iter_value_t<output_iterator>;
			if constexpr (std::contiguous_iterator<input_iterator> && std::contiguous_iterator<output_iterator>
				&& std::is_trivially_copyable_v<input_value_type> && std::is_trivially_copyable_v<output_value_type>
				&& (std::same_as<input_value_type, output_value_type>
					|| (std::integral<input_value_type> && std::integral<output_value_type>
						&& sizeof(input_value_type) == sizeof(output_value_type))))
			{
				std::size_t count{ static_cast<std::size_t>(last - first) };
				if (count) { core::memcpy(std::to_address(result), std::to_address(first), sizeof(std::iter_value_t<input_iterator>) * count); }
				return result += count;
			}
			else { _Copy(first, last, result); }
		}
	}


}
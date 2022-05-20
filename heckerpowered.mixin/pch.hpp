#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include <Windef.h>
#include <intrin.h>

#include "kernel_stl.hpp"

#include <cstddef>
#include <functional>
#include <atomic>
#include <string>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <type_traits>
#include <chrono>
#include <coroutine>
#include <deque>
#include <algorithm>
#include <numeric>

#pragma warning(disable: 4996)
#include "hook.hpp"
#pragma warning(default: 4996)

#include "core.hpp"
#include "string_builder.hpp"
#include "string_literal.hpp"
#include "compatibility.hpp"
#include "io.hpp"
#include "util.hpp"
#include "memory.hpp"
#include "native_struct.hpp"
#include "extern.hpp"
#include "lde.hpp"
#include "process.hpp"
#include "thread.hpp"
#include "procedure.hpp"
#include "infinity_hook.hpp"
#include "system.hpp"
#include "process_guard.hpp"
#include "communication.hpp"
#include "image_callback.hpp"
#include "object_callback.hpp"
#include "process_callback.hpp"
#include "concurrent.hpp"
#include "handle.hpp"
#include "main.hpp"
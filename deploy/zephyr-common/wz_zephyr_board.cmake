# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# wz_zephyr_board.cmake -- what every wz Zephyr application takes from its BOARD
# instead of carrying as a constant.
#
# An application includes this AFTER `find_package(Zephyr)` (so the build's
# Kconfig is known) and calls `wz_zephyr_rust_app()`. Everything that used to be
# written down for one machine, QEMU mps2/an385, is read here from the board's
# own configuration:
#
#   Rust target triple   from CONFIG_CPU_CORTEX_M* and the FPU's ABI. The same
#                        mapping zephyr-lang-rust uses; a CPU or an FPU ABI that has
#                        no Rust target is a configure error, never a guess.
#   tick rate            CONFIG_SYS_CLOCK_TICKS_PER_SEC, handed to cargo as
#                        WZ_TICKS_PER_SEC; the firmware's clock type reads it
#                        (`wz_runtime_zephyr::tick_hz_from_build!`).
#   core clock           CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC, the clock every tick and
#                        busy wait is derived from, handed to cargo as
#                        WZ_CORE_CLOCK_HZ so that an image can compare it with the
#                        clock the board reports (`wz_runtime_zephyr::core_clock`).
#   random source       the board's entropy device, or the QEMU test generator on
#                        a QEMU board only (wz_board_hooks.c refuses the rest).
#   wall clock           set at boot from this build's own instant.
#
# The Rust staticlib and the kernel's final image link are Zephyr's job; cargo
# only emits the archive, with the kernel and POSIX symbols undefined.

include_guard(GLOBAL)

set(WZ_ZEPHYR_COMMON_DIR ${CMAKE_CURRENT_LIST_DIR})

# The Rust target for the CPU this build selected.
function(wz_rust_target_for_board out)
  set(fpu_hard FALSE)
  if(CONFIG_FPU)
    if(CONFIG_FP_HARDABI)
      set(fpu_hard TRUE)
    else()
      message(FATAL_ERROR
        "wz: this build has an FPU with the soft-FP ABI (CONFIG_FP_SOFTABI). No Rust "
        "target uses the softfp ABI, so the Rust staticlib could not link into the "
        "image. Select CONFIG_FP_HARDABI, or build without the FPU (CONFIG_FPU=n).")
    endif()
  endif()

  if(CONFIG_CPU_CORTEX_M0 OR CONFIG_CPU_CORTEX_M0PLUS OR CONFIG_CPU_CORTEX_M1)
    set(triple thumbv6m-none-eabi)
  elseif(CONFIG_CPU_CORTEX_M3)
    set(triple thumbv7m-none-eabi)
  elseif(CONFIG_CPU_CORTEX_M4 OR CONFIG_CPU_CORTEX_M7)
    set(triple thumbv7em-none-eabi)
  elseif(CONFIG_CPU_CORTEX_M23)
    set(triple thumbv8m.base-none-eabi)
  elseif(CONFIG_CPU_CORTEX_M33 OR CONFIG_CPU_CORTEX_M52 OR CONFIG_CPU_CORTEX_M55
         OR CONFIG_CPU_CORTEX_M85)
    set(triple thumbv8m.main-none-eabi)
  else()
    message(FATAL_ERROR
      "wz: no Rust target is known for this board's CPU (BOARD=${BOARD}). Add its "
      "CONFIG_CPU_* to wz_rust_target_for_board in deploy/zephyr-common/"
      "wz_zephyr_board.cmake.")
  endif()

  # A Cortex-M0/M1/M23 has no FPU; asking for the hard ABI there is a Zephyr
  # configuration this mapping does not know how to honour.
  if(fpu_hard)
    if(triple STREQUAL "thumbv7em-none-eabi" OR triple STREQUAL "thumbv8m.main-none-eabi")
      set(triple "${triple}hf")
    else()
      message(FATAL_ERROR
        "wz: CONFIG_FPU with the hard ABI on a core (${triple}) that has no hard-float "
        "Rust target.")
    endif()
  endif()
  set(${out} ${triple} PARENT_SCOPE)
endfunction()

# wz_zephyr_rust_app(
#   RUST_DIR <dir>            the staticlib crate (holds Cargo.toml)
#   LIB      <stem>           the staticlib's name: lib<stem>.a
#   [FEATURES <f>...]         cargo features to turn on
#   [CARGO_ENV <VAR=val>...]  extra environment for the cargo build
#   [UNDEFINED <sym>...]      kernel / POSIX symbols only this application's Rust
#                             side references, to keep through the image link
# )
#
# Sets WZ_RUST_TARGET in the caller's scope, builds the crate as an always-run
# custom target, and links it into `app` with the symbol contract below.
function(wz_zephyr_rust_app)
  cmake_parse_arguments(WZ "" "RUST_DIR;LIB" "FEATURES;CARGO_ENV;UNDEFINED" ${ARGN})
  if(NOT WZ_RUST_DIR OR NOT WZ_LIB)
    message(FATAL_ERROR "wz_zephyr_rust_app needs RUST_DIR and LIB")
  endif()

  wz_rust_target_for_board(rust_target)
  set(WZ_RUST_TARGET ${rust_target} PARENT_SCOPE)
  # Layer Qzb reads this line back and requires it to equal the board table's
  # `rust_target`: the table says what toolchain a board needs, this derivation
  # says what the build will use, and they must not drift apart.
  message(STATUS "wz: Rust target ${rust_target}")

  if(NOT CONFIG_SYS_CLOCK_TICKS_PER_SEC)
    message(FATAL_ERROR "wz: CONFIG_SYS_CLOCK_TICKS_PER_SEC is unset; the clock has no rate.")
  endif()

  set(rust_lib ${WZ_RUST_DIR}/target/${rust_target}/release/lib${WZ_LIB}.a)
  set(cargo_features "")
  if(WZ_FEATURES)
    list(JOIN WZ_FEATURES "," joined)
    set(cargo_features --features ${joined})
  endif()

  # Always-run (ALL + no OUTPUT) so Rust source edits are picked up; cargo's own
  # incremental check keeps the no-change case cheap. BYPRODUCTS registers the
  # archive as this target's product so ninja can depend on it. The environment
  # is part of the compile (`env!` is tracked), so changing the board's tick rate
  # rebuilds the firmware crate.
  add_custom_target(wz_rust_lib ALL
    BYPRODUCTS ${rust_lib}
    COMMAND ${CMAKE_COMMAND} -E env
            WZ_TICKS_PER_SEC=${CONFIG_SYS_CLOCK_TICKS_PER_SEC}
            WZ_CORE_CLOCK_HZ=${CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC}
            ${WZ_CARGO_ENV}
            cargo build --release --target ${rust_target}
            --manifest-path ${WZ_RUST_DIR}/Cargo.toml ${cargo_features}
    WORKING_DIRECTORY ${WZ_RUST_DIR}
    COMMENT "cargo build wz Rust staticlib for ${rust_target} (tick rate ${CONFIG_SYS_CLOCK_TICKS_PER_SEC} Hz)"
    USES_TERMINAL
    VERBATIM
  )
  add_dependencies(app wz_rust_lib)

  # The instant the board sets its realtime clock to at boot (wz_board_hooks.c),
  # standing in for an SNTP sync on a board with no RTC: this build's own time, in
  # seconds since the Unix epoch, UTC.
  string(TIMESTAMP epoch_secs "%s" UTC)
  target_compile_definitions(app PRIVATE WZ_BOARD_EPOCH_SECS=${epoch_secs})
  target_sources(app PRIVATE ${WZ_ZEPHYR_COMMON_DIR}/wz_board_hooks.c)

  # Link the staticlib + force-keep what only the Rust side references. Zephyr's
  # libraries are scanned BEFORE the appended librustlib.a, so without
  # `--undefined` the linker would drop kernel symbols and the board hooks (no C
  # caller) and the Rust references would dangle. This is Zephyr's own idiom (it
  # does the same for e.g. _sw_isr_table): an explicit symbol contract.
  set(kept
    sys_clock_tick_get k_malloc k_free
    wz_log wz_yield_ms wz_delay_us wz_irq_lock wz_irq_unlock
    wzApplicationGetRandom wzApplicationGetTimeSinceEpoch)
  target_link_libraries(app PUBLIC ${rust_lib})
  foreach(sym IN LISTS kept WZ_UNDEFINED)
    target_link_libraries(app PUBLIC -Wl,--undefined=${sym})
  endforeach()
endfunction()

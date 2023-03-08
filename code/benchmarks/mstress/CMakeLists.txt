cmake_minimum_required(VERSION 3.15.0)

set(mstress_sources mstress.c)

if (DEFINED bm_logfile)
    add_compile_definitions(BM_LOGFILE=${bm_logfile})
    include_directories(AFTER ${CMAKE_SOURCE_DIR}/misc)
    list(APPEND mstress_sources ${CMAKE_SOURCE_DIR}/misc/harness.c)
endif()

add_executable(mstress.elf ${mstress_sources})


if (${gclib} STREQUAL bdwgc)
    include_directories(AFTER ${install_dir}/include)
    target_link_libraries(mstress.elf PRIVATE pthread gc)
    add_compile_definitions(BDWGC IGNOREFREE)
elseif (${gclib} STREQUAL cheribumpalloc)
    add_compile_definitions(BUMPALLOC)
    include_directories(AFTER ${CMAKE_SOURCE_DIR}/cheri_bump_alloc)
    target_link_libraries(mstress.elf PRIVATE pthread cheribumpalloc)
else()
    target_link_libraries(mstress.elf PRIVATE pthread)
endif()

install(TARGETS mstress.elf 
        RUNTIME DESTINATION bin)


include_directories(
   .
)

set(example_SRCS
   rtu.c
)

IF(WIN32)
set_source_files_properties(${example_SRCS}
                                       PROPERTIES LANGUAGE CXX)
ENDIF(WIN32)

add_executable(rtu
  ${example_SRCS}
)

target_link_libraries(simple_server
    lib60870
)

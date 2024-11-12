
set(sv_subscriber_example_SRCS
   dpshmi_sv.c
)

IF(WIN32)

set_source_files_properties(${sv_subscriber_example_SRCS}
                                       PROPERTIES LANGUAGE CXX)
add_executable(sv_subscriber_example
  ${sv_subscriber_example_SRCS}
)

target_link_libraries(sv_subscriber_example
    iec61850
)

ELSE(WIN32)

add_executable(sv_subscriber_example
  ${sv_subscriber_example_SRCS}
)

target_link_libraries(sv_subscriber_example
    iec61850
)

ENDIF(WIN32)



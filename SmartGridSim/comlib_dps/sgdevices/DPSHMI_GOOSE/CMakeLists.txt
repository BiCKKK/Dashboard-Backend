
set(goose_subscriber_example_SRCS
   dpshmi.c
)

IF(WIN32)

set_source_files_properties(${goose_subscriber_example_SRCS}
                                       PROPERTIES LANGUAGE CXX)
add_executable(dpshmi
  ${goose_subscriber_example_SRCS}
)

target_link_libraries(dpshmi
    iec61850
)

ELSE(WIN32)

add_executable(dpshmi
  ${goose_subscriber_example_SRCS}
)

target_link_libraries(dpshmi
    iec61850
)

ENDIF(WIN32)



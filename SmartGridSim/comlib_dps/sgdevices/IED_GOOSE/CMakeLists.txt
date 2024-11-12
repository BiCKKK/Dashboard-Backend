
set(ied_goose
   ied_goose.c
)

IF(WIN32)

set_source_files_properties(${ied_goose}
                                       PROPERTIES LANGUAGE CXX)
add_executable(ied_goose
  ${ied_goose}
)

target_link_libraries(goose_publisher_example
    iec61850
)

ELSE(WIN32)

add_executable(goose_publisher_example
  ${ied_goose}
)

target_link_libraries(goose_publisher_example
    iec61850
)

ENDIF(WIN32)



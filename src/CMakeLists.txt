INCLUDE_DIRECTORIES(${cryptlite_SOURCE_DIR}/include)

#FILE(GLOB src_files ${cryptlite_SOURCE_DIR}/src/*)
#ADD_LIBRARY(cryptlite SHARED ${src_files})
#ADD_LIBRARY(cryptlite_static STATIC ${src_files})
# SET_TARGET_PROPERTIES(cryptlite_static PROPERTIES OUTPUT_NAME cryptlite)

FILE(GLOB header_files ${cryptlite_SOURCE_DIR}/include/cryptlite/*)
INSTALL(FILES ${header_files} DESTINATION include/cryptlite)
#INSTALL(TARGETS cryptlite DESTINATION lib)

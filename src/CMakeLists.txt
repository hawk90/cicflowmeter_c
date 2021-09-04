# set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake"
# include("")

set(CIC_SOURCE cicflowmeter.c)

#################################################

#################################################
add_executable(CICFLOWMETER ${CIC_SOURCE})
target_include_directoris(CICFLOWMETER PUBLIC ${PROJECT_SOURCE_DIR}/include)

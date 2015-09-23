cmake_minimum_required(VERSION 3.2)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
set(CMAKE_CXX_STANDARD 11)

find_package(Crypto++)
find_package(Threads)
find_package(Boost COMPONENTS program_options REQUIRED)
include_directories(${CRYPTO++_INCLUDE_DIR})
include_directories(${Boost_INCLUDE_DIRECTORIES})

add_executable(crypto main.cpp)
target_link_libraries(crypto ${CRYPTO++_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${Boost_LIBRARIES})

add_executable(generator key.cpp)
target_link_libraries(generator ${CRYPTO++_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${Boost_LIBRARIES})
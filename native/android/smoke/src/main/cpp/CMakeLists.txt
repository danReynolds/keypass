cmake_minimum_required(VERSION 3.22.1)
project(keypass_smoke LANGUAGES CXX)
add_library(keypass_smoke SHARED smoke.cpp)
target_link_libraries(keypass_smoke dl)

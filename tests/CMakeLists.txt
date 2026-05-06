# UDP link plugin unit tests — MIT.
include(GoogleTest)

add_executable(test_udp test_udp.cpp)
target_link_libraries(test_udp PRIVATE
    GoodNet::sdk
    goodnet_udp_objects
    asio::asio
    Threads::Threads
    GTest::gtest
    GTest::gtest_main)
target_compile_features(test_udp PRIVATE cxx_std_23)
if(COMMAND goodnet_apply_pch)
    goodnet_apply_pch(test_udp)
endif()
gtest_discover_tests(test_udp
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60)

# NB external pthreads dependency!!
find_package (Threads)
find_library (RT rt)
find_library (PCAP pcap)

target_link_libraries(mbed-protocol-manager
    ${CMAKE_THREAD_LIBS_INIT}
    ${RT}
    ${PCAP}
)

# Optimization off and enable traces
add_definitions(-O0 -DMBED_CONF_MBED_TRACE_ENABLE=1)

# DNS resolving for PAL layer
add_definitions(-DPAL_NET_DNS_SUPPORT)
# enable PAL debug prints
add_definitions(-DVERBOSE)

# libpcap and linux socket definitions
add_definitions(-D_XOPEN_SOURCE=700 -D_GNU_SOURCE)

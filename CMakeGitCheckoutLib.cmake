SET(EXT_PROJECT_CHECKOUT_LOCATION ${CMAKE_GIT_CHECKOUT_DIR} )

if(NOT EXISTS ${CMAKE_GIT_CHECKOUT_DIR})
    message("Creating new clone to ${EXT_PROJECT_CHECKOUT_LOCATION}")
    #message("executing cmd cat ${LIB_FILENAME} | cut -d -f1" )

    if (CMAKE_GIT_CLONE_ADDRESS STREQUAL "")
    execute_process( COMMAND bash "-c" "cat ${LIB_FILENAME} | cut -d '#' -f1" OUTPUT_VARIABLE CMAKE_GIT_CLONE_ADDRESS )
    message("Parsed repository: ${CMAKE_GIT_CLONE_ADDRESS}")
    else()
    message("Using address for clone: ${CMAKE_GIT_CLONE_ADDRESS}")
    endif()

    execute_process(COMMAND git clone ${CMAKE_GIT_CLONE_ADDRESS} ${EXT_PROJECT_CHECKOUT_LOCATION})

    execute_process( COMMAND bash "-c" "cat ${LIB_FILENAME} | cut -d '#' -f2 -s" OUTPUT_VARIABLE CMAKE_GIT_CHECKOUT_TAG )

    if (CMAKE_GIT_CHECKOUT_TAG STREQUAL "")
        message("No tag defined in ${LIB_FILENAME} using master as default")
    else()
        message("Custom tag in ${LIB_FILENAME} using ${CMAKE_GIT_CHECKOUT_TAG} in ${EXT_PROJECT_CHECKOUT_LOCATION}")
        execute_process(COMMAND bash "-c" "ls -al"
                    WORKING_DIRECTORY ${EXT_PROJECT_CHECKOUT_LOCATION})
        execute_process(COMMAND bash "-c" "git show ${CMAKE_GIT_CHECKOUT_TAG}"
                    WORKING_DIRECTORY ${EXT_PROJECT_CHECKOUT_LOCATION})
        execute_process(COMMAND bash "-c" "git checkout ${CMAKE_GIT_CHECKOUT_TAG}"
                    WORKING_DIRECTORY ${EXT_PROJECT_CHECKOUT_LOCATION})
    endif()

else()
     message("Project ${CMAKE_GIT_CHECKOUT_DIR} already exists, no new checkout done delete ${CMAKE_GIT_CHECKOUT_DIR} if new checkout is needed")
endif()

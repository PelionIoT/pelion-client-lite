SET(EXT_PROJECT_CHECKOUT_LOCATION ${CMAKE_GIT_CHECKOUT_DIR} )

if(NOT EXISTS ${CMAKE_GIT_CHECKOUT_DIR})
    message("Creating new clone to ${EXT_PROJECT_CHECKOUT_LOCATION}")

    execute_process(COMMAND git clone ${CMAKE_GIT_CLONE_ADDRESS} ${EXT_PROJECT_CHECKOUT_LOCATION})
    execute_process(COMMAND git checkout ${CMAKE_GIT_CHECKOUT_TAG}
                WORKING_DIRECTORY ${EXT_PROJECT_CHECKOUT_LOCATION})
else()
     message("Project ${CMAKE_GIT_CHECKOUT_DIR} already exists, no new checkout done delete ${CMAKE_GIT_CHECKOUT_DIR} if new checkout is needed")
endif()
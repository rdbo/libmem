if(${CMAKE_SYSTEM_NAME} MATCHES Windows)
	set(CMAKE_GENERATOR "NMake Makefiles" CACHE INTERNAL "" FORCE)
else()
	set(CMAKE_GENERATOR "Unix Makefiles" CACHE INTERNAL "" FORCE)
endif()


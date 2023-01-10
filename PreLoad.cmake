if(WIN32)
	set(CMAKE_GENERATOR "NMake Makefiles" CACHE INTERNAL "" FORCE)
else()
	set(CMAKE_GENERATOR "Unix Makefiles" CACHE INTERNAL "" FORCE)
endif()


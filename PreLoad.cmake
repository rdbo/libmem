if(WIN32) # this MUST NOT match CYGWIN
	set(CMAKE_GENERATOR "NMake Makefiles" CACHE INTERNAL "" FORCE)
else()
	set(CMAKE_GENERATOR "Unix Makefiles" CACHE INTERNAL "" FORCE)
endif()


if(MINGW AND CMAKE_HOST_LINUX)
	set(CMAKE_GENERATOR "Ninja" CACHE INTERNAL "" FORCE)
elseif(WIN32) # this MUST NOT match CYGWIN or MinGW cross-compilation
	set(CMAKE_GENERATOR "NMake Makefiles" CACHE INTERNAL "" FORCE)
else()
	set(CMAKE_GENERATOR "Unix Makefiles" CACHE INTERNAL "" FORCE)
endif()

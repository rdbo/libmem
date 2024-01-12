#ifndef TESTDLL_H
#define TESTDLL_H

#ifdef TESTDLL_EXPORTS
#define TESTDLL_API __declspec(dllexport)
#else
#define TESTDLL_API __declspec(dllimport)
#endif

extern "C" {
    TESTDLL_API void Function1();
    TESTDLL_API int Function2(int);
}

#endif // TESTDLL_H
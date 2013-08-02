/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef LIBCOUCHSTORE_VISIBILITY_H
#define LIBCOUCHSTORE_VISIBILITY_H

#if defined(LIBCOUCHSTORE_INTERNAL)

#ifdef __SUNPRO_C
#define LIBCOUCHSTORE_API __global
#elif defined(HAVE_VISIBILITY) && HAVE_VISIBILITY
#define LIBCOUCHSTORE_API __attribute__ ((visibility("default")))
#elif defined(_MSC_VER)
#define LIBCOUCHSTORE_API extern __declspec(dllexport)
#else
#define LIBCOUCHSTORE_API
#endif

#else

#ifdef _MSC_VER
#define LIBCOUCHSTORE_API extern __declspec(dllimport)
#else
#define LIBCOUCHSTORE_API
#endif

#endif

#endif

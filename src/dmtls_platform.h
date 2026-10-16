#ifndef DMTLS_PLATFORM_H
#define DMTLS_PLATFORM_H
#include <stddef.h>
#include <stdarg.h>
char* dmtls_backend_strstr(const char* haystack, const char* needle);
void* dmtls_backend_calloc(size_t count, size_t size);
void dmtls_backend_free(void* pointer);
int dmtls_backend_snprintf(char* out, size_t size, const char* format, ...);
int dmtls_backend_vsnprintf(char* out, size_t size, const char* format, va_list args);
#endif

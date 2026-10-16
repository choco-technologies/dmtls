#include "dmtls_internal.h"
#include "dmtls_platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/dmod.h"
#include "psa/crypto_driver_random.h"
#include <stdint.h>
#include <string.h>
#include <errno.h>

struct dmtls_config* dmtls_config_list;
struct dmtls_connection* dmtls_connection_list;
dmtls_platform_t dmtls_platform;
dmosi_mutex_t dmtls_lock;
bool dmtls_initialized;
uint32_t dmtls_configs, dmtls_connections;
size_t dmtls_heap_used;
static bool entered;
/* Preserve the strongest fundamental alignment on both Cortex-M and x86. */
typedef union {size_t size; max_align_t align;} allocation_header;

void* dmtls_backend_calloc(size_t count, size_t size)
{
    if (size != 0 && count > (SIZE_MAX - sizeof(allocation_header)) / size) return NULL;
    size_t bytes = count * size + sizeof(allocation_header);
    if (dmtls_heap_used > dmtls_platform.heap_limit || bytes > dmtls_platform.heap_limit - dmtls_heap_used) return NULL;
    allocation_header* p = Dmod_Malloc(bytes);
    if (p == NULL) return NULL;
    p->size = bytes; dmtls_heap_used += bytes;
    memset(p + 1, 0, bytes - sizeof(*p)); return p + 1;
}
void dmtls_backend_free(void* pointer)
{
    if (pointer == NULL) return;
    allocation_header* p = (allocation_header*)pointer - 1;
    size_t bytes = p->size;
    mbedtls_platform_zeroize(p, bytes); dmtls_heap_used -= bytes; Dmod_Free(p);
}
int mbedtls_platform_get_entropy(psa_driver_get_entropy_flags_t flags,
    size_t* bits, unsigned char* output, size_t size)
{
    *bits = 0;
    if (flags != 0) return PSA_ERROR_NOT_SUPPORTED;
    if (size > SIZE_MAX / 8 || dmtls_platform.entropy == NULL ||
        dmtls_platform.entropy(dmtls_platform.user, output, size) != 0) {
        mbedtls_platform_zeroize(output, size); return PSA_ERROR_INSUFFICIENT_ENTROPY;
    }
    *bits = size * 8; return 0;
}
int dmtls_module_init(void)
{
    if (dmtls_lock != NULL) return 0;
    mbedtls_dmod_pk_init();
    mbedtls_dmod_ecp_init();
    dmtls_lock = dmosi_mutex_create(true);
    return dmtls_lock == NULL ? -ENOMEM : 0;
}
int dmtls_module_deinit(void)
{
    if (dmtls_configs != 0 || dmtls_connections != 0 || entered) return -EBUSY;
    if (dmtls_initialized) mbedtls_psa_crypto_free();
    dmtls_initialized = false;
    if (dmtls_lock != NULL) dmosi_mutex_destroy(dmtls_lock);
    dmtls_lock = NULL; memset(&dmtls_platform, 0, sizeof(dmtls_platform)); return 0;
}
dmtls_result_t dmtls_enter(void)
{
    if (dmtls_lock == NULL) return DMTLS_ERR_STATE;
    if (dmosi_mutex_lock(dmtls_lock) != 0) return DMTLS_ERR_BUSY;
    if (entered || !dmtls_initialized) {dmosi_mutex_unlock(dmtls_lock); return entered ? DMTLS_ERR_BUSY : DMTLS_ERR_STATE;}
    entered = true; return DMTLS_OK;
}
void dmtls_leave(void) {entered = false; dmosi_mutex_unlock(dmtls_lock);}
dmtls_result_t dmtls_platform_initialize(const dmtls_platform_t* platform)
{
    if (platform == NULL || platform->entropy == NULL || platform->heap_limit < 32768 || platform->max_connections == 0)
        return DMTLS_ERR_ARGUMENT;
    if (dmtls_lock == NULL) return DMTLS_ERR_STATE;
    if (dmosi_mutex_lock(dmtls_lock) != 0) return DMTLS_ERR_BUSY;
    if (entered || dmtls_initialized) {dmosi_mutex_unlock(dmtls_lock); return DMTLS_ERR_BUSY;}
    entered = true; dmtls_platform = *platform;
    psa_status_t rc = psa_crypto_init();
    if (rc != PSA_SUCCESS) {
        mbedtls_psa_crypto_free(); memset(&dmtls_platform, 0, sizeof(dmtls_platform));
    } else dmtls_initialized = true;
    dmtls_leave();
    return rc == PSA_SUCCESS ? DMTLS_OK : rc == PSA_ERROR_INSUFFICIENT_MEMORY ? DMTLS_ERR_MEMORY : DMTLS_ERR_ENTROPY;
}
dmtls_result_t dmtls_platform_shutdown(void)
{
    dmtls_result_t rc = dmtls_enter(); if (rc != DMTLS_OK) return rc;
    if (dmtls_configs || dmtls_connections) rc = DMTLS_ERR_BUSY;
    else {mbedtls_psa_crypto_free(); dmtls_initialized = false; memset(&dmtls_platform, 0, sizeof(dmtls_platform));}
    dmtls_leave(); return rc;
}
bool dmtls_valid_config(dmtls_config_t config)
{
    for (dmtls_config_t p = dmtls_config_list; p != NULL; p = p->next) if (p == config) return true;
    return false;
}
bool dmtls_valid_connection(dmtls_connection_t connection)
{
    for (dmtls_connection_t p = dmtls_connection_list; p != NULL; p = p->next) if (p == connection) return true;
    return false;
}
dmtls_result_t dmtls_refresh_utc(dmtls_connection_t c)
{
    dmutc_time_t time;
    if (dmutc_get(&time) != 0 || dmutc_to_calendar(&time, &c->utc) != 0) return DMTLS_ERR_TIME;
    return DMTLS_OK;
}
int dmtls_backend_vsnprintf(char* out, size_t size, const char* format, va_list args)
{return Dmod_VSnPrintf(out, size, format, args);}
int dmtls_backend_snprintf(char* out, size_t size, const char* format, ...)
{
    va_list args; va_start(args, format);
    int rc = Dmod_VSnPrintf(out, size, format, args);
    va_end(args); return rc;
}

void mbedtls_platform_zeroize(void* buffer, size_t size)
{
    volatile unsigned char* p = buffer;
    while (size-- != 0) *p++ = 0;
}
char* dmtls_backend_strstr(const char* text, const char* needle)
{
    size_t length = strlen(needle);
    if (length == 0) return (char*)text;
    for (; *text != 0; ++text) {
        size_t i = 0;
        while (i < length && text[i] != 0 && text[i] == needle[i]) ++i;
        if (i == length) return (char*)text;
    }
    return NULL;
}

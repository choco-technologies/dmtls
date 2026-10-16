#define DMOD_ENABLE_REGISTRATION ON
#include "dmod_test.h"
#include "dmtls.h"
#include "fixture_ca.h"

DMOD_TEST_STEP(tls_requires_an_explicit_entropy_source)
{
    DMOD_TEST_EXPECT_EQ(dmtls_initialize(NULL), DMTLS_ERR_ARGUMENT);
    dmtls_platform_t options = {0};
    DMOD_TEST_EXPECT_EQ(dmtls_initialize(&options), DMTLS_ERR_ARGUMENT);
}
DMOD_TEST_STEP(tls_rejects_calls_before_initialization)
{
    dmtls_config_t config = (dmtls_config_t)1;
    DMOD_TEST_EXPECT_EQ(dmtls_config_create("invalid", 7, &config), DMTLS_ERR_STATE);
    DMOD_TEST_EXPECT_NULL(config);
}

/* Deliberately deterministic test entropy: this test creates no TLS connection
 * and never protects application data. Production callers must use a strong
 * entropy source as required by the public API. */
static int fixture_entropy(void* user,uint8_t* output,size_t size)
{
    (void)user;
    for(size_t i=0;i<size;++i)output[i]=(uint8_t)(i*17+3);
    return 0;
}
DMOD_TEST_STEP(tls_real_module_lifecycle_and_ca_tables)
{
    dmtls_platform_t platform={fixture_entropy,NULL,512*1024,1};
    DMOD_TEST_EXPECT_EQ(dmtls_initialize(&platform),DMTLS_OK);
    dmtls_config_t config=NULL;
    DMOD_TEST_EXPECT_EQ(dmtls_config_create(fixture_ca,sizeof(fixture_ca),&config),DMTLS_OK);
    DMOD_TEST_EXPECT_EQ(dmtls_shutdown(),DMTLS_ERR_BUSY);
    DMOD_TEST_EXPECT_EQ(dmtls_config_destroy(config),DMTLS_OK);
    DMOD_TEST_EXPECT_EQ(dmtls_shutdown(),DMTLS_OK);
}

#include <gsasl.h>

int hsgsasl_VERSION_MAJOR()
{ return GSASL_VERSION_MAJOR; }

int hsgsasl_VERSION_MINOR()
{ return GSASL_VERSION_MINOR; }

int hsgsasl_VERSION_PATCH()
{ return GSASL_VERSION_PATCH; }

int hsgsasl_check_version ()
{ return gsasl_check_version (GSASL_VERSION) != NULL; }

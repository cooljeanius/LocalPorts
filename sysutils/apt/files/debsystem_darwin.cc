// -*- mode: cpp; mode: fold -*-
// Description								/*{{{*/
// $Id: debsystem_darwin.cc,v 1.4 2004/01/26 17:01:53 mdz Exp $
/* debsystem.cc already gets two patches applied to it, so I figured it would
 * be easier to just make a third file for the Fink-specific additions instead
 * of trying to wiggle it into a third patch for debsystem.cc... */
									/*}}}*/
// Include Files							/*{{{*/
#if defined(__GNUG__) && !defined(__APPLE_CC__)
# pragma implementation "apt-pkg/debsystem.h"
#endif /* __GNUG__ && !__APPLE_CC__ */

#include <apt-pkg/debsystem.h>
#include <apt-pkg/debversion.h>
#include <apt-pkg/debindexfile.h>
#include <apt-pkg/dpkgpm.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>

#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
									/*}}}*/

/* begin part that was originally FINK LOCAL changes */
/* (modified for MacPorts) */
#include <sys/utsname.h>
#include <CoreFoundation/CoreFoundation.h>
#include <fstream>
#include <sys/stat.h>

extern void init_deb2(); // gets patched into apt-pkg/deb/debindexfile.cc
extern void init_deb3(); // gets patched into apt-pkg/deb/debversion.cc

#define MACPORTSAPTSTATUSFILE "/tmp/macportsaptstatus"

struct versionrevision {
	unsigned long epoch;
	const char *version;
	const char *revision;
};

struct versionrevision darwin_version = {0,NULL,NULL};
struct versionrevision macosx_version = {0,NULL,NULL};

static void init_apt_on_darwin()
{
	Boolean status;
	SInt32 errorCode;
	CFURLRef fileURL = NULL;
	CFDataRef resourceData = NULL;
	CFPropertyListRef propertyList = NULL;
	CFStringRef string;
	static char buffer[256]; // This is static, to ensure the buffer stays around

	static struct utsname ver; // This is static, to ensure the buffer stays around

	/* Determine system version */
	/* TODO - should maybe check if this is really Darwin? */
	if (!uname(&ver)) {
		darwin_version.version = ver.release;
	}

	/* Check whether this is Mac OS X, and which version of it: */
	fileURL = CFURLCreateWithFileSystemPath(NULL,
											CFSTR("/System/Library/CoreServices/SystemVersion.plist"),
											kCFURLPOSIXPathStyle,
											false );
	if (!fileURL) {
		goto BAIL;
	}

	/* Read the XML: */
	status = CFURLCreateDataAndPropertiesFromResource(NULL,
													  fileURL,
													  &resourceData,
													  NULL,
													  NULL,
													  &errorCode);
	if (!status || errorCode != 0) {
		goto BAIL;
	}

	/* Reconstitute the dictionary using the XML data. */
	propertyList = CFPropertyListCreateFromXMLData(NULL,
												   resourceData,
												   kCFPropertyListImmutable,
												   &string);
	if (!propertyList) {
		goto BAIL;
	}

	/* Try to read the system version from it. */
	status = CFDictionaryGetValueIfPresent((CFDictionaryRef)propertyList,
										   (const void *)CFSTR("ProductVersion"),
										   (const void**)&string);
	if (!status) {
		goto BAIL;
	}

	/* Convert into a C string: */
	status = CFStringGetCString(string,
								buffer,
								sizeof(buffer),
								kCFStringEncodingISOLatin1);
	if (!status) {
		goto BAIL;
	}

	/* Finally link the buffer into the macosx_version struct. */
	macosx_version.version = buffer;

BAIL:
	// Release all of the CF objects that we are responsible for.
	if (fileURL) {
		CFRelease(fileURL);
	}
	if (resourceData) {
		CFRelease(resourceData);
	}
	if (propertyList) {
		CFRelease(propertyList);
	}
}

void initDebSystem()
{
	init_apt_on_darwin();
	(void)debSys;
	init_deb2();
	init_deb3();
}
/* end part that was originally FINK LOCAL changes */

// actually it looks like some of the changes to debsystem.cc will need to get
// wiggled into a third patch after all...

//
// Copyright (C) 2012 Realmac Software Ltd
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject
// to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
// ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
// CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#import "NSURL+RMApplicationGroup.h"

#import <Security/Security.h>
#import <pwd.h>

@implementation NSURL (RMApplicationGroup)

+ (NSString *)defaultGroupContainerIdentifier
{
	SecTaskRef task = NULL;
	
	NSString *applicationGroupIdentifier = nil;
	do {
		task = SecTaskCreateFromSelf(kCFAllocatorDefault);
		if (task == NULL) {
			break;
		}
		
		CFTypeRef applicationGroupIdentifiers = SecTaskCopyValueForEntitlement(task, CFSTR("com.apple.security.application-groups"), NULL);
		if (applicationGroupIdentifiers == NULL || CFGetTypeID(applicationGroupIdentifiers) != CFArrayGetTypeID() || CFArrayGetCount(applicationGroupIdentifiers) == 0) {
			break;
		}
		
		CFTypeRef firstApplicationGroupIdentifier = CFArrayGetValueAtIndex(applicationGroupIdentifiers, 0);
		if (CFGetTypeID(firstApplicationGroupIdentifier) != CFStringGetTypeID()) {
			break;
		}
		
		applicationGroupIdentifier = (__bridge NSString *)firstApplicationGroupIdentifier;
	} while (0);
	
	if (task != NULL) {
		CFRelease(task);
	}
	
	return applicationGroupIdentifier;
}

@end

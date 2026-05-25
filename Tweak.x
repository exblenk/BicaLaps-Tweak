/*
 * AIVideoUnlock — BISECT v2
 *
 * Previous minimal still crashed → cause is NOT in L1/L4.
 * Disabling: L2 (NSUserDefaults), L3 (FIRRemoteConfig swizzle).
 * Keeping:   L6 (SSL bypass) + L7 (restore txns) only.
 *
 * If this build does NOT crash → cause is L2 or L3.
 * If it STILL crashes        → cause is L6 (SecTrust hook).
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <substrate.h>

#define ENABLE_PIN_BYPASS 1

#define TWLog(fmt, ...) NSLog(@"[AIUnlock] " fmt, ##__VA_ARGS__)

// ═══════════════════════════════════════════════════════════════════════
// LAYER 6 — SSL pinning bypass (C symbols)
// ═══════════════════════════════════════════════════════════════════════
#if ENABLE_PIN_BYPASS

static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef, SecTrustResultType *);
static OSStatus new_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultProceed;
    return errSecSuccess;
}

static bool (*orig_SecTrustEvaluateWithError)(SecTrustRef, CFErrorRef *);
static bool new_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    if (error) *error = NULL;
    return true;
}

#endif

// ═══════════════════════════════════════════════════════════════════════
// LAYER 7 — Auto restoreCompletedTransactions via launch notification
// ═══════════════════════════════════════════════════════════════════════
static void onAppLaunched(CFNotificationCenterRef center, void *observer,
                          CFNotificationName name, const void *object,
                          CFDictionaryRef userInfo) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
            Class SK = NSClassFromString(@"SKPaymentQueue");
            if (!SK) return;
            id q = ((id(*)(id, SEL))objc_msgSend)((id)SK, @selector(defaultQueue));
            if (!q) return;
            ((void(*)(id, SEL))objc_msgSend)(q, @selector(restoreCompletedTransactions));
            TWLog(@"[TRIGGER] restoreCompletedTransactions called");
        } @catch (NSException *e) { TWLog(@"[TRIGGER] err: %@", e); }
    });
}

// ═══════════════════════════════════════════════════════════════════════
// Constructor
// ═══════════════════════════════════════════════════════════════════════
%ctor {
    @autoreleasepool {
        @try {
            TWLog(@"════════════════════════════════════════════");
            TWLog(@" AIVideoUnlock BISECT v2 — only L6+L7 active");
            TWLog(@"════════════════════════════════════════════");

#if ENABLE_PIN_BYPASS
            @try {
                void *sec1 = dlsym(RTLD_DEFAULT, "SecTrustEvaluate");
                if (sec1) MSHookFunction(sec1, (void *)new_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate);
                void *sec2 = dlsym(RTLD_DEFAULT, "SecTrustEvaluateWithError");
                if (sec2) MSHookFunction(sec2, (void *)new_SecTrustEvaluateWithError, (void **)&orig_SecTrustEvaluateWithError);
                TWLog(@"[init] SecTrust* hooked");
            } @catch (NSException *e) { TWLog(@"[init] SecTrust err: %@", e); }
#endif

            CFNotificationCenterAddObserver(
                CFNotificationCenterGetLocalCenter(),
                NULL,
                onAppLaunched,
                (CFStringRef)UIApplicationDidFinishLaunchingNotification,
                NULL,
                CFNotificationSuspensionBehaviorDeliverImmediately
            );

            TWLog(@"[init] bisect v2 ready");
        } @catch (NSException *e) {
            TWLog(@"[ctor] fatal: %@", e);
        }
    }
}

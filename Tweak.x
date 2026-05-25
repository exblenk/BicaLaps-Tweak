/*
 * AIVideoUnlock — BISECT v3
 *
 * v2 (L6+L7 only) did NOT crash → cause is L2 or L3.
 * This build adds L2 back (boolForKey + integerForKey only — no objectForKey).
 * objectForKey excluded because returning @YES for a non-bool key = swift_dynamicCast bomb.
 *
 * If this crashes → L2 boolForKey/integerForKey is the cause.
 * If no crash    → L3 (FIRRemoteConfig) is the cause.
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

static BOOL matchesPattern(NSString *str, NSString *pattern) {
    if (!str || ![str isKindOfClass:[NSString class]]) return NO;
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                       options:NSRegularExpressionCaseInsensitive
                                                                         error:nil];
    if (!re) return NO;
    return [re numberOfMatchesInString:str options:0 range:NSMakeRange(0, str.length)] > 0;
}

// ═══════════════════════════════════════════════════════════════════════
// LAYER 2 — NSUserDefaults (boolForKey + integerForKey ONLY — no objectForKey)
// ═══════════════════════════════════════════════════════════════════════
static NSString *const kPremiumPattern = @"isPremiumUser|isPremium\\b|premium_active|hasActiveSubscription|isPro\\b|isSubscribed|premiumPurchased|hasPaid";

%hook NSUserDefaults

- (BOOL)boolForKey:(NSString *)key {
    BOOL r = %orig;
    if (!r && matchesPattern(key, kPremiumPattern)) return YES;
    return r;
}

- (NSInteger)integerForKey:(NSString *)key {
    NSInteger r = %orig;
    if (r != 1 && matchesPattern(key, kPremiumPattern)) return 1;
    return r;
}

// objectForKey intentionally omitted — too risky for Swift type casts

%end

// ═══════════════════════════════════════════════════════════════════════
// LAYER 6 — SSL pinning bypass
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
// LAYER 7 — Auto restoreCompletedTransactions
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
            TWLog(@"═══════════════════════════════════════");
            TWLog(@" AIVideoUnlock BISECT v3 — L2(safe)+L6+L7");
            TWLog(@"═══════════════════════════════════════");

            %init();

#if ENABLE_PIN_BYPASS
            @try {
                void *sec1 = dlsym(RTLD_DEFAULT, "SecTrustEvaluate");
                if (sec1) MSHookFunction(sec1, (void *)new_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate);
                void *sec2 = dlsym(RTLD_DEFAULT, "SecTrustEvaluateWithError");
                if (sec2) MSHookFunction(sec2, (void *)new_SecTrustEvaluateWithError, (void **)&orig_SecTrustEvaluateWithError);
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

            TWLog(@"[init] bisect v3 ready");
        } @catch (NSException *e) {
            TWLog(@"[ctor] fatal: %@", e);
        }
    }
}

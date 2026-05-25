/*
 * AIVideoUnlock — MINIMAL debug build
 *
 * Goal: isolate the recurring swift_dynamicCast crash on NSURLSession-delegate.
 *
 * Disabled (network-touching) layers:
 *   - L1 NSJSONSerialization global hook
 *   - L4 NSURLSession response rewriter
 *
 * Active layers:
 *   - L2 NSUserDefaults (local key overrides — premium flags)
 *   - L3 FIRRemoteConfig swizzle (local return value override, ARC-safe)
 *   - L6 SSL pinning bypass
 *   - L7 Auto restoreCompletedTransactions on launch
 *
 * If the app stops crashing with this build, the cause IS one of L1/L4.
 * If it still crashes, the cause is L3 (FIRRC), L6 (SSL bypass), or unrelated.
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
// LAYER 2 — NSUserDefaults
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

- (id)objectForKey:(NSString *)key {
    id r = %orig;
    if (matchesPattern(key, kPremiumPattern)) return @YES;
    return r;
}

%end

// ═══════════════════════════════════════════════════════════════════════
// LAYER 3 — FIRRemoteConfig swizzle (ARC-safe)
// ═══════════════════════════════════════════════════════════════════════
static IMP origFIRConfigValueForKey = NULL;

static id swizzled_FIRConfigValueForKey(id self, SEL _cmd, NSString *key) {
    id orig = ((id (*)(id, SEL, NSString *))origFIRConfigValueForKey)(self, _cmd, key);
    @try {
        if (!key || ![key isKindOfClass:[NSString class]]) return orig;
        Class FIRRCV = NSClassFromString(@"FIRRemoteConfigValue");
        if (!FIRRCV) return orig;

        NSString *newValue = nil;
        if (matchesPattern(key, @"premium|paid|pro_required|require|locked")) newValue = @"false";
        else if (matchesPattern(key, @"limit|quota|max|daily"))                newValue = @"999999";
        if (!newValue) return orig;

        NSData *d = [newValue dataUsingEncoding:NSUTF8StringEncoding];
        SEL initSel = NSSelectorFromString(@"initWithData:source:");
        id raw = [FIRRCV alloc];
        if (![raw respondsToSelector:initSel]) return orig;
        // capture return — init may return a different instance
        id v = ((id (*)(id, SEL, NSData *, int))objc_msgSend)(raw, initSel, d, 2);
        if (!v) return orig;
        return v;
    } @catch (NSException *e) {
        TWLog(@"[err] L3: %@", e);
    }
    return orig;
}

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

%group AFNetworkingPin
%hook AFSecurityPolicy
- (BOOL)evaluateServerTrust:(SecTrustRef)trust forDomain:(NSString *)domain { return YES; }
%end
%end

%group TrustKitPin
%hook TSKPinningValidator
- (int)evaluateTrust:(SecTrustRef)trust forHostname:(NSString *)host { return 0; }
%end
%end

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
            if (!SK) { TWLog(@"[TRIGGER] SKPaymentQueue not present"); return; }
            id q = ((id(*)(id, SEL))objc_msgSend)((id)SK, @selector(defaultQueue));
            if (!q) { TWLog(@"[TRIGGER] queue nil"); return; }
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
            TWLog(@" AIVideoUnlock MINIMAL loaded into %@", [[NSBundle mainBundle] bundleIdentifier]);
            TWLog(@"════════════════════════════════════════════");

            // Required: init the ungrouped %hook (NSUserDefaults)
            %init();

            // L3 — FIRRemoteConfig swizzle
            @try {
                Class FIRRC = NSClassFromString(@"FIRRemoteConfig");
                if (FIRRC) {
                    SEL sel = NSSelectorFromString(@"configValueForKey:");
                    Method m = class_getInstanceMethod(FIRRC, sel);
                    if (m) {
                        origFIRConfigValueForKey = method_getImplementation(m);
                        method_setImplementation(m, (IMP)swizzled_FIRConfigValueForKey);
                        TWLog(@"[init] FIRRemoteConfig.configValueForKey: swizzled");
                    }
                }
            } @catch (NSException *e) { TWLog(@"[init] FIRRC err: %@", e); }

#if ENABLE_PIN_BYPASS
            @try {
                void *sec1 = dlsym(RTLD_DEFAULT, "SecTrustEvaluate");
                if (sec1) MSHookFunction(sec1, (void *)new_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate);
                void *sec2 = dlsym(RTLD_DEFAULT, "SecTrustEvaluateWithError");
                if (sec2) MSHookFunction(sec2, (void *)new_SecTrustEvaluateWithError, (void **)&orig_SecTrustEvaluateWithError);
                TWLog(@"[init] SecTrust* hooked");
            } @catch (NSException *e) { TWLog(@"[init] SecTrust err: %@", e); }

            @try {
                if (NSClassFromString(@"AFSecurityPolicy")) { %init(AFNetworkingPin); TWLog(@"[init] AFSecurityPolicy hooked"); }
            } @catch (NSException *e) { TWLog(@"[init] AF err: %@", e); }

            @try {
                if (NSClassFromString(@"TSKPinningValidator")) { %init(TrustKitPin); TWLog(@"[init] TrustKit hooked"); }
            } @catch (NSException *e) { TWLog(@"[init] TSK err: %@", e); }
#endif

            CFNotificationCenterAddObserver(
                CFNotificationCenterGetLocalCenter(),
                NULL,
                onAppLaunched,
                (CFStringRef)UIApplicationDidFinishLaunchingNotification,
                NULL,
                CFNotificationSuspensionBehaviorDeliverImmediately
            );

            TWLog(@"[init] MINIMAL build — L1/L4 disabled");
        } @catch (NSException *e) {
            TWLog(@"[ctor] fatal: %@", e);
        }
    }
}

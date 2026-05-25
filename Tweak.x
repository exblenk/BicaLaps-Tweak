/*
 * AIVideoUnlock — FULL v5
 *
 * Bisect result:
 *   L6+L7 alone     = no crash ✅
 *   L2+L6+L7        = crash ❌  (premium flag=true but server sends free-user JSON → Swift cast fails)
 *
 * Fix strategy:
 *   L1 (NSJSONSerialization) patches server JSON to match premium expectations.
 *   Rule: ONLY modify EXISTING keys — never add new ones, always preserve value type.
 *   L2 boolForKey/integerForKey kept (no objectForKey — too risky for Swift casts).
 *   L3 FIRRemoteConfig swizzle back (ARC-safe, read-only path).
 *   L6 SSL bypass.
 *   L7 restoreCompletedTransactions.
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
// LAYER 1 — NSJSONSerialization (type-preserving, existing-keys-only)
// ═══════════════════════════════════════════════════════════════════════
static NSString *const kPremiumKeyPat  = @"isPremiumUser|isPremium\\b|premium_active|hasActiveSubscription|isPro\\b|isSubscribed|premiumPurchased|hasPaid|is_premium|subscription_active";
static NSString *const kLockKeyPat     = @"isLocked|requiresPremium|pro_required|require_premium|premium_required|is_locked";
static NSString *const kLimitKeyPat    = @"limit|quota|max_|daily_|remaining_|credits";
static NSString *const kDateKeyPat     = @"expiresAt|expiry|expiration|expires_at|valid_until|subscription_end";

// Patch a single value, preserving its original type.
// Returns patched value or original if type unknown / not patchable.
static id patchValue(NSString *key, id value) {
    if (!value || [value isKindOfClass:[NSNull class]]) return value;

    // Premium/subscription keys → true/1
    if (matchesPattern(key, kPremiumKeyPat)) {
        if ([value isKindOfClass:[NSNumber class]]) {
            // Distinguish bool (objCType == 'c') from int
            const char *t = [(NSNumber *)value objCType];
            if (strcmp(t, @encode(BOOL)) == 0 || strcmp(t, @encode(bool)) == 0)
                return @YES;
            return @1;
        }
        if ([value isKindOfClass:[NSString class]]) {
            NSString *lo = [(NSString *)value lowercaseString];
            if ([lo isEqualToString:@"false"] || [lo isEqualToString:@"0"] || [lo isEqualToString:@"no"])
                return @"true";
        }
        return value;
    }

    // Lock keys → false/0
    if (matchesPattern(key, kLockKeyPat)) {
        if ([value isKindOfClass:[NSNumber class]]) {
            const char *t = [(NSNumber *)value objCType];
            if (strcmp(t, @encode(BOOL)) == 0 || strcmp(t, @encode(bool)) == 0)
                return @NO;
            return @0;
        }
        if ([value isKindOfClass:[NSString class]]) {
            NSString *lo = [(NSString *)value lowercaseString];
            if ([lo isEqualToString:@"true"] || [lo isEqualToString:@"1"] || [lo isEqualToString:@"yes"])
                return @"false";
        }
        return value;
    }

    // Limit/quota keys → large number, preserving type
    if (matchesPattern(key, kLimitKeyPat)) {
        if ([value isKindOfClass:[NSNumber class]]) {
            const char *t = [(NSNumber *)value objCType];
            if (strcmp(t, @encode(BOOL)) == 0 || strcmp(t, @encode(bool)) == 0)
                return value; // don't touch bool-typed limits
            // return same numeric type with large value
            if (strcmp(t, @encode(double)) == 0 || strcmp(t, @encode(float)) == 0)
                return @999999.0;
            return @999999;
        }
        return value;
    }

    // Expiry date keys → far future (year 2099), preserving type
    if (matchesPattern(key, kDateKeyPat)) {
        if ([value isKindOfClass:[NSNumber class]]) {
            // milliseconds or seconds — if > 1e10 it's ms, else seconds
            double orig = [(NSNumber *)value doubleValue];
            const char *t = [(NSNumber *)value objCType];
            double future = (orig > 1e10) ? 4102444800000.0 : 4102444800.0;
            if (strcmp(t, @encode(double)) == 0 || strcmp(t, @encode(float)) == 0)
                return @(future);
            return @((long long)future);
        }
        if ([value isKindOfClass:[NSString class]]) {
            // ISO date string — return a far-future date
            return @"2099-01-01T00:00:00Z";
        }
        return value;
    }

    return value;
}

// Recursively patch a JSON object (dict or array).
static id patchJSON(id obj) {
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary *d = (NSDictionary *)obj;
        NSMutableDictionary *out = [NSMutableDictionary dictionaryWithCapacity:d.count];
        [d enumerateKeysAndObjectsUsingBlock:^(NSString *key, id val, BOOL *stop) {
            id patched = patchValue(key, val);
            // Recurse into nested dicts/arrays (but don't recurse into already-patched primitives)
            if (patched == val && ([val isKindOfClass:[NSDictionary class]] || [val isKindOfClass:[NSArray class]]))
                patched = patchJSON(val);
            out[key] = patched ?: val;
        }];
        return out;
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        NSArray *a = (NSArray *)obj;
        NSMutableArray *out = [NSMutableArray arrayWithCapacity:a.count];
        for (id item in a) [out addObject:patchJSON(item)];
        return out;
    }
    return obj;
}

%hook NSJSONSerialization

+ (id)JSONObjectWithData:(NSData *)data options:(NSJSONReadingOptions)opt error:(NSError **)err {
    id orig = %orig;
    if (!orig) return orig;
    @try { return patchJSON(orig); }
    @catch (NSException *e) { TWLog(@"[L1] patch err: %@", e); }
    return orig;
}

%end

// ═══════════════════════════════════════════════════════════════════════
// LAYER 2 — NSUserDefaults (boolForKey + integerForKey, no objectForKey)
// ═══════════════════════════════════════════════════════════════════════
%hook NSUserDefaults

- (BOOL)boolForKey:(NSString *)key {
    BOOL r = %orig;
    if (!r && matchesPattern(key, kPremiumKeyPat)) return YES;
    return r;
}

- (NSInteger)integerForKey:(NSString *)key {
    NSInteger r = %orig;
    if (r != 1 && matchesPattern(key, kPremiumKeyPat)) return 1;
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
        if (matchesPattern(key, kPremiumKeyPat) || matchesPattern(key, kLockKeyPat))
            newValue = @"false";
        else if (matchesPattern(key, kLimitKeyPat))
            newValue = @"999999";
        if (!newValue) return orig;

        NSData *d = [newValue dataUsingEncoding:NSUTF8StringEncoding];
        SEL initSel = NSSelectorFromString(@"initWithData:source:");
        id raw = [FIRRCV alloc];
        if (![raw respondsToSelector:initSel]) return orig;
        id v = ((id (*)(id, SEL, NSData *, int))objc_msgSend)(raw, initSel, d, 2);
        if (!v) return orig;
        return v;
    } @catch (NSException *e) { TWLog(@"[L3] err: %@", e); }
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
            TWLog(@"════════════════════════════════════════════");
            TWLog(@" AIVideoUnlock v5 loaded — %@", [[NSBundle mainBundle] bundleIdentifier]);
            TWLog(@"════════════════════════════════════════════");

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
                        TWLog(@"[init] FIRRemoteConfig swizzled");
                    }
                }
            } @catch (NSException *e) { TWLog(@"[init] FIRRC err: %@", e); }

#if ENABLE_PIN_BYPASS
            @try {
                void *sec1 = dlsym(RTLD_DEFAULT, "SecTrustEvaluate");
                if (sec1) MSHookFunction(sec1, (void *)new_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate);
                void *sec2 = dlsym(RTLD_DEFAULT, "SecTrustEvaluateWithError");
                if (sec2) MSHookFunction(sec2, (void *)new_SecTrustEvaluateWithError, (void **)&orig_SecTrustEvaluateWithError);
            } @catch (NSException *e) { TWLog(@"[init] SecTrust err: %@", e); }

            @try {
                if (NSClassFromString(@"AFSecurityPolicy")) { %init(AFNetworkingPin); }
            } @catch (NSException *e) { TWLog(@"[init] AF err: %@", e); }

            @try {
                if (NSClassFromString(@"TSKPinningValidator")) { %init(TrustKitPin); }
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

            TWLog(@"[init] v5 ready");
        } @catch (NSException *e) {
            TWLog(@"[ctor] fatal: %@", e);
        }
    }
}

/*
 * AIVideoUnlock — v8 (ported from working Frida script)
 *
 * Root cause confirmed:
 *   L2 (boolForKey=YES) triggers app to verify receipt with Apple.
 *   Apple returns empty receipt → app tries Swift cast → swift_dynamicCast crash.
 *
 * Fix: port the Frida receipt forger exactly.
 *   L1 ONLY fires on Apple receipt responses (has "receipt"/"environment"/"latest_receipt").
 *   Injects real product IDs: gen_ai_yearly_2999 + gen_ai_weekly_999, status=0, far-future expiry.
 *   L2 restored (all threads) — same as Frida which works.
 *   L6 SSL bypass kept. L7 StoreKit restore kept. L3 FIRRC kept.
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

static NSString *const kPremiumPat = @"isPremiumUser|isPremium\\b|premium_active|hasActiveSubscription|isPro\\b|isSubscribed|premiumPurchased|hasPaid|is_premium|subscription_active";
static NSString *const kLimitPat   = @"limit|quota|max_|daily_|remaining_|credits";
static NSString *const kLockPat    = @"isLocked|requiresPremium|pro_required|require_premium|premium_required|is_locked";

static BOOL matchesPattern(NSString *str, NSString *pattern) {
    if (!str || ![str isKindOfClass:[NSString class]]) return NO;
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                       options:NSRegularExpressionCaseInsensitive
                                                                         error:nil];
    if (!re) return NO;
    return [re numberOfMatchesInString:str options:0 range:NSMakeRange(0, str.length)] > 0;
}

// ═══════════════════════════════════════════════════════════════════════
// LAYER 1 — Apple receipt forger (exact port of Frida v5)
// Only fires when response has receipt/environment/latest_receipt keys.
// ═══════════════════════════════════════════════════════════════════════
static BOOL looksLikeAppleReceipt(NSDictionary *d) {
    if (![d isKindOfClass:[NSDictionary class]]) return NO;
    return (d[@"receipt"] != nil || d[@"environment"] != nil || d[@"latest_receipt"] != nil);
}

static NSDictionary *buildReceiptInfo(NSString *productID) {
    return @{
        @"product_id"                : productID,
        @"expires_date_ms"           : @"4070908800000",
        @"transaction_id"            : @"1000000000000001",
        @"original_transaction_id"   : @"1000000000000001",
        @"purchase_date_ms"          : @"1700000000000",
        @"original_purchase_date_ms" : @"1700000000000",
        @"is_trial_period"           : @"0",
        @"is_in_intro_offer_period"  : @"0",
        @"quantity"                  : @"1",
        @"web_order_line_item_id"    : @"1"
    };
}

static NSDictionary *buildRenewalInfo(NSString *productID) {
    return @{
        @"product_id"            : productID,
        @"auto_renew_product_id" : productID,
        @"auto_renew_status"     : @"1"
    };
}

static id forgeAppleReceipt(NSDictionary *orig) {
    // Check if already has valid products
    id existingInfo = orig[@"latest_receipt_info"];
    BOOL hasRealProducts = NO;
    if ([existingInfo isKindOfClass:[NSArray class]])
        hasRealProducts = [(NSArray *)existingInfo count] > 0;

    id statusObj = orig[@"status"];
    int oldStatus = [statusObj isKindOfClass:[NSNumber class]] ? [(NSNumber *)statusObj intValue] : -1;

    if (oldStatus == 0 && hasRealProducts) {
        TWLog(@"[L1] receipt status=0 with products — passthrough");
        return orig;
    }

    TWLog(@"[L1] forging receipt (status=%d hasProducts=%d)", oldStatus, hasRealProducts);

    NSMutableDictionary *out = [NSMutableDictionary dictionaryWithDictionary:orig];
    out[@"status"]      = @0;
    out[@"environment"] = @"Production";

    out[@"latest_receipt_info"] = @[
        buildReceiptInfo(@"gen_ai_yearly_2999"),
        buildReceiptInfo(@"gen_ai_weekly_999")
    ];
    out[@"pending_renewal_info"] = @[
        buildRenewalInfo(@"gen_ai_yearly_2999"),
        buildRenewalInfo(@"gen_ai_weekly_999")
    ];

    return out;
}

%hook NSJSONSerialization
+ (id)JSONObjectWithData:(NSData *)data options:(NSJSONReadingOptions)opt error:(NSError **)err {
    id orig = %orig;
    if (!orig || ![orig isKindOfClass:[NSDictionary class]]) return orig;
    @try {
        if (looksLikeAppleReceipt(orig)) return forgeAppleReceipt(orig);
    } @catch (NSException *e) { TWLog(@"[L1] err: %@", e); }
    return orig;
}
%end

// ═══════════════════════════════════════════════════════════════════════
// LAYER 2 — NSUserDefaults (all threads — same as Frida)
// ═══════════════════════════════════════════════════════════════════════
%hook NSUserDefaults

- (BOOL)boolForKey:(NSString *)key {
    BOOL r = %orig;
    if (!r && matchesPattern(key, kPremiumPat)) return YES;
    return r;
}

- (NSInteger)integerForKey:(NSString *)key {
    NSInteger r = %orig;
    if (r != 1 && matchesPattern(key, kPremiumPat)) return 1;
    return r;
}

- (id)objectForKey:(NSString *)key {
    id r = %orig;
    if (matchesPattern(key, kPremiumPat)) return @YES;
    return r;
}

%end

// ═══════════════════════════════════════════════════════════════════════
// LAYER 3 — FIRRemoteConfig swizzle
// ═══════════════════════════════════════════════════════════════════════
static IMP origFIRConfigValueForKey = NULL;

static id swizzled_FIRConfigValueForKey(id self, SEL _cmd, NSString *key) {
    id orig = ((id (*)(id, SEL, NSString *))origFIRConfigValueForKey)(self, _cmd, key);
    @try {
        if (!key || ![key isKindOfClass:[NSString class]]) return orig;
        Class FIRRCV = NSClassFromString(@"FIRRemoteConfigValue");
        if (!FIRRCV) return orig;
        NSString *newValue = nil;
        if (matchesPattern(key, kPremiumPat) || matchesPattern(key, kLockPat)) newValue = @"false";
        else if (matchesPattern(key, kLimitPat)) newValue = @"999999";
        if (!newValue) return orig;
        NSData *d = [newValue dataUsingEncoding:NSUTF8StringEncoding];
        SEL initSel = NSSelectorFromString(@"initWithData:source:");
        id raw = [FIRRCV alloc];
        if (![raw respondsToSelector:initSel]) return orig;
        id v = ((id (*)(id, SEL, NSData *, int))objc_msgSend)(raw, initSel, d, 2);
        return v ?: orig;
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
            TWLog(@"[L7] restoreCompletedTransactions called");
        } @catch (NSException *e) { TWLog(@"[L7] err: %@", e); }
    });
}

// ═══════════════════════════════════════════════════════════════════════
// Constructor
// ═══════════════════════════════════════════════════════════════════════
%ctor {
    @autoreleasepool {
        @try {
            TWLog(@"════════════════════════════════════════════");
            TWLog(@" AIVideoUnlock v8 — %@", [[NSBundle mainBundle] bundleIdentifier]);
            TWLog(@"════════════════════════════════════════════");

            %init();

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
            } @catch (NSException *e) {}

            @try {
                if (NSClassFromString(@"TSKPinningValidator")) { %init(TrustKitPin); }
            } @catch (NSException *e) {}
#endif

            CFNotificationCenterAddObserver(
                CFNotificationCenterGetLocalCenter(),
                NULL,
                onAppLaunched,
                (CFStringRef)UIApplicationDidFinishLaunchingNotification,
                NULL,
                CFNotificationSuspensionBehaviorDeliverImmediately
            );

            TWLog(@"[init] v8 ready");
        } @catch (NSException *e) {
            TWLog(@"[ctor] fatal: %@", e);
        }
    }
}

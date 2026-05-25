/*
 * AIVideoUnlock — v9 (100% faithful Frida port, nothing extra)
 *
 * Previous versions had extra patterns + extra layers not in the Frida script.
 * This is a minimal, exact port of the working Frida v5:
 *   - NSJSONSerialization receipt forger (identical logic)
 *   - NSUserDefaults: exact same 4-key pattern, exact same selectors
 *   - SKPaymentQueue restore (guarded)
 *   - NO FIRRC, NO SSL bypass, NO NSFileManager — Frida doesn't need these
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>

#define TWLog(fmt, ...) NSLog(@"[AIUnlock] " fmt, ##__VA_ARGS__)

// Exact same 4-key pattern as Frida v5
static NSRegularExpression *sPremiumRE = nil;

static BOOL matchesPremiumKey(NSString *key) {
    if (!key || ![key isKindOfClass:[NSString class]]) return NO;
    if (!sPremiumRE) {
        sPremiumRE = [NSRegularExpression
            regularExpressionWithPattern:@"isPremiumUser|isPremium\\b|premium_active|hasActiveSubscription"
                                 options:NSRegularExpressionCaseInsensitive
                                   error:nil];
    }
    return [sPremiumRE numberOfMatchesInString:key options:0 range:NSMakeRange(0, key.length)] > 0;
}

// ═══════════════════════════════════════════════════════════════════════
// LAYER 1 — Apple receipt forger (identical to Frida v5)
// ═══════════════════════════════════════════════════════════════════════
static BOOL looksLikeAppleReceipt(NSDictionary *d) {
    if (![d isKindOfClass:[NSDictionary class]]) return NO;
    // Must have "status" key (same guard as Frida)
    if (!d[@"status"]) return NO;
    return (d[@"receipt"] != nil || d[@"environment"] != nil || d[@"latest_receipt"] != nil);
}

static NSDictionary *buildInfo(NSString *pid) {
    return @{
        @"product_id"                : pid,
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

static NSDictionary *buildRenewal(NSString *pid) {
    return @{
        @"product_id"            : pid,
        @"auto_renew_product_id" : pid,
        @"auto_renew_status"     : @"1"
    };
}

%hook NSJSONSerialization

+ (id)JSONObjectWithData:(NSData *)data options:(NSJSONReadingOptions)opt error:(NSError **)err {
    id orig = %orig;
    if (!orig || ![orig isKindOfClass:[NSDictionary class]]) return orig;
    @try {
        NSDictionary *d = (NSDictionary *)orig;
        if (!looksLikeAppleReceipt(d)) return orig;

        NSNumber *statusNum = d[@"status"];
        int oldStatus = statusNum ? [statusNum intValue] : -1;

        // Check if already valid
        id existingInfo = d[@"latest_receipt_info"];
        BOOL hasProducts = [existingInfo isKindOfClass:[NSArray class]] && [(NSArray *)existingInfo count] > 0;

        if (oldStatus == 0 && hasProducts) {
            TWLog(@"[L1] receipt ok (status=0, has products) — passthrough");
            return orig;
        }

        TWLog(@"[L1] forging receipt status=%d hasProducts=%d", oldStatus, hasProducts);

        NSMutableDictionary *out = [NSMutableDictionary dictionaryWithDictionary:d];
        out[@"status"]      = @0;
        out[@"environment"] = @"Production";
        out[@"latest_receipt_info"] = @[
            buildInfo(@"gen_ai_yearly_2999"),
            buildInfo(@"gen_ai_weekly_999")
        ];
        out[@"pending_renewal_info"] = @[
            buildRenewal(@"gen_ai_yearly_2999"),
            buildRenewal(@"gen_ai_weekly_999")
        ];
        return out;
    } @catch (NSException *e) { TWLog(@"[L1] err: %@", e); }
    return orig;
}

%end

// ═══════════════════════════════════════════════════════════════════════
// LAYER 2 — NSUserDefaults (exact Frida pattern, exact selectors)
// ═══════════════════════════════════════════════════════════════════════
%hook NSUserDefaults

- (BOOL)boolForKey:(NSString *)key {
    BOOL r = %orig;
    if (!r && matchesPremiumKey(key)) { TWLog(@"[L2] boolForKey '%@' → YES", key); return YES; }
    return r;
}

- (NSInteger)integerForKey:(NSString *)key {
    NSInteger r = %orig;
    if (r != 1 && matchesPremiumKey(key)) { TWLog(@"[L2] integerForKey '%@' → 1", key); return 1; }
    return r;
}

- (id)objectForKey:(NSString *)key {
    id r = %orig;
    if (matchesPremiumKey(key)) {
        TWLog(@"[L2] objectForKey '%@' → @YES", key);
        return @YES;
    }
    return r;
}

%end

// ═══════════════════════════════════════════════════════════════════════
// LAYER 7 — StoreKit restore (guarded, same as Frida)
// ═══════════════════════════════════════════════════════════════════════
static void onAppLaunched(CFNotificationCenterRef c, void *o, CFNotificationName n,
                          const void *obj, CFDictionaryRef i) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        @try {
            Class SK = NSClassFromString(@"SKPaymentQueue");
            if (!SK) { TWLog(@"[L7] SKPaymentQueue missing"); return; }
            id q = ((id(*)(id,SEL))objc_msgSend)((id)SK, @selector(defaultQueue));
            if (!q) { TWLog(@"[L7] queue nil"); return; }
            ((void(*)(id,SEL))objc_msgSend)(q, @selector(restoreCompletedTransactions));
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
            TWLog(@"═══════════════════════════════");
            TWLog(@" AIVideoUnlock v9 — %@", [[NSBundle mainBundle] bundleIdentifier]);
            TWLog(@"═══════════════════════════════");

            %init();

            CFNotificationCenterAddObserver(
                CFNotificationCenterGetLocalCenter(), NULL, onAppLaunched,
                (CFStringRef)UIApplicationDidFinishLaunchingNotification,
                NULL, CFNotificationSuspensionBehaviorDeliverImmediately);

            TWLog(@"[init] v9 ready — exact Frida port");
        } @catch (NSException *e) { TWLog(@"[ctor] fatal: %@", e); }
    }
}

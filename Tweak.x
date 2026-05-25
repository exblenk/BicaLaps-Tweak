/*
 * AIVideoUnlock — Theos tweak port of unlock-deep.js (hardened)
 *
 * Fixes from prior version:
 *  - Removed bogus %hook NSObject placeholder
 *  - Replaced UIApplication-launch hook with NSNotificationCenter observer
 *    (didFinishLaunchingWithOptions is on AppDelegate, not UIApplication)
 *  - Wrapped optional class hooks (AFSecurityPolicy, TSKPinningValidator)
 *    in %group + %init() — only initialized when the class exists
 *  - Blocks for gate rewriters are [Block_copy]'d into the dictionary
 *  - All %ctor work wrapped in @try/@catch so a single failure doesn't crash
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <substrate.h>

// ─── toggles ───────────────────────────────────────────────────────────
// #define ENABLE_CC_OBSERVER 1
#define ENABLE_NET_LOG     1
#define ENABLE_PIN_BYPASS  1

#define TWLog(fmt, ...) NSLog(@"[AIUnlock] " fmt, ##__VA_ARGS__)

static NSString *const PRODUCT_YEAR  = @"gen_ai_yearly_2999";
static NSString *const PRODUCT_WEEK  = @"gen_ai_weekly_999";
static NSString *const FAR_FUTURE_MS = @"4070908800000";

// ─── helpers ───────────────────────────────────────────────────────────
static NSMutableDictionary *buildReceiptInfo(NSString *pid) {
    return [@{
        @"product_id":                pid,
        @"expires_date_ms":           FAR_FUTURE_MS,
        @"transaction_id":            @"1000000000000001",
        @"original_transaction_id":   @"1000000000000001",
        @"purchase_date_ms":          @"1700000000000",
        @"original_purchase_date_ms": @"1700000000000",
        @"is_trial_period":           @"0",
        @"is_in_intro_offer_period":  @"0",
        @"quantity":                  @"1",
        @"web_order_line_item_id":    @"1",
    } mutableCopy];
}

static NSMutableDictionary *buildRenewal(NSString *pid) {
    return [@{
        @"product_id":            pid,
        @"auto_renew_product_id": pid,
        @"auto_renew_status":     @"1",
    } mutableCopy];
}

static BOOL looksLikeAppleReceipt(NSDictionary *d) {
    if (![d isKindOfClass:[NSDictionary class]]) return NO;
    if (!d[@"status"]) return NO;
    return d[@"receipt"] != nil || d[@"environment"] != nil || d[@"latest_receipt"] != nil;
}

static BOOL matchesPattern(NSString *str, NSString *pattern) {
    if (!str || ![str isKindOfClass:[NSString class]]) return NO;
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                       options:NSRegularExpressionCaseInsensitive
                                                                         error:nil];
    if (!re) return NO;
    return [re numberOfMatchesInString:str options:0 range:NSMakeRange(0, str.length)] > 0;
}

// ═══════════════════════════════════════════════════════════════════════
// LAYER 1 — NSJSONSerialization
// ═══════════════════════════════════════════════════════════════════════
%hook NSJSONSerialization

+ (id)JSONObjectWithData:(NSData *)data options:(NSJSONReadingOptions)opt error:(NSError **)error {
    id obj = %orig;
    @try {
        if (!obj || ![obj isKindOfClass:[NSDictionary class]]) return obj;
        NSDictionary *dict = (NSDictionary *)obj;

        if (looksLikeAppleReceipt(dict)) {
            NSInteger status = [dict[@"status"] integerValue];
            NSArray *info = dict[@"latest_receipt_info"];
            BOOL hasProducts = [info isKindOfClass:[NSArray class]] && info.count > 0;
            TWLog(@"[HIT] Apple receipt status=%ld hasProducts=%d", (long)status, hasProducts);

            if (status == 0 && hasProducts) {
                TWLog(@"[SKIP] valid receipt — pass through");
                return obj;
            }

            NSMutableDictionary *m = [dict mutableCopy];
            m[@"status"] = @(0);
            m[@"latest_receipt_info"] = @[buildReceiptInfo(PRODUCT_YEAR), buildReceiptInfo(PRODUCT_WEEK)];
            m[@"pending_renewal_info"] = @[buildRenewal(PRODUCT_YEAR), buildRenewal(PRODUCT_WEEK)];
            m[@"environment"] = @"Production";
            TWLog(@"[PATCH] receipt → status=0 + yearly+weekly @2099");
            return m;
        }

        if ([dict[@"fields"] isKindOfClass:[NSDictionary class]]) {
            NSMutableDictionary *m = [dict mutableCopy];
            NSMutableDictionary *fields = [dict[@"fields"] mutableCopy];
            BOOL touched = NO;
            for (NSString *k in [fields allKeys]) {
                if (![k isKindOfClass:[NSString class]]) continue;
                if (matchesPattern(k, @"premium|pro\\b|subscribed|active|paid")) {
                    fields[k] = @{@"booleanValue": @YES};
                    touched = YES;
                } else if (matchesPattern(k, @"count|limit|quota|left|remaining|videos")) {
                    fields[k] = @{@"integerValue": @"999999"};
                    touched = YES;
                } else if (matchesPattern(k, @"expir|renew")) {
                    fields[k] = @{@"stringValue": @"2099-12-31T23:59:59Z"};
                    touched = YES;
                }
            }
            if (touched) {
                m[@"fields"] = fields;
                TWLog(@"[GATE] Firestore user document patched");
                return m;
            }
        }
    } @catch (NSException *e) {
        TWLog(@"[err] L1: %@", e);
    }
    return obj;
}

%end

// ═══════════════════════════════════════════════════════════════════════
// LAYER 2 — NSUserDefaults
// ═══════════════════════════════════════════════════════════════════════
static NSString *const kPremiumPattern = @"isPremiumUser|isPremium\\b|premium_active|hasActiveSubscription|isPro\\b|isSubscribed|premiumPurchased|hasPaid";

%hook NSUserDefaults

- (BOOL)boolForKey:(NSString *)key {
    BOOL r = %orig;
    if (!r && matchesPattern(key, kPremiumPattern)) {
        return YES;
    }
    return r;
}

- (NSInteger)integerForKey:(NSString *)key {
    NSInteger r = %orig;
    if (r != 1 && matchesPattern(key, kPremiumPattern)) {
        return 1;
    }
    return r;
}

- (id)objectForKey:(NSString *)key {
    id r = %orig;
    if (matchesPattern(key, kPremiumPattern)) {
        return @YES;
    }
    return r;
}

%end

// ═══════════════════════════════════════════════════════════════════════
// LAYER 3 — FIRRemoteConfig (dynamic swizzle in %ctor below)
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
        SEL init = NSSelectorFromString(@"initWithData:source:");
        id v = [[FIRRCV alloc] init];
        if ([v respondsToSelector:init]) {
            ((void (*)(id, SEL, NSData *, int))objc_msgSend)(v, init, d, 2);
            return v;
        }
    } @catch (NSException *e) {
        TWLog(@"[err] L3: %@", e);
    }
    return orig;
}

// ═══════════════════════════════════════════════════════════════════════
// LAYER 4 — NSURLSession response rewriter
// ═══════════════════════════════════════════════════════════════════════
static NSArray<NSDictionary *> *gatePatches(void) {
    static NSArray *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSDictionary *(^rwFirebase)(NSDictionary *) = [^NSDictionary *(NSDictionary *j) {
            if (![j[@"entries"] isKindOfClass:[NSDictionary class]]) return j;
            NSMutableDictionary *m = [j mutableCopy];
            NSMutableDictionary *e = [j[@"entries"] mutableCopy];
            for (NSString *k in [e allKeys]) {
                if (matchesPattern(k, @"premium|paid|pro\\b|locked|require")) e[k] = @"false";
                else if (matchesPattern(k, @"limit|quota|max|daily"))         e[k] = @"999999";
                else if (matchesPattern(k, @"enabled|show"))                  e[k] = @"true";
            }
            m[@"entries"] = e;
            return m;
        } copy];

        NSDictionary *(^rwCloudFn)(NSDictionary *) = [^NSDictionary *(NSDictionary *j) {
            NSMutableDictionary *m = [j mutableCopy];
            m[@"isPremium"] = @YES;
            m[@"isPro"] = @YES;
            m[@"isSubscribed"] = @YES;
            m[@"expiresAt"] = FAR_FUTURE_MS;
            m[@"status"] = @"active";
            return m;
        } copy];

        NSDictionary *(^rwKie)(NSDictionary *) = [^NSDictionary *(NSDictionary *j) {
            NSMutableDictionary *m = [j mutableCopy];
            if (m[@"code"]) m[@"code"] = @(200);
            if (m[@"msg"])  m[@"msg"]  = @"success";
            if ([m[@"data"] isKindOfClass:[NSDictionary class]]) {
                NSMutableDictionary *d = [m[@"data"] mutableCopy];
                if (d[@"credits"]) d[@"credits"] = @(999999);
                if (d[@"quota"])   d[@"quota"]   = @(999999);
                m[@"data"] = d;
            }
            return m;
        } copy];

        NSDictionary *(^rwAws)(NSDictionary *) = [^NSDictionary *(NSDictionary *j) {
            NSMutableDictionary *m = [j mutableCopy];
            if (m[@"videosLeft"])      m[@"videosLeft"] = @(999);
            if (m[@"isServerBusy"])    m[@"isServerBusy"] = @NO;
            if (m[@"isGrokServerBusy"]) m[@"isGrokServerBusy"] = @NO;
            if (m[@"quotaExceeded"])   m[@"quotaExceeded"] = @NO;
            if (m[@"isShow"])          m[@"isShow"] = @YES;
            return m;
        } copy];

        NSDictionary *(^rwFirestore)(NSDictionary *) = [^NSDictionary *(NSDictionary *j) {
            if (![j[@"fields"] isKindOfClass:[NSDictionary class]]) return j;
            NSMutableDictionary *m = [j mutableCopy];
            NSMutableDictionary *f = [j[@"fields"] mutableCopy];
            for (NSString *k in [f allKeys]) {
                if (matchesPattern(k, @"premium|pro\\b|subscribed|active|paid"))
                    f[k] = @{@"booleanValue": @YES};
                else if (matchesPattern(k, @"count|limit|quota|left|remaining|videos"))
                    f[k] = @{@"integerValue": @"999999"};
                else if (matchesPattern(k, @"expir|renew"))
                    f[k] = @{@"stringValue": @"2099-12-31T23:59:59Z"};
            }
            m[@"fields"] = f;
            return m;
        } copy];

        cached = @[
            @{@"name": @"firebase-remote-config",
              @"pattern": @"firebaseremoteconfig\\.googleapis\\.com.*namespaces/firebase:fetch",
              @"rewrite": rwFirebase},
            @{@"name": @"cloud-functions",
              @"pattern": @"cloudfunctions\\.net|us-central1-.*\\.cloudfunctions\\.net",
              @"rewrite": rwCloudFn},
            @{@"name": @"kie.ai",
              @"pattern": @"api\\.kie\\.ai",
              @"rewrite": rwKie},
            @{@"name": @"aws-execute-api",
              @"pattern": @"execute-api\\..*amazonaws\\.com",
              @"rewrite": rwAws},
            @{@"name": @"firestore-doc",
              @"pattern": @"firestore\\.googleapis\\.com.*/documents/users/",
              @"rewrite": rwFirestore},
        ];
    });
    return cached;
}

%hook NSURLSession

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request
                            completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))handler {
    @try {
        NSString *url = request.URL.absoluteString;
#if ENABLE_NET_LOG
        TWLog(@"[NET] %@ %@", request.HTTPMethod ?: @"GET", url);
#endif

        if (!handler || !url) return %orig;

        NSDictionary *matched = nil;
        for (NSDictionary *p in gatePatches()) {
            if (matchesPattern(url, p[@"pattern"])) { matched = p; break; }
        }
        if (!matched) return %orig;

        TWLog(@"[GATE] match: %@", matched[@"name"]);
        NSDictionary *(^rw)(NSDictionary *) = matched[@"rewrite"];
        NSString *patchName = matched[@"name"];

        void (^wrapped)(NSData *, NSURLResponse *, NSError *) =
        ^(NSData *data, NSURLResponse *resp, NSError *err) {
            @try {
                if (data) {
                    id parsed = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                    if ([parsed isKindOfClass:[NSDictionary class]]) {
                        NSDictionary *patched = rw(parsed);
                        NSData *newData = [NSJSONSerialization dataWithJSONObject:patched options:0 error:nil];
                        if (newData) {
                            TWLog(@"[PATCH] (%@) rewritten", patchName);
                            handler(newData, resp, err);
                            return;
                        }
                    }
                }
            } @catch (NSException *e) { TWLog(@"[err] gate %@: %@", patchName, e); }
            handler(data, resp, err);
        };

        return %orig(request, wrapped);
    } @catch (NSException *e) {
        TWLog(@"[err] L4: %@", e);
        return %orig;
    }
}

%end

// ═══════════════════════════════════════════════════════════════════════
// LAYER 5 — CCCrypt observer (optional)
// ═══════════════════════════════════════════════════════════════════════
#if ENABLE_CC_OBSERVER
static CCCryptorStatus (*orig_CCCrypt)(CCOperation, CCAlgorithm, CCOptions,
                                       const void *, size_t, const void *,
                                       const void *, size_t, void *, size_t, size_t *);

static CCCryptorStatus new_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions opts,
                                   const void *key, size_t keyLen,
                                   const void *iv, const void *dataIn, size_t dataInLen,
                                   void *dataOut, size_t dataOutAvail, size_t *dataOutMoved) {
    CCCryptorStatus r = orig_CCCrypt(op, alg, opts, key, keyLen, iv, dataIn, dataInLen,
                                     dataOut, dataOutAvail, dataOutMoved);
    if (dataInLen > 64) {
        NSData *keyData = [NSData dataWithBytes:key length:MIN(keyLen, (size_t)32)];
        TWLog(@"[CC] %@ alg=%d in=%zu key=%@",
              op == kCCEncrypt ? @"ENC" : @"DEC", (int)alg, dataInLen, keyData);
    }
    return r;
}
#endif

// ═══════════════════════════════════════════════════════════════════════
// LAYER 6 — SSL pinning bypass (system funcs + conditional class hooks)
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

// Optional class hooks — only initialized in %ctor if class exists
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
// LAYER 7 — Auto-trigger restoreCompletedTransactions via notification
// ═══════════════════════════════════════════════════════════════════════
static void onAppLaunched(CFNotificationCenterRef center, void *observer,
                          CFNotificationName name, const void *object,
                          CFDictionaryRef userInfo) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
            Class SK = NSClassFromString(@"SKPaymentQueue");
            if (!SK) {
                TWLog(@"[TRIGGER] SKPaymentQueue not present");
                return;
            }
            id q = [SK performSelector:@selector(defaultQueue)];
            if (!q) {
                TWLog(@"[TRIGGER] queue nil");
                return;
            }
            [q performSelector:@selector(restoreCompletedTransactions)];
            TWLog(@"[TRIGGER] restoreCompletedTransactions called");
        } @catch (NSException *e) {
            TWLog(@"[TRIGGER] err: %@", e);
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════
// Constructor
// ═══════════════════════════════════════════════════════════════════════
%ctor {
    @autoreleasepool {
        @try {
            TWLog(@"════════════════════════════════════════════");
            TWLog(@" AIVideoUnlock loaded into %@", [[NSBundle mainBundle] bundleIdentifier]);
            TWLog(@"════════════════════════════════════════════");

            // Required when any %group is used — initializes the ungrouped hooks
            // (NSJSONSerialization, NSUserDefaults, NSURLSession).
            %init();

            // L3 — FIRRemoteConfig swizzle if class present
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
            // L6 — SSL pinning: C funcs
            @try {
                void *sec1 = dlsym(RTLD_DEFAULT, "SecTrustEvaluate");
                if (sec1) MSHookFunction(sec1, (void *)new_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate);
                void *sec2 = dlsym(RTLD_DEFAULT, "SecTrustEvaluateWithError");
                if (sec2) MSHookFunction(sec2, (void *)new_SecTrustEvaluateWithError, (void **)&orig_SecTrustEvaluateWithError);
                TWLog(@"[init] SecTrust* hooked");
            } @catch (NSException *e) { TWLog(@"[init] SecTrust err: %@", e); }

            // L6 — SSL pinning: optional class hooks
            @try {
                if (NSClassFromString(@"AFSecurityPolicy")) {
                    %init(AFNetworkingPin);
                    TWLog(@"[init] AFSecurityPolicy hooked");
                }
            } @catch (NSException *e) { TWLog(@"[init] AF err: %@", e); }

            @try {
                if (NSClassFromString(@"TSKPinningValidator")) {
                    %init(TrustKitPin);
                    TWLog(@"[init] TrustKit hooked");
                }
            } @catch (NSException *e) { TWLog(@"[init] TSK err: %@", e); }
#endif

#if ENABLE_CC_OBSERVER
            @try {
                void *cc = dlsym(RTLD_DEFAULT, "CCCrypt");
                if (cc) {
                    MSHookFunction(cc, (void *)new_CCCrypt, (void **)&orig_CCCrypt);
                    TWLog(@"[init] CCCrypt observer armed");
                }
            } @catch (NSException *e) { TWLog(@"[init] CC err: %@", e); }
#endif

            // L7 — register launch observer
            CFNotificationCenterAddObserver(
                CFNotificationCenterGetLocalCenter(),
                NULL,
                onAppLaunched,
                (CFStringRef)UIApplicationDidFinishLaunchingNotification,
                NULL,
                CFNotificationSuspensionBehaviorDeliverImmediately
            );

            TWLog(@"[init] all layers armed");
        } @catch (NSException *e) {
            TWLog(@"[ctor] fatal: %@", e);
        }
    }
}

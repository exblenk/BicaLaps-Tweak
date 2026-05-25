/*
 * AIVideoUnlock — Theos tweak port of unlock-deep.js
 *
 * Layers:
 *   L1 Receipt forger + Firestore document patcher (NSJSONSerialization)
 *   L2 UserDefaults premium-key override
 *   L3 FIRRemoteConfig configValueForKey override
 *   L4 NSURLSession response rewriter (Firebase / Cloud Functions / kie.ai / AWS / Firestore)
 *   L5 CCCrypt observer (optional, off by default for perf — flip #define to enable)
 *   L6 SSL pinning bypass (SecTrustEvaluate + AFNetworking + TrustKit)
 *   L7 Auto-trigger restoreCompletedTransactions on launch
 *
 * Target: com.saidul.aivideo (AI_Video_Maker)
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <objc/runtime.h>
#import <dlfcn.h>

// ─── toggles ───────────────────────────────────────────────────────────
// #define ENABLE_CC_OBSERVER  1   // enable CCCrypt observer (verbose)
#define ENABLE_NET_LOG          1   // log all URLs
#define ENABLE_PIN_BYPASS       1   // bypass SSL pinning (for proxy interception)
#define ENABLE_JSON_HOOK        1   // L1: NSJSONSerialization hook
#define ENABLE_RESP_REWRITE     1   // L4: NSURLSession response rewriter
#define ENABLE_FIRESTORE_IN_L1  0   // L1 Path B: Firestore patch in JSON hook (broad, off — L4 covers it)
#define ENABLE_RW_CLOUDFN       0   // L4: cloud-functions rewriter (risky — added shape changes)
#define ENABLE_RW_AWS           1
#define ENABLE_RW_KIE           1
#define ENABLE_RW_FIREBASE      1
#define ENABLE_RW_FIRESTORE     1

#define TWLog(fmt, ...) NSLog(@"[AIUnlock] " fmt, ##__VA_ARGS__)

static NSString *const PRODUCT_YEAR  = @"gen_ai_yearly_2999";
static NSString *const PRODUCT_WEEK  = @"gen_ai_weekly_999";
static NSString *const FAR_FUTURE_MS = @"4070908800000";
static NSNumber *const FAR_FUTURE_MS_NUM = @4070908800000;
static NSString *const FAR_FUTURE_ISO = @"2099-12-31T23:59:59Z";

// Type-preserving patch: matches the original value's class.
static id matchType(id orig, NSNumber *boolVal, NSNumber *numVal, NSString *strVal) {
    if (!orig) return boolVal;
    if ([orig isKindOfClass:[NSNumber class]]) {
        const char *t = [(NSNumber *)orig objCType];
        if (t && (t[0] == 'c' || t[0] == 'B')) return boolVal;  // bool
        return numVal;
    }
    if ([orig isKindOfClass:[NSString class]]) return strVal;
    return orig;
}

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
    return d[@"receipt"] || d[@"environment"] || d[@"latest_receipt"];
}

static NSRegularExpression *regex(NSString *pattern) {
    return [NSRegularExpression regularExpressionWithPattern:pattern
                                                     options:NSRegularExpressionCaseInsensitive
                                                       error:nil];
}

static BOOL matchesPattern(NSString *str, NSString *pattern) {
    if (!str) return NO;
    NSRegularExpression *re = regex(pattern);
    return [re numberOfMatchesInString:str options:0 range:NSMakeRange(0, str.length)] > 0;
}

// ═══════════════════════════════════════════════════════════════════════
// LAYER 1 — NSJSONSerialization: forge Apple receipt + patch Firestore
// ═══════════════════════════════════════════════════════════════════════
#if ENABLE_JSON_HOOK
%hook NSJSONSerialization

+ (id)JSONObjectWithData:(NSData *)data options:(NSJSONReadingOptions)opt error:(NSError **)error {
    id obj = %orig;
    if (!obj || ![obj isKindOfClass:[NSDictionary class]]) return obj;

    NSDictionary *dict = (NSDictionary *)obj;

    // Path A: Apple verifyReceipt response
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

#if ENABLE_FIRESTORE_IN_L1
    // Path B: Firestore document — rewrite premium fields
    if ([dict objectForKey:@"fields"] && [dict[@"fields"] isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *m = [dict mutableCopy];
        NSMutableDictionary *fields = [dict[@"fields"] mutableCopy];
        BOOL touched = NO;
        for (NSString *k in [fields allKeys]) {
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
#endif

    return obj;
}

%end
#endif  // ENABLE_JSON_HOOK

// ═══════════════════════════════════════════════════════════════════════
// LAYER 2 — NSUserDefaults: force premium keys
// ═══════════════════════════════════════════════════════════════════════
static NSString *const kPremiumPattern = @"isPremiumUser|isPremium\\b|premium_active|hasActiveSubscription|isPro\\b|isSubscribed|premiumPurchased|hasPaid";

%hook NSUserDefaults

- (BOOL)boolForKey:(NSString *)key {
    BOOL r = %orig;
    if (!r && matchesPattern(key, kPremiumPattern)) {
        TWLog(@"[UD] boolForKey \"%@\" → YES", key);
        return YES;
    }
    return r;
}

- (NSInteger)integerForKey:(NSString *)key {
    NSInteger r = %orig;
    if (r != 1 && matchesPattern(key, kPremiumPattern)) {
        TWLog(@"[UD] integerForKey \"%@\" → 1", key);
        return 1;
    }
    return r;
}

- (id)objectForKey:(NSString *)key {
    id r = %orig;
    if (matchesPattern(key, kPremiumPattern)) {
        TWLog(@"[UD] objectForKey \"%@\" → @YES", key);
        return @YES;
    }
    return r;
}

%end

// ═══════════════════════════════════════════════════════════════════════
// LAYER 3 — FIRRemoteConfig: override configValueForKey
// (uses %hookf for dynamic class — Firebase may or may not be linked)
// ═══════════════════════════════════════════════════════════════════════
%hook NSObject  // placeholder — we'll do FIRRemoteConfig dynamically in %ctor
%end

static IMP origFIRConfigValueForKey = NULL;

static id swizzled_FIRConfigValueForKey(id self, SEL _cmd, NSString *key) {
    id orig = ((id (*)(id, SEL, NSString *))origFIRConfigValueForKey)(self, _cmd, key);
    if (!key) return orig;

    Class FIRRCV = NSClassFromString(@"FIRRemoteConfigValue");
    if (!FIRRCV) return orig;

    if (matchesPattern(key, @"premium|paid|pro_required|require|locked")) {
        NSData *d = [@"false" dataUsingEncoding:NSUTF8StringEncoding];
        id v = [[FIRRCV alloc] init];
        // Try the known initializer
        SEL init = NSSelectorFromString(@"initWithData:source:");
        if ([v respondsToSelector:init]) {
            ((id (*)(id, SEL, NSData *, int))objc_msgSend)(v, init, d, 2);
            TWLog(@"[FIRRC] \"%@\" → false", key);
            return v;
        }
    } else if (matchesPattern(key, @"limit|quota|max|daily")) {
        NSData *d = [@"999999" dataUsingEncoding:NSUTF8StringEncoding];
        id v = [[FIRRCV alloc] init];
        SEL init = NSSelectorFromString(@"initWithData:source:");
        if ([v respondsToSelector:init]) {
            ((id (*)(id, SEL, NSData *, int))objc_msgSend)(v, init, d, 2);
            TWLog(@"[FIRRC] \"%@\" → 999999", key);
            return v;
        }
    }
    return orig;
}

// ═══════════════════════════════════════════════════════════════════════
// LAYER 4 — NSURLSession response rewriter
// ═══════════════════════════════════════════════════════════════════════
#if ENABLE_RESP_REWRITE
typedef struct {
    NSString *name;
    NSString *pattern;
    NSDictionary *(^rewrite)(NSDictionary *);
} GatePatch;

static NSArray *gatePatches(void) {
    static NSArray *cached = nil;
    if (cached) return cached;

    GatePatch *firebaseRC = malloc(sizeof(GatePatch));
    NSDictionary *(^rwFirebase)(NSDictionary *) = ^NSDictionary *(NSDictionary *j) {
        if (![j[@"entries"] isKindOfClass:[NSDictionary class]]) return j;
        NSMutableDictionary *m = [j mutableCopy];
        NSMutableDictionary *e = [j[@"entries"] mutableCopy];
        for (NSString *k in [e allKeys]) {
            if (matchesPattern(k, @"premium|paid|pro\\b|locked|require")) e[k] = @"false";
            if (matchesPattern(k, @"limit|quota|max|daily")) e[k] = @"999999";
            if (matchesPattern(k, @"enabled|show")) e[k] = @"true";
        }
        m[@"entries"] = e;
        return m;
    };

    // Only patch keys that ALREADY exist — never add new keys.
    // Adding keys changes the response shape and breaks Swift `as!` casts in the app.
    NSDictionary *(^rwCloudFn)(NSDictionary *) = ^NSDictionary *(NSDictionary *j) {
        NSMutableDictionary *m = [j mutableCopy];
        BOOL touched = NO;
        for (NSString *k in [m allKeys]) {
            if (matchesPattern(k, @"^(isPremium|isPro|isSubscribed|premium|pro|subscribed|active|paid)$")) {
                m[k] = matchType(m[k], @YES, @1, @"true");
                touched = YES;
            } else if (matchesPattern(k, @"^(expiresAt|expires_at|expirationDate|expiration)$")) {
                m[k] = matchType(m[k], @YES, FAR_FUTURE_MS_NUM, FAR_FUTURE_MS);
                touched = YES;
            } else if (matchesPattern(k, @"^(status|state)$")) {
                m[k] = matchType(m[k], @YES, @1, @"active");
                touched = YES;
            } else if (matchesPattern(k, @"^(credits|quota|videosLeft|remaining|count|limit)$")) {
                m[k] = matchType(m[k], @YES, @999999, @"999999");
                touched = YES;
            }
        }
        return touched ? m : j;
    };

    NSDictionary *(^rwKie)(NSDictionary *) = ^NSDictionary *(NSDictionary *j) {
        NSMutableDictionary *m = [j mutableCopy];
        if (m[@"code"]) m[@"code"] = matchType(m[@"code"], @YES, @200, @"200");
        if (m[@"msg"])  m[@"msg"]  = matchType(m[@"msg"],  @YES, @0,   @"success");
        if ([m[@"data"] isKindOfClass:[NSDictionary class]]) {
            NSMutableDictionary *d = [m[@"data"] mutableCopy];
            if (d[@"credits"]) d[@"credits"] = matchType(d[@"credits"], @YES, @999999, @"999999");
            if (d[@"quota"])   d[@"quota"]   = matchType(d[@"quota"],   @YES, @999999, @"999999");
            m[@"data"] = d;
        }
        return m;
    };

    NSDictionary *(^rwAws)(NSDictionary *) = ^NSDictionary *(NSDictionary *j) {
        NSMutableDictionary *m = [j mutableCopy];
        if (m[@"videosLeft"])       m[@"videosLeft"]       = matchType(m[@"videosLeft"],       @YES, @999, @"999");
        if (m[@"isServerBusy"])     m[@"isServerBusy"]     = matchType(m[@"isServerBusy"],     @NO,  @0,   @"false");
        if (m[@"isGrokServerBusy"]) m[@"isGrokServerBusy"] = matchType(m[@"isGrokServerBusy"], @NO,  @0,   @"false");
        if (m[@"quotaExceeded"])    m[@"quotaExceeded"]    = matchType(m[@"quotaExceeded"],    @NO,  @0,   @"false");
        if (m[@"isShow"])           m[@"isShow"]           = matchType(m[@"isShow"],           @YES, @1,   @"true");
        return m;
    };

    NSDictionary *(^rwFirestore)(NSDictionary *) = ^NSDictionary *(NSDictionary *j) {
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
    };

    NSMutableArray *list = [NSMutableArray array];
#if ENABLE_RW_FIREBASE
    [list addObject:@{@"name": @"firebase-remote-config",
                      @"pattern": @"firebaseremoteconfig\\.googleapis\\.com.*namespaces/firebase:fetch",
                      @"rewrite": rwFirebase}];
#endif
#if ENABLE_RW_CLOUDFN
    [list addObject:@{@"name": @"cloud-functions",
                      @"pattern": @"cloudfunctions\\.net|us-central1-.*\\.cloudfunctions\\.net",
                      @"rewrite": rwCloudFn}];
#endif
#if ENABLE_RW_KIE
    [list addObject:@{@"name": @"kie.ai",
                      @"pattern": @"api\\.kie\\.ai",
                      @"rewrite": rwKie}];
#endif
#if ENABLE_RW_AWS
    [list addObject:@{@"name": @"aws-execute-api",
                      @"pattern": @"execute-api\\..*amazonaws\\.com",
                      @"rewrite": rwAws}];
#endif
#if ENABLE_RW_FIRESTORE
    [list addObject:@{@"name": @"firestore-doc",
                      @"pattern": @"firestore\\.googleapis\\.com.*/documents/users/",
                      @"rewrite": rwFirestore}];
#endif
    cached = list;
    return cached;
}

%hook NSURLSession

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request
                            completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))handler {
    NSString *url = request.URL.absoluteString;

#if ENABLE_NET_LOG
    TWLog(@"[NET] %@ %@", request.HTTPMethod ?: @"GET", url);
#endif

    NSDictionary *matchedPatch = nil;
    for (NSDictionary *p in gatePatches()) {
        if (matchesPattern(url, p[@"pattern"])) { matchedPatch = p; break; }
    }

    if (!matchedPatch || !handler) {
        return %orig;
    }

    TWLog(@"[GATE] match: %@", matchedPatch[@"name"]);
    NSDictionary *(^rewriteBlock)(NSDictionary *) = matchedPatch[@"rewrite"];
    NSString *patchName = matchedPatch[@"name"];

    void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (!data) { handler(data, resp, err); return; }
        NSError *jerr = nil;
        id parsed = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jerr];
        if (!parsed || ![parsed isKindOfClass:[NSDictionary class]]) {
            handler(data, resp, err);
            return;
        }
        NSDictionary *patched = rewriteBlock(parsed);
        NSData *newData = [NSJSONSerialization dataWithJSONObject:patched options:0 error:nil];
        if (newData) {
            TWLog(@"[PATCH] (%@) rewritten", patchName);
            handler(newData, resp, err);
        } else {
            handler(data, resp, err);
        }
    };

    return %orig(request, wrapped);
}

%end
#endif  // ENABLE_RESP_REWRITE

// ═══════════════════════════════════════════════════════════════════════
// LAYER 5 — CCCrypt observer (optional)
// ═══════════════════════════════════════════════════════════════════════
#if ENABLE_CC_OBSERVER
#import <substrate.h>

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
        TWLog(@"[CC] %@ alg=%d in=%zuB key=%@",
              op == kCCEncrypt ? @"ENC" : @"DEC", (int)alg, dataInLen, keyData);
    }
    return r;
}
#endif

// ═══════════════════════════════════════════════════════════════════════
// LAYER 6 — SSL pinning bypass
// ═══════════════════════════════════════════════════════════════════════
#if ENABLE_PIN_BYPASS
#import <substrate.h>

static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef, SecTrustResultType *);
static OSStatus new_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    OSStatus r = orig_SecTrustEvaluate(trust, result);
    if (result) *result = kSecTrustResultProceed;
    return errSecSuccess;
}

static bool (*orig_SecTrustEvaluateWithError)(SecTrustRef, CFErrorRef *);
static bool new_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    if (error) *error = NULL;
    return true;
}

// AFNetworking
%hook AFSecurityPolicy
- (BOOL)evaluateServerTrust:(SecTrustRef)trust forDomain:(NSString *)domain { return YES; }
%end

// TrustKit
%hook TSKPinningValidator
- (int)evaluateTrust:(SecTrustRef)trust forHostname:(NSString *)host { return 0; }
%end

#endif

// ═══════════════════════════════════════════════════════════════════════
// LAYER 7 — Auto-trigger restoreCompletedTransactions
// ═══════════════════════════════════════════════════════════════════════
%hook UIApplication
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts {
    BOOL r = %orig;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
            Class SK = NSClassFromString(@"SKPaymentQueue");
            if (SK) {
                SKPaymentQueue *q = [SK defaultQueue];
                [q restoreCompletedTransactions];
                TWLog(@"[TRIGGER] restoreCompletedTransactions called");
            } else {
                TWLog(@"[TRIGGER] SKPaymentQueue not present");
            }
        } @catch (NSException *e) {
            TWLog(@"[TRIGGER] err: %@", e);
        }
    });
    return r;
}
%end

// ═══════════════════════════════════════════════════════════════════════
// Constructor — dynamic hooks for FIRRemoteConfig + C symbol hooks
// ═══════════════════════════════════════════════════════════════════════
%ctor {
    @autoreleasepool {
        TWLog(@"════════════════════════════════════════════");
        TWLog(@" AIVideoUnlock loaded into %@", [[NSBundle mainBundle] bundleIdentifier]);
        TWLog(@"════════════════════════════════════════════");

        // L3: dynamic hook on FIRRemoteConfig if linked
        Class FIRRC = NSClassFromString(@"FIRRemoteConfig");
        if (FIRRC) {
            SEL sel = @selector(configValueForKey:);
            Method m = class_getInstanceMethod(FIRRC, sel);
            if (m) {
                origFIRConfigValueForKey = method_getImplementation(m);
                method_setImplementation(m, (IMP)swizzled_FIRConfigValueForKey);
                TWLog(@"[init] FIRRemoteConfig.configValueForKey: swizzled");
            }
        }

#if ENABLE_PIN_BYPASS
        // L6: hook C symbols via MSHookFunction
        void *sec1 = dlsym(RTLD_DEFAULT, "SecTrustEvaluate");
        if (sec1) MSHookFunction(sec1, (void *)new_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate);

        void *sec2 = dlsym(RTLD_DEFAULT, "SecTrustEvaluateWithError");
        if (sec2) MSHookFunction(sec2, (void *)new_SecTrustEvaluateWithError, (void **)&orig_SecTrustEvaluateWithError);
        TWLog(@"[init] SSL pinning bypass armed");
#endif

#if ENABLE_CC_OBSERVER
        void *cc = dlsym(RTLD_DEFAULT, "CCCrypt");
        if (cc) {
            MSHookFunction(cc, (void *)new_CCCrypt, (void **)&orig_CCCrypt);
            TWLog(@"[init] CCCrypt observer armed");
        }
#endif

        TWLog(@"[init] all layers armed");
    }
}

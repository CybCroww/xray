#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

NS_ASSUME_NONNULL_BEGIN

// Apply before saving the NETunnelProviderProtocol in the app. These rules
// remain in force during reconnects, independently of the core's state.
FOUNDATION_EXPORT void CVPNRequireProtectedRouting(NETunnelProviderProtocol *configuration);

// Pass only resolver IPs here. Queries to them travel through the default
// tunnel route. Configure this before starting the protected core.
FOUNDATION_EXPORT NEPacketTunnelNetworkSettings *_Nullable CVPNFullTunnelSettings(NSArray<NSString *> *resolverIPs, NSInteger mtu);

// Retain one bridge for the lifetime of the NEPacketTunnelProvider. It
// installs the network settings before starting the core.
@interface CVPNPacketFlow : NSObject
- (instancetype)initWithProvider:(NEPacketTunnelProvider *)provider;
- (instancetype)init NS_UNAVAILABLE;
- (void)startWithConfig:(NSString *)config
                   mtu:(NSInteger)mtu
             resolverIPs:(NSArray<NSString *> *)resolverIPs
             completion:(void (^)(NSError *_Nullable))completion;
- (void)stopWithCompletion:(dispatch_block_t)completion;
- (void)takeMemorySnapshot:(void (^)(NSDictionary<NSString *, NSNumber *> *))completion;
@end

NS_ASSUME_NONNULL_END

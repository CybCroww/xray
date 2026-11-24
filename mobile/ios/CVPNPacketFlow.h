#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

NS_ASSUME_NONNULL_BEGIN

// Retain one bridge for the lifetime of the NEPacketTunnelProvider. Install
// network settings before starting it and use the same MTU in both places.
@interface CVPNPacketFlow : NSObject
- (instancetype)initWithPacketFlow:(NEPacketTunnelFlow *)flow;
- (instancetype)init NS_UNAVAILABLE;
- (void)startWithConfig:(NSString *)config
                    mtu:(NSInteger)mtu
             completion:(void (^)(NSError *_Nullable))completion;
- (void)stopWithCompletion:(dispatch_block_t)completion;
- (void)takeMemorySnapshot:(void (^)(NSDictionary<NSString *, NSNumber *> *))completion;
@end

NS_ASSUME_NONNULL_END

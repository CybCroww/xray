#import "CVPNPacketFlow.h"
#import <CVPNCore/CVPNCore.h>
#import <mach/mach.h>
#import <os/proc.h>
#import <sys/socket.h>

@interface CVPNFlowWriter : NSObject <CVPNMobilePacketWriter>
@property (nonatomic, weak) NEPacketTunnelFlow *flow;
@end

@implementation CVPNFlowWriter
- (BOOL)writePacket:(NSData *)packet {
    @autoreleasepool {
        if (packet.length == 0) return NO;
        uint8_t version = ((const uint8_t *)packet.bytes)[0] >> 4;
        if (version != 4 && version != 6) return NO;
        return [self.flow writePackets:@[packet] withProtocols:@[@(version == 4 ? AF_INET : AF_INET6)]];
    }
}
@end

@implementation CVPNPacketFlow {
    NEPacketTunnelFlow *_flow;
    dispatch_queue_t _queue;
    dispatch_source_t _memoryPressure;
    CVPNMobileTunnel *_tunnel;
    BOOL _readPending;
    uint64_t _generation;
}

- (instancetype)initWithPacketFlow:(NEPacketTunnelFlow *)flow {
    if ((self = [super init])) {
        _flow = flow;
        _queue = dispatch_queue_create("cvpn.packet-flow", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)startWithConfig:(NSString *)config mtu:(NSInteger)mtu completion:(void (^)(NSError *))completion {
    dispatch_async(_queue, ^{
        if (self->_tunnel) {
            completion([NSError errorWithDomain:@"CVPNPacketFlow" code:1 userInfo:nil]);
            return;
        }
        CVPNFlowWriter *writer = [CVPNFlowWriter new];
        writer.flow = self->_flow;
        NSError *error = nil;
        CVPNMobileTunnel *tunnel = CVPNMobileStart(config, writer, mtu, 0, &error);
        if (!tunnel) {
            completion(error ?: [NSError errorWithDomain:@"CVPNPacketFlow" code:2 userInfo:nil]);
            return;
        }
        self->_tunnel = tunnel;
        self->_generation++;
        [self readNext];

        dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MEMORYPRESSURE, 0,
            DISPATCH_MEMORYPRESSURE_WARN | DISPATCH_MEMORYPRESSURE_CRITICAL,
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
        if (source) {
            __weak CVPNMobileTunnel *weakTunnel = tunnel;
            __weak dispatch_source_t weakSource = source;
            dispatch_source_set_event_handler(source, ^{
                dispatch_source_t strongSource = weakSource;
                if (strongSource) {
                    [weakTunnel trimMemory:(dispatch_source_get_data(strongSource) & DISPATCH_MEMORYPRESSURE_CRITICAL) != 0];
                }
            });
            self->_memoryPressure = source;
            dispatch_resume(source);
        }
        completion(nil);
    });
}

- (void)readNext {
    if (!_tunnel || _readPending) return;
    _readPending = YES;
    uint64_t generation = _generation;
    __weak CVPNPacketFlow *weakSelf = self;
    [_flow readPacketsWithCompletionHandler:^(NSArray<NSData *> *packets, NSArray<NSNumber *> *protocols) {
        (void)protocols; // IP version is already encoded in each packet.
        CVPNPacketFlow *bridge = weakSelf;
        if (!bridge) return;
        dispatch_async(bridge->_queue, ^{
            @autoreleasepool {
                bridge->_readPending = NO;
                if (generation == bridge->_generation) {
                    for (NSData *packet in packets) [bridge->_tunnel pushPacket:packet];
                }
                [bridge readNext];
            }
        });
    }];
}

- (void)stopWithCompletion:(dispatch_block_t)completion {
    dispatch_async(_queue, ^{
        self->_generation++;
        if (self->_memoryPressure) {
            dispatch_source_cancel(self->_memoryPressure);
            self->_memoryPressure = nil;
        }
        [self->_tunnel stop:NULL];
        self->_tunnel = nil;
        completion();
    });
}

- (void)takeMemorySnapshot:(void (^)(NSDictionary<NSString *, NSNumber *> *))completion {
    dispatch_async(_queue, ^{
        NSString *json = [self->_tunnel memoryStatsJSON] ?: @"{}";
        NSData *data = [json dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *go = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
        NSMutableDictionary *values = [go mutableCopy] ?: [NSMutableDictionary dictionary];
        task_vm_info_data_t info = {0};
        mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
        if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) == KERN_SUCCESS &&
            count >= TASK_VM_INFO_REV1_COUNT) {
            values[@"physicalFootprintBytes"] = @(info.phys_footprint);
        }
        if (@available(iOS 13.0, *)) values[@"availableProcessMemoryBytes"] = @(os_proc_available_memory());
        completion([values copy]);
    });
}
@end

#import "CVPNPacketFlow.h"
#import <CVPNCore/CVPNCore.h>
#import <Network/Network.h>
#import <arpa/inet.h>
#import <mach/mach.h>
#import <os/proc.h>
#import <sys/socket.h>

static const NSUInteger CVPNInputBatchBytes = 16 * 1024;

void CVPNRequireProtectedRouting(NETunnelProviderProtocol *configuration) {
    configuration.includeAllNetworks = YES;
    configuration.excludeLocalNetworks = NO;
    if (@available(iOS 16.4, *)) {
        configuration.excludeAPNs = NO;
        configuration.excludeCellularServices = NO;
    }
    if (@available(iOS 17.4, *)) configuration.excludeDeviceCommunication = NO;
}

NEPacketTunnelNetworkSettings *CVPNFullTunnelSettings(NSArray<NSString *> *resolverIPs, NSInteger mtu) {
    if (mtu < 1280 || mtu > 1500 || resolverIPs.count == 0) return nil;
    for (NSString *resolver in resolverIPs) {
        struct in_addr v4;
        struct in6_addr v6;
        const char *address = resolver.UTF8String;
        if (!address || (inet_pton(AF_INET, address, &v4) != 1 && inet_pton(AF_INET6, address, &v6) != 1)) return nil;
    }
    NEPacketTunnelNetworkSettings *settings = [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:@"127.0.0.1"];
    NEIPv4Settings *ipv4 = [[NEIPv4Settings alloc] initWithAddresses:@[@"198.18.0.2"] subnetMasks:@[@"255.255.255.252"]];
    ipv4.includedRoutes = @[[NEIPv4Route defaultRoute]];
    settings.IPv4Settings = ipv4;
    NEIPv6Settings *ipv6 = [[NEIPv6Settings alloc] initWithAddresses:@[@"fd00:6376:706e::2"] networkPrefixLengths:@[@64]];
    ipv6.includedRoutes = @[[NEIPv6Route defaultRoute]];
    settings.IPv6Settings = ipv6;
    NEDNSSettings *dns = [[NEDNSSettings alloc] initWithServers:resolverIPs];
    dns.matchDomains = @[@""];
    settings.DNSSettings = dns;
    settings.MTU = @(mtu);
    return settings;
}

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
    __weak NEPacketTunnelProvider *_provider;
    NEPacketTunnelFlow *_flow;
    dispatch_queue_t _queue;
    dispatch_source_t _memoryPressure;
    nw_path_monitor_t _pathMonitor;
    nw_path_t _lastPath;
    CVPNMobileTunnel *_tunnel;
    NSMutableData *_inputBatch;
    NSUInteger _mtu;
    BOOL _readPending;
    BOOL _starting;
    uint64_t _generation;
}

- (instancetype)initWithProvider:(NEPacketTunnelProvider *)provider {
    if ((self = [super init])) {
        _provider = provider;
        _flow = provider.packetFlow;
        _queue = dispatch_queue_create("cvpn.packet-flow", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)startWithConfig:(NSString *)config mtu:(NSInteger)mtu resolverIPs:(NSArray<NSString *> *)resolverIPs completion:(void (^)(NSError *))completion {
    dispatch_async(_queue, ^{
        if (self->_tunnel || self->_starting) {
            completion([NSError errorWithDomain:@"CVPNPacketFlow" code:1 userInfo:nil]);
            return;
        }
        NEPacketTunnelProvider *provider = self->_provider;
        NEVPNProtocol *profile = provider.protocolConfiguration;
        NEPacketTunnelNetworkSettings *settings = CVPNFullTunnelSettings(resolverIPs, mtu);
        BOOL hasExclusions = profile.excludeLocalNetworks;
        if (@available(iOS 16.4, *)) hasExclusions = hasExclusions || profile.excludeAPNs || profile.excludeCellularServices;
        if (@available(iOS 17.4, *)) hasExclusions = hasExclusions || profile.excludeDeviceCommunication;
        if (!profile.includeAllNetworks || hasExclusions || !settings) {
            completion([NSError errorWithDomain:@"CVPNPacketFlow" code:3 userInfo:nil]);
            return;
        }
        self->_starting = YES;
        uint64_t generation = ++self->_generation;
        [provider setTunnelNetworkSettings:settings completionHandler:^(NSError *error) {
            dispatch_async(self->_queue, ^{
                if (generation != self->_generation) {
                    completion([NSError errorWithDomain:NSCocoaErrorDomain code:NSUserCancelledError userInfo:nil]);
                    return;
                }
                self->_starting = NO;
                if (error) { completion(error); return; }
                [self startCore:config mtu:mtu completion:completion];
            });
        }];
    });
}

- (void)startCore:(NSString *)config mtu:(NSInteger)mtu completion:(void (^)(NSError *))completion {
    CVPNFlowWriter *writer = [CVPNFlowWriter new];
    writer.flow = self->_flow;
    NSError *error = nil;
    CVPNMobileTunnel *tunnel = CVPNMobileStartProtected(config, writer, mtu, 0, &error);
    if (!tunnel) {
        completion(error ?: [NSError errorWithDomain:@"CVPNPacketFlow" code:2 userInfo:nil]);
        return;
    }
    self->_tunnel = tunnel;
    _mtu = (NSUInteger)mtu;
    _inputBatch = [NSMutableData dataWithLength:CVPNInputBatchBytes];
    [self readNext];
    [self monitorNetwork];

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
}

// gomobile borrows NSMutableData for the synchronous call. Use a fixed buffer
// so the binding doesn't malloc/copy a separate NSData for every IP packet.
- (void)pushPackets:(NSArray<NSData *> *)packets {
    if (_lastPath && nw_path_get_status(_lastPath) == nw_path_status_unsatisfied) {
        [_tunnel recordInputDrops:(NSInteger)packets.count];
        return;
    }
    uint8_t *bytes = _inputBatch.mutableBytes;
    NSUInteger offset = 0;
    NSInteger dropped = 0;
    for (NSData *packet in packets) {
        NSUInteger size = packet.length;
        if (size < 20 || size > _mtu) {
            dropped++;
            continue;
        }
        if (offset + 2 + size > CVPNInputBatchBytes) {
            [_tunnel pushPacketBatch:_inputBatch length:(NSInteger)offset];
            offset = 0;
        }
        bytes[offset] = (uint8_t)(size >> 8);
        bytes[offset + 1] = (uint8_t)size;
        [packet getBytes:bytes + offset + 2 length:size];
        offset += 2 + size;
    }
    if (offset) [_tunnel pushPacketBatch:_inputBatch length:(NSInteger)offset];
    if (dropped) [_tunnel recordInputDrops:dropped];
}

- (void)monitorNetwork {
    _pathMonitor = nw_path_monitor_create();
    if (!_pathMonitor) return;
    nw_path_monitor_set_queue(_pathMonitor, _queue);
    __weak CVPNPacketFlow *weakSelf = self;
    uint64_t generation = _generation;
    nw_path_monitor_set_update_handler(_pathMonitor, ^(nw_path_t path) {
        CVPNPacketFlow *bridge = weakSelf;
        if (!bridge || bridge->_generation != generation || !bridge->_tunnel) return;
        nw_path_t previous = bridge->_lastPath;
        nw_path_status_t status = nw_path_get_status(path);
        nw_path_status_t previousStatus = previous ? nw_path_get_status(previous) : nw_path_status_invalid;
        if (status == nw_path_status_invalid ||
            (previous && status == previousStatus && nw_path_is_equal(previous, path))) return;
        bridge->_lastPath = path;
        if (status == nw_path_status_unsatisfied) {
            [bridge->_tunnel networkUnavailable];
        } else if (previous && !(previousStatus == nw_path_status_satisfiable && status == nw_path_status_satisfied)) {
            // A satisfiable path may be activated by the app's first dial.
            // Preserve those sockets when the path has just become satisfied.
            [bridge->_tunnel networkChanged];
        }
    });
    nw_path_monitor_start(_pathMonitor);
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
                    [bridge pushPackets:packets];
                }
                [bridge readNext];
            }
        });
    }];
}

- (void)stopWithCompletion:(dispatch_block_t)completion {
    dispatch_async(_queue, ^{
        self->_generation++;
        self->_starting = NO;
        if (self->_pathMonitor) {
            nw_path_monitor_cancel(self->_pathMonitor);
            self->_pathMonitor = nil;
        }
        self->_lastPath = nil;
        if (self->_memoryPressure) {
            dispatch_source_cancel(self->_memoryPressure);
            self->_memoryPressure = nil;
        }
        [self->_tunnel stop:NULL];
        self->_tunnel = nil;
        self->_inputBatch = nil;
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

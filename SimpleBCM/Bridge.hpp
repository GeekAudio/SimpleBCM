//
//  Bridge.hpp
//  SimpleBCM
//
//  Created by laobamac on 2026/9/19.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEBCM_BRIDGE_HPP
#define SIMPLEBCM_BRIDGE_HPP

#include "WirelessABI.hpp"
#include "Patcher.hpp"
#include <IOKit/IOService.h>

class BCM80211UserClient;

namespace bcm {

enum class InterfaceKind : uint8_t { Classic, Virtual, Skywalk };

struct Endpoint {
    IOService *interface;
    IOService *controller;
    InterfaceKind kind;
    char name[16];
};

struct AvailabilityEvent {
    uint64_t seconds;
    uint64_t microseconds;
    uint32_t length;
    uint8_t payload[NativeDriverAvailableSize];
};

struct Counters {
    uint64_t opens;
    uint64_t denied;
    uint64_t commands;
    uint64_t errors;
    uint64_t events;
    uint64_t dropped;
    uint64_t notifications;
    uint64_t notificationErrors;
    uint64_t scanRecords;
    uint64_t scanDoneEvents;
    uint64_t scanDoneRecords;
    uint64_t associationRequests;
    uint64_t associationAccepted;
    uint64_t availabilityEvents;
    uint64_t availabilityReplays;
    uint64_t associationEvents;
    uint64_t associationEventConversions;
    uint64_t associationEventReadErrors;
    uint64_t powerAvailabilityEvents;
    uint32_t lastAssociationEventLength;
    uint32_t lastAssociationEventReadResult;
    uint32_t lastAvailabilityReadResult;
    uint64_t selectors[9];
    uint32_t lastRequest;
    uint32_t lastResult;
    uint32_t lastAssociationResult;
    /* 11-17 · the values the ENXIO at the top of Bridge::command was taken on. airportd's ASSOCIATE(20) never
       reached the embedded driver (AssociationRequests stays 0) while SCAN(10) did: either the interface or the
       controller was judged inactive at that moment, or the request never came. Published, not logged: IOLog
       does not reach the unified log on this system and dmesg is empty. */
    uint32_t lastRequestKind;
    uint32_t lastRequestSet;
    uint32_t lastRejectType;
    uint32_t lastRejectKind;
    uint64_t rejects;
    uint64_t rejectInterfaceInactive;
    uint64_t rejectControllerInactive;
    /* 11-17 · the last 16 commands in order: request, flags (bit0 set, bits8+ kind) and result. Published as
       ReqHist0..15 / ReqHistN. 27 keeps ASSOCIATE at set type 20 (table index 19); set type 254 is an empty
       slot and type 255 is BTCOEX/UCM, so the earlier "slot 20 empty / slot 254 populated" hypothesis was a
       0-based/1-based table-index confusion. The 16-slot window only covers a few seconds at the observed
       command rate; the persistent counters below and the Set history are the authoritative view. */
    uint32_t requestHistory[16];
    uint32_t requestHistoryFlags[16];
    uint32_t requestHistoryResult[16];
    uint32_t requestHistoryNext;
    uint32_t requestHistoryCount;
    /* 11-17 · association diagnostics. AssociationRequests counts set+20 before any gate, so a type-20
       request rejected by the length/layout gate still shows up there. LastAssociateLength records the
       incoming length (0x290 on 27, 0x38C on Tahoe). AssociateLengthMismatch counts every set+20 whose
       length differs from the ABI's associateSize, including the 27 0x290 layout;
       GoldenGateAssociateRequests isolates the 0x290 layout. */
    uint64_t associateLengthMismatch;
    uint64_t goldenGateAssociateRequests;
    /* 11-17 · 27 answers GET CURRENT_NETWORK (103) with the same 0x8E8 record it uses for a scan result, but the
       Tahoe payload's handler is a three-instruction stub (movl $0x66,%eax; ret). Building that record needs the
       legacy scan-result field offsets, which the driver never exposes symbolically: keep the head of the last
       successful scan result and of the last associate request so the layout can be read back from ioreg. */
    uint32_t scanSnapshot[32];
    uint32_t assocSnapshot[16];
    /* 11-17/18 · material for GET CURRENT_NETWORK (103). The buffers are heap-allocated in
       Bridge::initialize: growing Counters' static BSS by ~1.2 KB made the kext hang at
       ExitBootServices on 27.2 (bisect B: baseline + arrays only reproduces it), so the
       data lives in IOMalloc'd memory instead. */
    uint32_t associateSsidLength;
    uint32_t currentNetworkValid;
    uint32_t last103OutputSize;
    uint32_t c103Hits;
    uint32_t lastAssociateLength;
    uint32_t lastGoldenGateSample[GoldenGateSampleWords];
    uint32_t lastGoldenGateBssidCount;
    uint32_t lastGoldenGateScope;
    /* 11-17 · the last 16 Set commands: type, header->length and IOReturn. The request history above mixes
       get/set and is evicted within seconds; this keeps the set path visible across an association attempt. */
    uint64_t setHistoryCount;
    uint32_t setHistoryNext;
    uint32_t setHistory[16];
    uint32_t setHistoryLength[16];
    uint32_t setHistoryResult[16];
    uint32_t lastSetType;
    uint32_t lastSetLength;
    uint32_t lastSetResult;
    /* 11-17 · decisive probe: count every association that reaches the embedded driver's
       AirPort_BrcmNIC::setASSOCIATE, regardless of whether it came from the SimpleBCM user client or from
       airportd's legacy ifnet ioctl path (which bypasses the user client). */
    uint64_t driverAssociateRequests;
    uint32_t driverAssociateHookReady;
    uint32_t lastDriverAssociateWord;
    /* 11-17 · event-9 diagnostics: queueEvent counts before the client filter/ring, so AssociationEvents==0
       means the driver never posted event 9; the kind split shows whether a future event came from Classic,
       Virtual or Skywalk. */
    uint32_t lastAssociationEventKind;
    uint64_t associationEventsClassic;
    uint64_t associationEventsVirtual;
    uint64_t associationEventsSkywalk;
};

extern Counters counters;
/* heap-allocated in Bridge::initialize (see Counters comment) */
extern uint8_t *currentNetworkBuffer;
extern uint8_t *associateSsidBuffer;

class Bridge {
public:
    static void initialize();
    static void trackController(IOService *controller);
    static void enableNativeSkywalk();
    static bool ready();
    static bool goldenGateAssociateEnabled();
    static bool currentNetworkEnabled();
    static const UserABI &abi();
    static uint64_t copyAvailability(const Endpoint &endpoint, AvailabilityEvent &event);
    static int refreshAvailability(const Endpoint &endpoint);
    static bool isScalarGet(uint32_t request);
    static bool identify(IOService *interface, InterfaceKind kind, Endpoint &endpoint);
    static bool addClient(BCM80211UserClient *client);
    static void removeClient(BCM80211UserClient *client);
    static int command(const Endpoint &endpoint, bool set, LegacyRequest &request, void *shadow, size_t size);
    static void publish(IOService *service);
    static bool prepareImage(LinkedImage &image, size_t index);
    static void disable(const char *reason);
private:
    static void patchImage(KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size);
};

}

#endif

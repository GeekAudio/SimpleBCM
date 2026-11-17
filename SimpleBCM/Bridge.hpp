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
       ReqHist0..15 / ReqHistN. One slot of history hid whether ASSOCIATE(20) was never sent or merely renamed
       (the 27 set tables have slot 20 empty and slot 254 populated). */
    uint32_t requestHistory[16];
    uint32_t requestHistoryFlags[16];
    uint32_t requestHistoryResult[16];
    uint32_t requestHistoryNext;
    uint32_t requestHistoryCount;
};

extern Counters counters;

class Bridge {
public:
    static void initialize();
    static void trackController(IOService *controller);
    static void enableNativeSkywalk();
    static bool ready();
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

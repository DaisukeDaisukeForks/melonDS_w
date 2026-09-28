/*
    Copyright 2016-2026 melonDS team

    This file is part of melonDS.

    melonDS is free software: you can redistribute it and/or modify it under
    the terms of the GNU General Public License as published by the Free
    Software Foundation, either version 3 of the License, or (at your option)
    any later version.

    melonDS is distributed in the hope that it will be useful, but WITHOUT ANY
    WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with melonDS. If not, see http://www.gnu.org/licenses/.
*/

#ifndef LOCALMP_H
#define LOCALMP_H

#include "types.h"
#include "Platform.h"
#include "MPInterface.h"
#include <array>
#include <vector>

namespace melonDS
{
class Savestate;
struct MPStatusData
{
    u16 ConnectedBitmask; // bitmask of which instances are ready to send/receive packets
    u32 PacketWriteOffset;
    u32 ReplyWriteOffset;
    u16 MPHostinst; // instance ID from which the last CMD frame was sent
    u16 MPReplyBitmask;   // bitmask of which clients replied in time
};

constexpr u32 kPacketQueueSize = 0x10000;
constexpr u32 kReplyQueueSize = 0x10000;
constexpr u32 kMaxFrameSize = 0x948;

class LocalMP : public MPInterface
{
public:
    // Fixed-size, bounded observation queue. Records are copied from the real
    // LocalMP path; reading the log never consumes emulated network packets.
    struct PacketLogEntry
    {
        u64 Timestamp;
        u32 Sequence;
        u32 Type;
        u16 SenderID;
        s16 ReceiverID; // -1 for broadcast, otherwise the receiving instance
        u16 Length;
        bool Received;
        std::array<u8, kMaxFrameSize> Payload;
    };
    static constexpr u32 kLogCapacity = 256;
    struct HeldPacket { u32 Id; int Sender; u32 Type; u64 Timestamp; u16 Targets; u16 Length; std::array<u8, kMaxFrameSize> Payload; };
    void SetPacketInterceptor(int inst, bool enabled);
    void ClearPacketControl(int inst);
    void SetPacketRoutes(int inst, u16 targets);
    u32 CopyHeldPackets(int inst, HeldPacket* output, u32 capacity);
    int CommitPacket(int inst, u32 id, bool drop, const u8* data, int length, int targets, double timestamp);
    int InjectPacket(int inst, u32 type, const u8* data, int length, u64 timestamp, u16 targets);

    LocalMP() noexcept;
    LocalMP(const LocalMP&) = delete;
    LocalMP& operator=(const LocalMP&) = delete;
    LocalMP(LocalMP&& other) = delete;
    LocalMP& operator=(LocalMP&& other) = delete;
    ~LocalMP() noexcept;

    void Process() {}
    void DoTransportState(Savestate* state, void (*semaphoreState)(Savestate*, Platform::Semaphore*));

    void Begin(int inst);
    void End(int inst);

    int SendPacket(int inst, u8* data, int len, u64 timestamp);
    int RecvPacket(int inst, u8* data, u64* timestamp);
    int SendCmd(int inst, u8* data, int len, u64 timestamp);
    int SendReply(int inst, u8* data, int len, u64 timestamp, u16 aid);
    int SendAck(int inst, u8* data, int len, u64 timestamp);
    int RecvHostPacket(int inst, u8* data, u64* timestamp);
    u16 RecvReplies(int inst, u8* data, u64 timestamp, u16 aidmask);

    // Returns up to capacity entries, oldest first, removing them from the log.
    // 'dropped' is the number of entries overwritten since the last drain.
    u32 DrainPacketLog(PacketLogEntry* out, u32 capacity, u32* dropped) noexcept;

private:
    void FIFORead(int inst, int fifo, void* buf, int len) noexcept;
    void FIFOWrite(int inst, int fifo, void* buf, int len) noexcept;
    int SendPacketGeneric(int inst, u32 type, const u8* packet, int len, u64 timestamp, bool bypass = false, int targets = -1) noexcept;
    int RecvPacketGeneric(int inst, u8* packet, bool block, u64* timestamp) noexcept;
    void LogPacket(int sender, int receiver, u32 type, const u8* packet,
                   int length, u64 timestamp, bool received) noexcept;

    Platform::Mutex* MPQueueLock;
    MPStatusData MPStatus {};
    u8 MPPacketQueue[kPacketQueueSize] {};
    u8 MPReplyQueue[kReplyQueueSize] {};
    u32 PacketReadOffset[16] {};
    u32 ReplyReadOffset[16] {};

    int LastHostID = -1;
    Platform::Semaphore* SemPool[32] {};
    std::array<PacketLogEntry, kLogCapacity> PacketLog {};
    u32 LogRead = 0;
    u32 LogCount = 0;
    u32 LogSequence = 0;
    u32 LogDropped = 0;
    u16 InterceptMask = 0;
    std::array<u16, 16> RouteMasks {0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff};
    std::vector<HeldPacket> HeldPackets;
    u32 NextHeldId = 1;
};
}

#endif // LOCALMP_H

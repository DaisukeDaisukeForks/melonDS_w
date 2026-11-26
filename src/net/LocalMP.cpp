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

#include <cstring>

#include "LocalMP.h"
#include <algorithm>
#include "Savestate.h"

using namespace melonDS;
using namespace melonDS::Platform;

using Platform::Log;
using Platform::LogLevel;

namespace melonDS
{
// Routing metadata belongs to this in-process FIFO, not the emulated 802.11 frame.
struct RoutedPacketHeader : MPPacketHeader { u32 Targets; };
void LocalMP::DoTransportState(Savestate* state, void (*semaphoreState)(Savestate*, Platform::Semaphore*))
{
    Mutex_Lock(MPQueueLock);
    state->VarArray(&MPStatus, sizeof(MPStatus));
    state->VarArray(MPPacketQueue, sizeof(MPPacketQueue));
    state->VarArray(MPReplyQueue, sizeof(MPReplyQueue));
    state->VarArray(PacketReadOffset, sizeof(PacketReadOffset));
    state->VarArray(ReplyReadOffset, sizeof(ReplyReadOffset));
    state->VarArray(&LastHostID, sizeof(LastHostID));
    state->Var16(&InterceptMask); state->VarArray(RouteMasks.data(), sizeof(RouteMasks)); state->Var32(&NextHeldId);
    u32 heldCount = HeldPackets.size(); state->Var32(&heldCount);
    if (heldCount > 64) { state->Error = true; Mutex_Unlock(MPQueueLock); return; }
    if (!state->Saving) HeldPackets.resize(heldCount);
    for (auto& packet : HeldPackets) {
        state->VarArray(&packet, sizeof(packet));
        if (packet.Sender < 0 || packet.Sender > 15 || packet.Length > kMaxFrameSize
            || ((packet.Type & 0xffff) == 2 && packet.Length > 1024)) state->Error = true;
    }
    for (auto* semaphore : SemPool) semaphoreState(state, semaphore);
    if (!state->Saving) { LogRead = 0; LogCount = 0; LogDropped = 0; PeersKnown = 0; }
    Mutex_Unlock(MPQueueLock);
}

LocalMP::LocalMP() noexcept :
    MPQueueLock(Mutex_Create())
{
    memset(MPPacketQueue, 0, kPacketQueueSize);
    memset(MPReplyQueue, 0, kReplyQueueSize);
    memset(&MPStatus, 0, sizeof(MPStatus));
    memset(PacketReadOffset, 0, sizeof(PacketReadOffset));
    memset(ReplyReadOffset, 0, sizeof(ReplyReadOffset));

    // prepare semaphores
    // semaphores 0-15: regular frames; semaphore I is posted when instance I needs to process a new frame
    // semaphores 16-31: MP replies; semaphore I is posted when instance I needs to process a new MP reply

    for (int i = 0; i < 32; i++)
    {
        SemPool[i] = Semaphore_Create();
    }

    Log(LogLevel::Info, "MP comm init OK\n");
}

LocalMP::~LocalMP() noexcept
{
    for (int i = 0; i < 32; i++)
    {
        Semaphore_Free(SemPool[i]);
        SemPool[i] = nullptr;
    }

    Mutex_Free(MPQueueLock);
}

void LocalMP::Begin(int inst)
{
    Mutex_Lock(MPQueueLock);
    PacketReadOffset[inst] = MPStatus.PacketWriteOffset;
    ReplyReadOffset[inst] = MPStatus.ReplyWriteOffset;
    Semaphore_Reset(SemPool[inst]);
    Semaphore_Reset(SemPool[16 + inst]);
    MPStatus.ConnectedBitmask |= (1 << inst);
    Mutex_Unlock(MPQueueLock);
}

void LocalMP::End(int inst)
{
    Mutex_Lock(MPQueueLock);
    MPStatus.ConnectedBitmask &= ~(1 << inst);
    Mutex_Unlock(MPQueueLock);
}
void LocalMP::SetPeer(int inst, const u8* mac, const u8* bssid)
{
    if (inst < 0 || inst >= 16 || !mac || !bssid) return;
    Mutex_Lock(MPQueueLock);
    memcpy(PeerMAC[inst].data(), mac, 6);
    memcpy(PeerBSSID[inst].data(), bssid, 6);
    PeersKnown |= 1u << inst;
    Mutex_Unlock(MPQueueLock);
}
void LocalMP::SetPacketInterceptor(int inst, bool enabled)
{
    Mutex_Lock(MPQueueLock);
    if (enabled) InterceptMask |= 1u << inst; else InterceptMask &= ~(1u << inst);
    Mutex_Unlock(MPQueueLock);
}
void LocalMP::SetPacketRoutes(int inst, u16 targets)
{
    Mutex_Lock(MPQueueLock); RouteMasks[inst] = targets; Mutex_Unlock(MPQueueLock);
}
void LocalMP::ClearPacketControl(int inst)
{
    Mutex_Lock(MPQueueLock);
    InterceptMask &= ~(1u << inst); RouteMasks[inst] = 0xffff;
    HeldPackets.erase(std::remove_if(HeldPackets.begin(), HeldPackets.end(), [inst](const HeldPacket& p) { return p.Sender == inst; }), HeldPackets.end());
    Mutex_Unlock(MPQueueLock);
}
u32 LocalMP::CopyHeldPackets(int inst, HeldPacket* output, u32 capacity)
{
    Mutex_Lock(MPQueueLock);
    u32 count = 0;
    for (const auto& packet : HeldPackets) if (packet.Sender == inst && count < capacity) output[count++] = packet;
    Mutex_Unlock(MPQueueLock); return count;
}
int LocalMP::CommitPacket(int inst, u32 id, bool drop, const u8* data, int length, int targets, double timestamp)
{
    if (length < -1 || length > kMaxFrameSize || (length > 0 && !data) || targets < -1 || targets > 65535) return -1;
    HeldPacket packet {}; bool found = false;
    Mutex_Lock(MPQueueLock);
    for (auto it = HeldPackets.begin(); it != HeldPackets.end(); ++it) if (it->Sender == inst && it->Id == id) {
        if (!drop && (it->Type & 0xffff) == 2 && length > 1024) { Mutex_Unlock(MPQueueLock); return -1; }
        packet = *it; HeldPackets.erase(it); found = true; break;
    }
    Mutex_Unlock(MPQueueLock);
    if (!found) return -2;
    if (drop) return 0;
    return SendPacketGeneric(inst, packet.Type, length < 0 ? packet.Payload.data() : data,
        length < 0 ? packet.Length : length, timestamp < 0 ? packet.Timestamp : static_cast<u64>(timestamp), true,
        targets < 0 ? packet.Targets : targets);
}
int LocalMP::InjectPacket(int inst, u32 type, const u8* data, int length, u64 timestamp, u16 targets)
{
    if ((type & 0xffff) > 3 || ((type & 0xffff) == 2 && ((type >> 16) < 1 || (type >> 16) > 15))
        || ((type & 0xffff) == 2 && length > 1024)) return -1;
    return SendPacketGeneric(inst, type, data, length, timestamp, true, targets);
}

void LocalMP::LogPacket(int sender, int receiver, u32 type, const u8* packet,
                        int length, u64 timestamp, bool received) noexcept
{
    if (length < 0 || length > kMaxFrameSize || (length && !packet)) return;
    // Called under MPQueueLock. No allocation, JavaScript, or I/O on the
    // emulation path. A full ring drops its oldest observation, not a packet.
    if (LogCount == kLogCapacity)
    {
        LogRead = (LogRead + 1) % kLogCapacity;
        --LogCount;
        ++LogDropped;
    }
    auto& entry = PacketLog[(LogRead + LogCount) % kLogCapacity];
    entry.Timestamp = timestamp;
    entry.Sequence = ++LogSequence;
    entry.Type = type;
    entry.SenderID = static_cast<u16>(sender);
    entry.ReceiverID = static_cast<s16>(receiver);
    entry.Length = static_cast<u16>(length);
    entry.Received = received;
    if (length > 0) memcpy(entry.Payload.data(), packet, length);
    ++LogCount;
}

u32 LocalMP::DrainPacketLog(PacketLogEntry* out, u32 capacity, u32* dropped) noexcept
{
    if (!out && capacity) return 0;
    Mutex_Lock(MPQueueLock);
    if (dropped) { *dropped = LogDropped; LogDropped = 0; }
    const u32 count = capacity < LogCount ? capacity : LogCount;
    for (u32 i = 0; i < count; ++i)
        out[i] = PacketLog[(LogRead + i) % kLogCapacity];
    LogRead = (LogRead + count) % kLogCapacity;
    LogCount -= count;
    Mutex_Unlock(MPQueueLock);
    return count;
}

void LocalMP::FIFORead(int inst, int fifo, void* buf, int len) noexcept
{
    u8* data;

    u32 offset, datalen;
    if (fifo == 0)
    {
        offset = PacketReadOffset[inst];
        data = MPPacketQueue;
        datalen = kPacketQueueSize;
    }
    else
    {
        offset = ReplyReadOffset[inst];
        data = MPReplyQueue;
        datalen = kReplyQueueSize;
    }

    if ((offset + len) >= datalen)
    {
        u32 part1 = datalen - offset;
        memcpy(buf, &data[offset], part1);
        memcpy(&((u8*)buf)[part1], data, len - part1);
        offset = len - part1;
    }
    else
    {
        memcpy(buf, &data[offset], len);
        offset += len;
    }

    if (fifo == 0) PacketReadOffset[inst] = offset;
    else           ReplyReadOffset[inst] = offset;
}

void LocalMP::FIFOWrite(int inst, int fifo, void* buf, int len) noexcept
{
    u8* data;

    u32 offset, datalen;
    if (fifo == 0)
    {
        offset = MPStatus.PacketWriteOffset;
        data = MPPacketQueue;
        datalen = kPacketQueueSize;
    }
    else
    {
        offset = MPStatus.ReplyWriteOffset;
        data = MPReplyQueue;
        datalen = kReplyQueueSize;
    }

    if ((offset + len) >= datalen)
    {
        u32 part1 = datalen - offset;
        memcpy(&data[offset], buf, part1);
        memcpy(data, &((u8*)buf)[part1], len - part1);
        offset = len - part1;
    }
    else
    {
        memcpy(&data[offset], buf, len);
        offset += len;
    }

    if (fifo == 0) MPStatus.PacketWriteOffset = offset;
    else           MPStatus.ReplyWriteOffset = offset;
}

int LocalMP::SendPacketGeneric(int inst, u32 type, const u8* packet, int len, u64 timestamp, bool bypass, int targets) noexcept
{
    if (len < 0 || len > kMaxFrameSize || (len && !packet))
    {
        Log(LogLevel::Warn, "wifi: attempting to send frame too big (len=%d max=%d)\n", len, kMaxFrameSize);
        return 0;
    }

    Mutex_Lock(MPQueueLock);

    if (!bypass && (InterceptMask & (1u << inst))) {
        if (HeldPackets.size() >= 64) { ++LogDropped; Mutex_Unlock(MPQueueLock); return 0; }
        HeldPacket held {}; held.Id = NextHeldId++; held.Sender = inst; held.Type = type;
        held.Timestamp = timestamp; held.Targets = RouteMasks[inst]; held.Length = len;
        if (len) memcpy(held.Payload.data(), packet, len);
        HeldPackets.push_back(held); Mutex_Unlock(MPQueueLock); return len;
    }

    u16 mask = MPStatus.ConnectedBitmask;

    // TODO: check if the FIFO is full!

    RoutedPacketHeader pktheader {};
    pktheader.Magic = 0x4946494E;
    pktheader.SenderID = inst;
    pktheader.Type = type;
    pktheader.Length = len;
    pktheader.Timestamp = timestamp;
    pktheader.Targets = targets < 0 ? RouteMasks[inst] : targets;

    type &= 0xFFFF;
    int replyHost = MPStatus.MPHostinst;
    if (type == 2 && (PeersKnown & (1u << inst)))
    {
        // Reply frames contain the real receiver at 12-byte TX header + 4.
        // Empty replies still belong to this client's associated BSSID.
        const u8* destination = len >= 22 ? packet + 16 : PeerBSSID[inst].data();
        u16 hosts = 0;
        replyHost = -1;
        for (int i = 0; i < 16; ++i)
            if (i != inst && (mask & PeersKnown & (1u << i))
                && !memcmp(PeerMAC[i].data(), destination, 6))
            {
                hosts |= 1u << i;
                replyHost = i;
            }
        pktheader.Targets &= hosts;
        if (!pktheader.Targets) replyHost = -1;
    }
    int nfifo = (type == 2) ? 1 : 0;
    FIFOWrite(inst, nfifo, &pktheader, sizeof(pktheader));
    if (len)
        FIFOWrite(inst, nfifo, const_cast<u8*>(packet), len);

    LogPacket(inst, type == 2 ? replyHost : -1,
              pktheader.Type, packet, len, timestamp, false);

    if (type == 1)
    {
        // Retained in the legacy transport snapshot; registered in-process
        // peers route replies by receiver MAC rather than this global ID.
        MPStatus.MPHostinst = inst;
        MPStatus.MPReplyBitmask = 0;
        ReplyReadOffset[inst] = MPStatus.ReplyWriteOffset;
        Semaphore_Reset(SemPool[16 + inst]);
    }
    else if (type == 2)
    {
        MPStatus.MPReplyBitmask |= (1 << inst);
    }

    if (type == 2)
    {
        // Every active reader shares this FIFO. Each must consume (or skip)
        // every entry, otherwise its read cursor and semaphore count diverge
        // as soon as another host receives a reply.
        for (int i = 0; i < 16; ++i)
            if (mask & (1u << i)) Semaphore_Post(SemPool[16 + i]);
    }
    else
    {
        for (int i = 0; i < 16; i++)
        {
            if (mask & (1<<i))
                Semaphore_Post(SemPool[i]);
        }
    }

    // Keep enqueue and notification atomic with Begin()/SendCmd(), both of
    // which reset read cursors and semaphore counts under this same lock.
    Mutex_Unlock(MPQueueLock);

    return len;
}

int LocalMP::RecvPacketGeneric(int inst, u8* packet, bool block, u64* timestamp) noexcept
{
    for (;;)
    {
        if (!Semaphore_TryWait(SemPool[inst], block ? RecvTimeout : 0))
        {
            return 0;
        }

        Mutex_Lock(MPQueueLock);

        RoutedPacketHeader pktheader = {};
        FIFORead(inst, 0, &pktheader, sizeof(pktheader));

        if (pktheader.Magic != 0x4946494E)
        {
            Log(LogLevel::Warn, "PACKET FIFO OVERFLOW\n");
            PacketReadOffset[inst] = MPStatus.PacketWriteOffset;
            Semaphore_Reset(SemPool[inst]);
            Mutex_Unlock(MPQueueLock);
            return 0;
        }

        if (pktheader.SenderID == inst || !(pktheader.Targets & (1u << inst)))
        {
            // skip this packet
            PacketReadOffset[inst] += pktheader.Length;
            if (PacketReadOffset[inst] >= kPacketQueueSize)
                PacketReadOffset[inst] -= kPacketQueueSize;

            Mutex_Unlock(MPQueueLock);
            continue;
        }

        if (pktheader.Length)
        {
            FIFORead(inst, 0, packet, pktheader.Length);

            if (pktheader.Type == 1)
                LastHostID = pktheader.SenderID;
        }

        LogPacket(pktheader.SenderID, inst, pktheader.Type, packet,
                  pktheader.Length, pktheader.Timestamp, true);

        if (timestamp) *timestamp = pktheader.Timestamp;
        Mutex_Unlock(MPQueueLock);
        return pktheader.Length;
    }
}

int LocalMP::SendPacket(int inst, u8* packet, int len, u64 timestamp)
{
    return SendPacketGeneric(inst, 0, packet, len, timestamp);
}

int LocalMP::RecvPacket(int inst, u8* packet, u64* timestamp)
{
    return RecvPacketGeneric(inst, packet, false, timestamp);
}

int LocalMP::SendCmd(int inst, u8* packet, int len, u64 timestamp)
{
    return SendPacketGeneric(inst, 1, packet, len, timestamp);
}

int LocalMP::SendReply(int inst, u8* packet, int len, u64 timestamp, u16 aid)
{
    return SendPacketGeneric(inst, 2 | (aid<<16), packet, len, timestamp);
}

int LocalMP::SendAck(int inst, u8* packet, int len, u64 timestamp)
{
    return SendPacketGeneric(inst, 3, packet, len, timestamp);
}

int LocalMP::RecvHostPacket(int inst, u8* packet, u64* timestamp)
{
    bool disconnected = false;
    Mutex_Lock(MPQueueLock);
    if (PeersKnown & (1u << inst))
    {
        bool known = false, connected = false;
        for (int i = 0; i < 16; ++i)
            if (i != inst && (PeersKnown & (1u << i))
                && !memcmp(PeerMAC[i].data(), PeerBSSID[inst].data(), 6))
            {
                known = true;
                connected |= (MPStatus.ConnectedBitmask & (1u << i)) != 0;
            }
        disconnected = known && !connected;
    }
    else if (LastHostID != -1)
        disconnected = !(MPStatus.ConnectedBitmask & (1u << LastHostID));
    Mutex_Unlock(MPQueueLock);
    if (disconnected) return -1;

    return RecvPacketGeneric(inst, packet, true, timestamp);
}

u16 LocalMP::RecvReplies(int inst, u8* packets, u64 timestamp, u16 aidmask)
{
    u16 ret = 0;
    u16 myinstmask = (1 << inst);
    u16 curinstmask;

    curinstmask = MPStatus.ConnectedBitmask;

    // if all clients have left: return early
    if ((myinstmask & curinstmask) == curinstmask)
        return 0;

    for (;;)
    {
        if (!Semaphore_TryWait(SemPool[16+inst], RecvTimeout))
        {
            // no more replies available
            return ret;
        }

        Mutex_Lock(MPQueueLock);

        RoutedPacketHeader pktheader = {};
        FIFORead(inst, 1, &pktheader, sizeof(pktheader));

        if (pktheader.Magic != 0x4946494E)
        {
            Log(LogLevel::Warn, "REPLY FIFO OVERFLOW\n");
            ReplyReadOffset[inst] = MPStatus.ReplyWriteOffset;
            Semaphore_Reset(SemPool[16 + inst]);
            Mutex_Unlock(MPQueueLock);
            return 0;
        }

        if ((pktheader.SenderID == inst) || !(pktheader.Targets & (1u << inst)) || // excluded by router
            (pktheader.Timestamp < (timestamp - 32))) // stale packet
        {
            // skip this packet
            ReplyReadOffset[inst] += pktheader.Length;
            if (ReplyReadOffset[inst] >= kReplyQueueSize)
                ReplyReadOffset[inst] -= kReplyQueueSize;

            Mutex_Unlock(MPQueueLock);
            continue;
        }

        if (pktheader.Length)
        {
            u32 aid = (pktheader.Type >> 16);
            FIFORead(inst, 1, &packets[(aid-1)*1024], pktheader.Length);
            ret |= (1 << aid);
            LogPacket(pktheader.SenderID, inst, pktheader.Type,
                      &packets[(aid-1)*1024], pktheader.Length, pktheader.Timestamp, true);
        }
        else
        {
            LogPacket(pktheader.SenderID, inst, pktheader.Type,
                      nullptr, 0, pktheader.Timestamp, true);
        }

        myinstmask |= (1 << pktheader.SenderID);
        if (((myinstmask & curinstmask) == curinstmask) ||
            ((ret & aidmask) == aidmask))
        {
            // all the clients have sent their reply

            Mutex_Unlock(MPQueueLock);
            return ret;
        }

        Mutex_Unlock(MPQueueLock);
    }
}

}


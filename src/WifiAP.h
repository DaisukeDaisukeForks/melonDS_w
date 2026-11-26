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

#ifndef WIFIAP_H
#define WIFIAP_H

#include "types.h"
#include <string>
#include <array>

namespace melonDS
{
class Wifi;
class Savestate;

class WifiAP
{
public:
    WifiAP(Wifi* client, void* userdata);
    ~WifiAP();
    void Reset();
    void DoTransportState(Savestate* state);
    void SetSSID(const char* value, size_t length);
    bool ConfigureAP(int slot, const u8* ssid, int length, int security, const u8* key, int keyLength, int channel, const u8* mac);
    bool RemoveAP(int slot);

    static const char* APName;
    static const u8 APMac[6];
    static const u8 APChannel;

    void MSTimer();

    // packet format: 12-byte TX header + original 802.11 frame
    int SendPacket(const u8* data, int len);
    int RecvPacket(u8* data);

private:
    struct APProfile {
        bool enabled = false;
        bool configured = false;
        std::string ssid;
        std::array<u8, 6> mac{};
        u8 channel = 6;
        u8 security = 0;
        std::array<u8, 13> key{};
        u8 keyLength = 0;
    };
    static constexpr int MaxAPs = 8;
    std::array<APProfile, MaxAPs> Profiles{};
    int ConnectedAP = -1;
    u32 PendingBeacons = 0;
    u32 PendingProbes = 0;
    std::array<u8, 6> ProbeClient{};
    int ProbeChannel = 6;
    int FindAP(const u8* mac) const;
    int BuildAnnouncement(u8* out, int slot, bool probe);
    Wifi* Client;
    void* UserData;

    u64 USCounter;

    u16 SeqNo;

    bool BeaconDue;

    u8 PacketBuffer[2048];
    int PacketLen;
    int RXNum;

    u8 LANBuffer[2048];

    // this is a lazy AP, we only keep track of one client
    // 0=disconnected 1=authenticated 2=associated
    int ClientStatus;

    int HandleManagementFrame(const u8* data, int len);
};

}
#endif

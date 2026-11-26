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

#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <utility>
#include "NDS.h"
#include "Wifi.h"
#include "WifiAP.h"
#include "Savestate.h"
#include "Platform.h"

#ifndef __WIN32__
#include <stddef.h>
#endif

namespace melonDS
{
void WifiAP::DoTransportState(Savestate* state)
{
    // The first profile uses the historical transport layout for old .mel files.
    u32 length = static_cast<u32>(Profiles[0].ssid.size());
    state->Var32(&length);
    if (length > 32) { state->Error = true; return; }
    if (!state->Saving) Profiles[0].ssid.resize(length);
    state->VarArray(Profiles[0].ssid.data(), length);
    state->Var64(&USCounter); state->Var16(&SeqNo); state->VarBool(&BeaconDue);
    state->VarArray(PacketBuffer, sizeof(PacketBuffer));
    state->VarArray(&PacketLen, sizeof(PacketLen)); state->VarArray(&RXNum, sizeof(RXNum));
    state->VarArray(LANBuffer, sizeof(LANBuffer)); state->VarArray(&ClientStatus, sizeof(ClientStatus));
    if (PacketLen < 0 || PacketLen > static_cast<int>(sizeof(PacketBuffer))) state->Error = true;
}
using Platform::Log;
using Platform::LogLevel;


const char* WifiAP::APName = "melonAP";
const u8 WifiAP::APMac[6] = {0x00, 0xF0, 0x77, 0x77, 0x77, 0x77};
const u8 WifiAP::APChannel = 6;

#define PWRITE_8(p, v)      *p++ = v;
#define PWRITE_16(p, v)     *(u16*)p = v; p += 2;
#define PWRITE_32(p, v)     *(u32*)p = v; p += 4;
#define PWRITE_64(p, v)     *(u64*)p = v; p += 8;

#define PWRITE_MAC(p, a,b,c,d,e,f) \
    *p++ = a; *p++ = b; *p++ = c; *p++ = d; *p++ = e; *p++ = f;

#define PWRITE_MAC2(p, m) \
    *p++ = m[0]; *p++ = m[1]; *p++ = m[2]; *p++ = m[3]; *p++ = m[4]; *p++ = m[5];

#define PWRITE_SEQNO(p)     PWRITE_16(p, SeqNo); SeqNo += 0x10;

#define PWRITE_TXH(p, len, rate) \
    PWRITE_16(p, 0); \
    PWRITE_16(p, 0); \
    PWRITE_16(p, 0); \
    PWRITE_16(p, 0); \
    PWRITE_8(p, rate); \
    PWRITE_8(p, APChannel); \
    PWRITE_16(p, len);

//#define PALIGN_4(p, base)  p += ((4 - ((ptrdiff_t)(p-base) & 0x3)) & 0x3);
// no idea what is the ideal padding there
// but in the case of management frames the padding shouldn't be counted as an information element
// (theory: the hardware just doesn't touch the space between the frame and the FCS)
#define PLEN(p, base)      (int)(ptrdiff_t)(p-base)
#define PALIGN_4(p, base)  while (PLEN(p,base) & 0x3) *p++ = 0xFF;


bool MACEqual(const u8* a, const u8* b);
bool MACIsBroadcast(const u8* a);


WifiAP::WifiAP(Wifi* client, void* userdata) : Client(client), UserData(userdata)
{
    Profiles[0].enabled = true;
    Profiles[0].ssid = APName;
    std::copy(APMac, APMac + 6, Profiles[0].mac.begin());
}

void WifiAP::SetSSID(const char* value, size_t length)
{
    if (!Profiles[0].configured) Profiles[0].ssid.assign(value, std::min(length, size_t(32)));
}

bool WifiAP::ConfigureAP(int slot, const u8* ssid, int length, int security, const u8* key,
                         int keyLength, int channel, const u8* mac)
{
    if (slot < 0 || slot >= MaxAPs || !ssid || length < 1 || length > 32 || !mac ||
        (mac[0] & 1) || channel < 1 || channel > 14 || security < 0 || security > 2 ||
        keyLength != (security == 0 ? 0 : security == 1 ? 5 : 13) || (keyLength && !key)) return false;
    for (int i = 0; i < MaxAPs; ++i)
        if (i != slot && Profiles[i].enabled &&
            std::equal(Profiles[i].mac.begin(), Profiles[i].mac.end(), mac)) return false;
    APProfile profile;
    profile.enabled = profile.configured = true;
    profile.ssid.assign(reinterpret_cast<const char*>(ssid), length);
    std::copy(mac, mac + 6, profile.mac.begin());
    profile.channel = static_cast<u8>(channel);
    profile.security = static_cast<u8>(security);
    profile.keyLength = static_cast<u8>(keyLength);
    if (keyLength) std::copy(key, key + keyLength, profile.key.begin());
    Profiles[slot] = std::move(profile);
    PendingBeacons |= (1U << slot);
    PendingProbes &= ~(1U << slot);
    if (ConnectedAP == slot) { ConnectedAP = -1; ClientStatus = 0; }
    return true;
}

bool WifiAP::RemoveAP(int slot)
{
    if (slot < 0 || slot >= MaxAPs) return false;
    Profiles[slot] = APProfile{};
    PendingBeacons &= ~(1U << slot);
    PendingProbes &= ~(1U << slot);
    if (ConnectedAP == slot) { ConnectedAP = -1; ClientStatus = 0; }
    return true;
}

int WifiAP::FindAP(const u8* mac) const
{
    for (int i = 0; i < MaxAPs; ++i)
        if (Profiles[i].enabled && std::equal(Profiles[i].mac.begin(), Profiles[i].mac.end(), mac))
            return i;
    return -1;
}

WifiAP::~WifiAP()
{
}

void WifiAP::Reset()
{
    // random starting point for the counter
    USCounter = 0x428888000ULL;
    SeqNo = 0x0120;

    BeaconDue = false;

    memset(PacketBuffer, 0, sizeof(PacketBuffer));
    PacketLen = 0;
    RXNum = 0;

    ClientStatus = 0;
    ConnectedAP = -1;
    PendingBeacons = 0;
    PendingProbes = 0;
}


void WifiAP::MSTimer()
{
    USCounter += 0x400;

    u32 chk = (u32)USCounter;
    if (!(chk & 0x1FC00))
    {
        for (int i = 0; i < MaxAPs; ++i)
            if (Profiles[i].enabled) PendingBeacons |= (1U << i);
    }
}


int WifiAP::BuildAnnouncement(u8* data, int slot, bool probe)
{
    const APProfile& ap = Profiles[slot];
    u8* base = data + 12;
    u8* p = base;
    PWRITE_16(p, probe ? 0x0050 : 0x0080);
    PWRITE_16(p, 0);
    if (probe) PWRITE_MAC2(p, ProbeClient.data());
    else PWRITE_MAC(p, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF);
    PWRITE_MAC2(p, ap.mac.data());
    PWRITE_MAC2(p, ap.mac.data());
    PWRITE_SEQNO(p);
    PWRITE_64(p, USCounter);
    PWRITE_16(p, 128);
    PWRITE_16(p, 0x0021 | (ap.security ? 0x0010 : 0));
    PWRITE_8(p, 0x01); PWRITE_8(p, 0x02); PWRITE_8(p, 0x82); PWRITE_8(p, 0x84);
    PWRITE_8(p, 0x03); PWRITE_8(p, 0x01); PWRITE_8(p, ap.channel);
    if (!probe) { PWRITE_8(p, 0x05); PWRITE_8(p, 0x04);
        PWRITE_32(p, 0); }
    PWRITE_8(p, 0x00); PWRITE_8(p, static_cast<u8>(ap.ssid.size()));
    memcpy(p, ap.ssid.data(), ap.ssid.size()); p += ap.ssid.size();
    PALIGN_4(p, base);
    PWRITE_32(p, 0xDEADBEEF);
    const int length = PLEN(p, base);
    p = data;
    PWRITE_16(p, 0); PWRITE_16(p, 0); PWRITE_16(p, 0); PWRITE_16(p, 0);
    PWRITE_8(p, 20); PWRITE_8(p, ap.channel); PWRITE_16(p, length);
    return length + 12;
}

int WifiAP::HandleManagementFrame(const u8* data, int len)
{
    // TODO: perfect this
    // noting that frames sent pre-auth/assoc don't have a proper BSSID
    //if (!MACEqual(&data[16], (u8*)APMac)) // check BSSID
    //    return 0;

    if (RXNum)
    {
        Log(LogLevel::Warn, "wifiAP: can't reply!!\n");
        return 0;
    }

    if (len < 12 + 24) return 0;
    u16 framectl = *(u16*)&data[0];
    const int targetAP = FindAP(&data[16]);
    const u8* targetMac = targetAP >= 0 ? Profiles[targetAP].mac.data() : APMac;
    const bool targetMatches = targetAP >= 0 && Profiles[targetAP].channel == ProbeChannel;
    if (((framectl >> 4) & 0xF) == 4) {
        // Probe requests have either a wildcard SSID or an SSID information element.
        std::string requested;
        bool foundSSID = false;
        const int end = len - 12;
        for (int pos = 24; pos + 2 <= end;) {
            const int kind = data[pos++], size = data[pos++];
            if (pos + size > end) return 0;
            if (kind == 0) {
                requested.assign(reinterpret_cast<const char*>(data + pos), size);
                foundSSID = true;
                break;
            }
            pos += size;
        }
        if (!foundSSID) return 0;
        std::copy(data + 10, data + 16, ProbeClient.begin());
        for (int i = 0; i < MaxAPs; ++i)
            if (Profiles[i].enabled && Profiles[i].channel == ProbeChannel &&
                (requested.empty() || Profiles[i].ssid == requested)) PendingProbes |= (1U << i);
        return len;
    }

    u8* base = &PacketBuffer[0];
    u8* p = base;

    switch ((framectl >> 4) & 0xF)
    {
    case 0x0: // assoc request
        {
            if (!targetMatches || ConnectedAP != targetAP) return 0;

            if (ClientStatus != 1)
            {
                Log(LogLevel::Error, "wifiAP: bad assoc request, needs auth prior\n");
                return 0;
            }

            ClientStatus = 2;
            Log(LogLevel::Debug, "wifiAP: client associated\n");

            PWRITE_16(p, 0x0010);
            PWRITE_16(p, 0x0000); // duration??
            PWRITE_MAC2(p, (&data[10])); // recv
            PWRITE_MAC2(p, targetMac); // sender
            PWRITE_MAC2(p, targetMac); // BSSID
            PWRITE_SEQNO(p);

            PWRITE_16(p, 0x0021); // capability
            PWRITE_16(p, 0); // status (success)
            PWRITE_16(p, 0xC001); // assoc ID
            PWRITE_8(p, 0x01); PWRITE_8(p, 0x02); PWRITE_8(p, 0x82); PWRITE_8(p, 0x84); // rates

            PacketLen = PLEN(p, base);
            RXNum = 1;
        }
        return len;

    case 0x4: // probe request
        {
            // Nintendo's WFC setup util sends probe requests when searching for APs
            // these should be replied with a probe response, which is almost like a beacon

            PWRITE_16(p, 0x0050);
            PWRITE_16(p, 0x0000); // duration??
            PWRITE_MAC2(p, (&data[10])); // recv
            PWRITE_MAC2(p, APMac); // sender
            PWRITE_MAC2(p, APMac); // BSSID (checkme)
            PWRITE_SEQNO(p);

            PWRITE_64(p, USCounter);
            PWRITE_16(p, 128); // beacon interval
            PWRITE_16(p, 0x0021); // capability
            PWRITE_8(p, 0x01); PWRITE_8(p, 0x02); PWRITE_8(p, 0x82); PWRITE_8(p, 0x84); // rates
            PWRITE_8(p, 0x03); PWRITE_8(p, 0x01); PWRITE_8(p, APChannel); // current channel
            PWRITE_8(p, 0x00); PWRITE_8(p, Profiles[0].ssid.size());
            memcpy(p, Profiles[0].ssid.data(), Profiles[0].ssid.size()); p += Profiles[0].ssid.size();

            PacketLen = PLEN(p, base);
            RXNum = 1;
        }
        return len;

    case 0xA: // deassoc
        {
            if (!targetMatches || ConnectedAP != targetAP) return 0;

            ClientStatus = 1;
            Log(LogLevel::Debug, "wifiAP: client deassociated\n");

            PWRITE_16(p, 0x00A0);
            PWRITE_16(p, 0x0000); // duration??
            PWRITE_MAC2(p, (&data[10])); // recv
            PWRITE_MAC2(p, targetMac); // sender
            PWRITE_MAC2(p, targetMac); // BSSID
            PWRITE_SEQNO(p);

            PWRITE_16(p, 3); // reason code

            PacketLen = PLEN(p, base);
            RXNum = 1;
        }
        return len;

    case 0xB: // auth
        {
            if (!targetMatches || len < 12 + 30 || *(const u16*)(data + 24) != 0) return 0;
            ConnectedAP = targetAP;
            ClientStatus = 1;
            Log(LogLevel::Debug, "wifiAP: client authenticated\n");

            PWRITE_16(p, 0x00B0);
            PWRITE_16(p, 0x0000); // duration??
            PWRITE_MAC2(p, (&data[10])); // recv
            PWRITE_MAC2(p, targetMac); // sender
            PWRITE_MAC2(p, targetMac); // BSSID
            PWRITE_SEQNO(p);

            PWRITE_16(p, 0); // auth algorithm (open)
            PWRITE_16(p, 2); // auth sequence
            PWRITE_16(p, 0); // status code (success)

            PacketLen = PLEN(p, base);
            RXNum = 1;
        }
        return len;

    case 0xC: // deauth
        {
            if (!targetMatches || ConnectedAP != targetAP) return 0;
            ClientStatus = 0;
            ConnectedAP = -1;
            Log(LogLevel::Debug, "wifiAP: client deauthenticated\n");

            PWRITE_16(p, 0x00C0);
            PWRITE_16(p, 0x0000); // duration??
            PWRITE_MAC2(p, (&data[10])); // recv
            PWRITE_MAC2(p, targetMac); // sender
            PWRITE_MAC2(p, targetMac); // BSSID
            PWRITE_SEQNO(p);

            PWRITE_16(p, 3); // reason code

            PacketLen = PLEN(p, base);
            RXNum = 1;
        }
        return len;

    default:
        Log(LogLevel::Warn, "wifiAP: unknown management frame type %X\n", (framectl>>4)&0xF);
        return 0;
    }
}


int WifiAP::SendPacket(const u8* data, int len)
{
    if (len < 12 + 24) return 0;
    ProbeChannel = data[9];
    data += 12;

    u16 framectl = *(u16*)&data[0];
    switch ((framectl >> 2) & 0x3)
    {
    case 0: // management
        return HandleManagementFrame(data, len);

    case 1: // control
        // TODO ???
        return 0;

    case 2: // data
        {
            if (ConnectedAP < 0 || !Profiles[ConnectedAP].enabled ||
                Profiles[ConnectedAP].channel != ProbeChannel ||
                !MACEqual(data + 4, Profiles[ConnectedAP].mac.data()) ||
                (framectl & 0x0300) != 0x0100)
            {
                Log(LogLevel::Error, "wifiAP: got data frame with bad fromDS/toDS bits %04X\n", framectl);
                return 0;
            }

            // TODO: WFC patch??

            if (*(u32*)&data[24] == 0x0003AAAA && *(u16*)&data[28] == 0x0000)
            {
                if (ClientStatus != 2)
                {
                    Log(LogLevel::Warn, "wifiAP: trying to send shit without being associated\n");
                    return 0;
                }

                int lan_len = (len - 30 - 4) + 14;

                memcpy(&LANBuffer[0], &data[16], 6); // destination MAC
                memcpy(&LANBuffer[6], &data[10], 6); // source MAC
                *(u16*)&LANBuffer[12] = *(u16*)&data[30]; // type
                memcpy(&LANBuffer[14], &data[32], lan_len - 14);

                Platform::Net_SendPacket(LANBuffer, lan_len, UserData);
            }
        }
        return len;
    }

    return 0;
}

int WifiAP::RecvPacket(u8* data)
{
    if (BeaconDue)
    {
        BeaconDue = false;

        // craft beacon
        u8* base = data + 12;
        u8* p = base;

        PWRITE_16(p, 0x0080);
        PWRITE_16(p, 0x0000); // duration??
        PWRITE_MAC(p, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF); // recv
        PWRITE_MAC2(p, APMac); // sender
        PWRITE_MAC2(p, APMac); // BSSID
        PWRITE_SEQNO(p);

        PWRITE_64(p, USCounter);
        PWRITE_16(p, 128); // beacon interval
        PWRITE_16(p, 0x0021); // capability
        PWRITE_8(p, 0x01); PWRITE_8(p, 0x02); PWRITE_8(p, 0x82); PWRITE_8(p, 0x84); // rates
        PWRITE_8(p, 0x03); PWRITE_8(p, 0x01); PWRITE_8(p, APChannel); // current channel
        PWRITE_8(p, 0x05); PWRITE_8(p, 0x04); PWRITE_8(p, 0); PWRITE_8(p, 0); PWRITE_8(p, 0); PWRITE_8(p, 0); // TIM
        PWRITE_8(p, 0x00); PWRITE_8(p, Profiles[0].ssid.size());
        memcpy(p, Profiles[0].ssid.data(), Profiles[0].ssid.size()); p += Profiles[0].ssid.size();

        PALIGN_4(p, base);
        PWRITE_32(p, 0xDEADBEEF); // checksum. doesn't matter for now

        int len = PLEN(p, base);
        p = data;
        PWRITE_TXH(p, len, 20);

        return len+12;
    }

    if (RXNum)
    {
        RXNum = 0;

        u8* base = data + 12;
        u8* p = base;

        memcpy(p, PacketBuffer, PacketLen);
        p += PacketLen;

        PALIGN_4(p, base);
        PWRITE_32(p, 0xDEADBEEF);

        int len = PLEN(p, base);
        p = data;
        PWRITE_TXH(p, len, 20);

        return len+12;
    }

    if (PendingProbes || PendingBeacons) {
        const bool probe = PendingProbes != 0;
        u32& pending = probe ? PendingProbes : PendingBeacons;
        for (int slot = 0; slot < MaxAPs; ++slot) {
            const u32 bit = 1U << slot;
            if (!(pending & bit)) continue;
            pending &= ~bit;
            if (Profiles[slot].enabled) return BuildAnnouncement(data, slot, probe);
        }
    }
    if (ClientStatus < 2 || ConnectedAP < 0 || !Profiles[ConnectedAP].enabled) return 0;

    int rxlen = Platform::Net_RecvPacket(LANBuffer, UserData);
    while (rxlen > 0)
    {
        // check destination MAC
        if (!MACIsBroadcast(&LANBuffer[0]))
        {
            if (!MACEqual(&LANBuffer[0], Client->GetMAC()))
            {
                rxlen = Platform::Net_RecvPacket(LANBuffer, UserData);
                continue;
            }
        }

        if (MACEqual(&LANBuffer[6], Client->GetMAC()))
        {
            rxlen = Platform::Net_RecvPacket(LANBuffer, UserData);
            continue;
        }

        // packet is good

        u8* base = data + 12;
        u8* p = base;

        PWRITE_16(p, 0x0208);
        PWRITE_16(p, 0x0000); // duration??
        PWRITE_MAC2(p, (&LANBuffer[0])); // recv
        PWRITE_MAC2(p, Profiles[ConnectedAP].mac.data()); // BSSID
        PWRITE_MAC2(p, (&LANBuffer[6])); // sender
        PWRITE_SEQNO(p);

        PWRITE_32(p, 0x0003AAAA);
        PWRITE_16(p, 0x0000);
        PWRITE_16(p, *(u16*)&LANBuffer[12]);
        memcpy(p, &LANBuffer[14], rxlen-14); p += rxlen-14;

        PALIGN_4(p, base);
        PWRITE_32(p, 0xDEADBEEF); // checksum. doesn't matter for now

        int len = PLEN(p, base);
        p = data;
        PWRITE_TXH(p, len, 20);

        return len+12;
    }

    return 0;
}

}
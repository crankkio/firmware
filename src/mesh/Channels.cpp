#include "Channels.h"
#include "CryptoEngine.h"
#include "NodeDB.h"

#include <assert.h>

/// 16 bytes of random PSK for our _public_ default channel that all devices power up on (AES128)
static const uint8_t defaultpsk[] = {0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
                                     0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0xbf};

Channels channels;

uint8_t xorHash(uint8_t *p, size_t len)
{
    uint8_t code = 0;
    for (int i = 0; i < len; i++)
        code ^= p[i];
    return code;
}

/**
 * Validate a channel, fixing any errors as needed
 */
Channel &Channels::fixupChannel(ChannelIndex chIndex)
{
    Channel &ch = getByIndex(chIndex);

    ch.index = chIndex; // Preinit the index so it be ready to share with the phone (we'll never change it later)

    if (!ch.has_settings) {
        // No settings! Must disable and skip
        ch.role = Channel_Role_DISABLED;
        memset(&ch.settings, 0, sizeof(ch.settings));
        ch.has_settings = true;
    } else {
        ChannelSettings &channelSettings = ch.settings;

        // Convert the old string "Default" to our new short representation
        if (strcmp(channelSettings.name, "Default") == 0)
            *channelSettings.name = '\0';

        /* Convert any old usage of the defaultpsk into our new short representation.
        if (channelSettings.psk.size == sizeof(defaultpsk) &&
            memcmp(channelSettings.psk.bytes, defaultpsk, sizeof(defaultpsk)) == 0) {
            *channelSettings.psk.bytes = 1;
            channelSettings.psk.size = 1;
        } */
    }

    hashes[chIndex] = generateHash(chIndex);

    return ch;
}

/**
 * Write a default channel to the specified channel index
 */
void Channels::initDefaultChannel(ChannelIndex chIndex)
{
    Channel &ch = getByIndex(chIndex);
    ChannelSettings &channelSettings = ch.settings;

    // radioConfig.modem_config = RadioConfig_ModemConfig_Bw125Cr45Sf128;  // medium range and fast
    // channelSettings.modem_config = ChannelSettings_ModemConfig_Bw500Cr45Sf128;  // short range and fast, but wide
    // bandwidth so incompatible radios can talk together
    channelSettings.modem_config = ChannelSettings_ModemConfig_Bw125Cr48Sf4096; // slow and long range

    channelSettings.tx_power = 0; // default
    uint8_t defaultpskIndex = 1;
    channelSettings.psk.bytes[0] = defaultpskIndex;
    channelSettings.psk.size = 1;
    strcpy(channelSettings.name, "");

    ch.has_settings = true;
    ch.role = Channel_Role_PRIMARY;
}

/** Given a channel index, change to use the crypto key specified by that index
 */
void Channels::setCrypto(ChannelIndex chIndex)
{
    Channel &ch = getByIndex(chIndex);
    ChannelSettings &channelSettings = ch.settings;
    assert(ch.has_settings);

    memset(activePSK, 0, sizeof(activePSK)); // In case the user provided a short key, we want to pad the rest with zeros
    memcpy(activePSK, channelSettings.psk.bytes, channelSettings.psk.size);
    activePSKSize = channelSettings.psk.size;
    if (activePSKSize == 0) {
        if (ch.role == Channel_Role_SECONDARY) {
            DEBUG_MSG("Unset PSK for secondary channel %s. using primary key\n", ch.settings.name);
            setCrypto(primaryIndex);
        } else
            DEBUG_MSG("Warning: User disabled encryption\n");
    } else if (activePSKSize == 1) {
        // Convert the short single byte variants of psk into variant that can be used more generally

        uint8_t pskIndex = activePSK[0];
        DEBUG_MSG("Expanding short PSK #%d\n", pskIndex);
        if (pskIndex == 0)
            activePSKSize = 0; // Turn off encryption
        else {
            memcpy(activePSK, defaultpsk, sizeof(defaultpsk));
            activePSKSize = sizeof(defaultpsk);
            // Bump up the last byte of PSK as needed
            uint8_t *last = activePSK + sizeof(defaultpsk) - 1;
            *last = *last + pskIndex - 1; // index of 1 means no change vs defaultPSK
        }
    } else if (activePSKSize < 16) {
        // Error! The user specified only the first few bits of an AES128 key.  So by convention we just pad the rest of the key
        // with zeros
        DEBUG_MSG("Warning: User provided a too short AES128 key - padding\n");
        activePSKSize = 16;
    } else if (activePSKSize < 32 && activePSKSize != 16) {
        // Error! The user specified only the first few bits of an AES256 key.  So by convention we just pad the rest of the key
        // with zeros
        DEBUG_MSG("Warning: User provided a too short AES256 key - padding\n");
        activePSKSize = 32;
    }

    // Tell our crypto engine about the psk
    crypto->setKey(activePSKSize, activePSK);
}

void Channels::initDefaults()
{
    devicestate.channels_count = MAX_NUM_CHANNELS;
    for (int i = 0; i < devicestate.channels_count; i++)
        fixupChannel(i);
    initDefaultChannel(0);
}

void Channels::onConfigChanged()
{
    // Make sure the phone hasn't mucked anything up
    for (int i = 0; i < devicestate.channels_count; i++) {
        Channel &ch = fixupChannel(i);

        if (ch.role == Channel_Role_PRIMARY)
            primaryIndex = i;
    }

    setCrypto(primaryIndex); // FIXME: for the time being (still single channel - just use our only channel as the crypto key)
}

Channel &Channels::getByIndex(ChannelIndex chIndex)
{
    assert(chIndex < devicestate.channels_count);
    Channel *ch = devicestate.channels + chIndex;
    return *ch;
}

void Channels::setChannel(const Channel &c)
{
    Channel &old = getByIndex(c.index);

    // if this is the new primary, demote any existing roles
    if (c.role == Channel_Role_PRIMARY)
        for (int i = 0; i < devicestate.channels_count; i++)
            if (devicestate.channels[i].role == Channel_Role_PRIMARY)
                devicestate.channels[i].role = Channel_Role_SECONDARY;

    old = c; // slam in the new settings/role
}

const char *Channels::getName(size_t chIndex)
{
    // Convert the short "" representation for Default into a usable string
    ChannelSettings &channelSettings = getByIndex(chIndex).settings;
    const char *channelName = channelSettings.name;
    if (!*channelName) { // emptystring
        // Per mesh.proto spec, if bandwidth is specified we must ignore modemConfig enum, we assume that in that case
        // the app fucked up and forgot to set channelSettings.name

        if (channelSettings.bandwidth != 0)
            channelName = "Unset";
        else
            switch (channelSettings.modem_config) {
            case ChannelSettings_ModemConfig_Bw125Cr45Sf128:
                channelName = "Medium";
                break;
            case ChannelSettings_ModemConfig_Bw500Cr45Sf128:
                channelName = "ShortFast";
                break;
            case ChannelSettings_ModemConfig_Bw31_25Cr48Sf512:
                channelName = "LongAlt";
                break;
            case ChannelSettings_ModemConfig_Bw125Cr48Sf4096:
                channelName = "LongSlow";
                break;
            default:
                channelName = "Invalid";
                break;
            }
    }

    return channelName;
}

/**
* Generate a short suffix used to disambiguate channels that might have the same "name" entered by the human but different PSKs.
* The ideas is that the PSK changing should be visible to the user so that they see they probably messed up and that's why they
their nodes
* aren't talking to each other.
*
* This string is of the form "#name-X".
*
* Where X is either:
* (for custom PSKS) a letter from A to Z (base26), and formed by xoring all the bytes of the PSK together,
* OR (for the standard minimially secure PSKs) a number from 0 to 9.
*
* This function will also need to be implemented in GUI apps that talk to the radio.
*
* https://github.com/meshtastic/Meshtastic-device/issues/269
*/
const char *Channels::getPrimaryName()
{
    static char buf[32];

    char suffix;
    auto channelSettings = getPrimary();
    if (channelSettings.psk.size != 1) {
        // We have a standard PSK, so generate a letter based hash.
        uint8_t code = xorHash(activePSK, activePSKSize);

        suffix = 'A' + (code % 26);
    } else {
        suffix = '0' + channelSettings.psk.bytes[0];
    }

    snprintf(buf, sizeof(buf), "#%s-%c", channelSettings.name, suffix);
    return buf;
}

/** Given a channel hash setup crypto for decoding that channel (or the primary channel if that channel is unsecured)
 *
 * This method is called before decoding inbound packets
 *
 * @return -1 if no suitable channel could be found, otherwise returns the channel index
 */
int16_t Channels::setActiveByHash(ChannelHash channelHash) {}

/** Given a channel index setup crypto for encoding that channel (or the primary channel if that channel is unsecured)
 *
 * This method is called before encoding outbound packets
 *
 * @eturn the (0 to 255) hash for that channel - if no suitable channel could be found, return -1
 */
int16_t Channels::setActiveByIndex(ChannelIndex channelIndex) {}

/** Given a channel number, return the (0 to 255) hash for that channel
 * If no suitable channel could be found, return -1
 */
ChannelHash Channels::generateHash(ChannelIndex channelNum) {}
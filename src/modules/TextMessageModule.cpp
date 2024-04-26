#include "TextMessageModule.h"
#include "MeshService.h"
#include "NodeDB.h"
#include "PowerFSM.h"
#include "configuration.h"
#include "mesh/blockchain/BlockchainHandler.h"

TextMessageModule *textMessageModule;

ProcessMessage TextMessageModule::handleReceived(const meshtastic_MeshPacket &mp)
{
#ifdef DEBUG_PORT
    auto &p = mp.decoded;
    LOG_INFO("Received text msg from=0x%0x, id=0x%x, msg=%.*s\n", mp.from, mp.id, p.payload.size, p.payload.bytes);
#endif

    String message(p.payload.bytes, p.payload.size);
    LOG_INFO("\nCrankk message received: %s\n", message);

    char nodeIdHex[9];
    sprintf(nodeIdHex, "%08x", mp.from);
    String nodeId = String(nodeIdHex);
    LOG_INFO("\nFrom node id: %s\n", nodeId);
    if (message == "CR24" && nodeId != "0") {
        LOG_INFO("\nCreating BlockchainHandler with public key: %s\n", moduleConfig.wallet.public_key);
        std::unique_ptr<BlockchainHandler> blockchainHandler(
            new BlockchainHandler(moduleConfig.wallet.public_key, moduleConfig.wallet.private_key));

        String packetId = String(mp.id, HEX);
        String command = "(free.mesh03.add-received-with-chain \"" + nodeId + "\" \"" + packetId + "\" \"19\")";
        blockchainHandler->executeBlockchainCommand("send", command);
    }

    // We only store/display messages destined for us.
    // Keep a copy of the most recent text message.
    devicestate.rx_text_message = mp;
    devicestate.has_rx_text_message = true;

    powerFSM.trigger(EVENT_RECEIVED_MSG);
    notifyObservers(&mp);

    return ProcessMessage::CONTINUE; // Let others look at this message also if they want
}

bool TextMessageModule::wantPacket(const meshtastic_MeshPacket *p)
{
    return MeshService::isTextPayload(p);
}
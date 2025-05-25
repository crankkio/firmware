#include "configuration.h"
#if defined(ARCH_ESP32) && !MESHTASTIC_EXCLUDE_CRANKK
#include "CrankkModule.h"
#include "MeshService.h"
#include "NodeDB.h"
#include "PowerFSM.h"
#include "Router.h"

CrankkModule *crankkModule;

void CrankkModule::initializeBlockchainHandler()
{
    if (moduleConfig.wallet.enabled && moduleConfig.wallet.public_key && moduleConfig.wallet.private_key) {
        blockchainHandler_ = std::unique_ptr<BlockchainHandler>(
            new BlockchainHandler(moduleConfig.wallet.public_key, moduleConfig.wallet.private_key, moduleConfig.wallet.enabled));
        LOG_INFO("Blockchain handler initialized with wallet: %s\n", moduleConfig.wallet.public_key);
    } else {
        LOG_WARN("Blockchain handler disabled - invalid wallet config\n");
    }
}

ProcessMessage CrankkModule::handleReceived(const meshtastic_MeshPacket &mp)
{
#ifdef DEBUG_PORT
    auto &p = mp.decoded;
    LOG_DEBUG("Received crankk msg from=0x%0x, id=0x%x, msg=%.*s\n", mp.from, mp.id, p.payload.size, p.payload.bytes);
#endif

    String message = "";
    char msg[237];
    sprintf(msg, "%s", p.payload.bytes);
    message += msg;
    LOG_DEBUG("\nCrankk message received: %s\n", message);

    String nodeId = String(mp.from, HEX);
    LOG_DEBUG("\nFrom node id: %s\n", nodeId);

    if (!blockchainHandler_) {
        LOG_ERROR("Blockchain handler not initialized - check wallet config\n");
        return ProcessMessage::CONTINUE;
    }

    if (message == "CR24" && nodeId != "0") {
        handleCR24(mp, nodeId);
    } else if (message.startsWith("TRANSFER_FRAG:") && nodeId != "0") {
        handleFragmentedTransfer(mp, message);
    } else if (message.startsWith("TRANSFER:") && nodeId != "0") {
        handleTransferCommand(mp, message);
    } else if (message.startsWith("TRANSFER_RESPONSE:") && nodeId != "0") {
        // Handle transfer response
        String transferString = message.substring(18); // Skip "TRANSFER_RESPONSE:"
        LOG_INFO("Transfer response from node %x: %s\n", mp.from, transferString.c_str());
    }
    // Add other message handlers here

    // We only store/display messages destined for us.
    // Keep a copy of the most recent text message.
    // devicestate.rx_text_message = mp;
    // devicestate.has_rx_text_message = true;

    // powerFSM.trigger(EVENT_RECEIVED_MSG);
    // notifyObservers(&mp);

    return ProcessMessage::CONTINUE; // Let others look at this message also if they want
}

void CrankkModule::handleCR24(const meshtastic_MeshPacket &mp, const String &nodeId)
{
    // Get the director's public key in order to perform the encryption
    String get_key_command = "(free.mesh03.get-sender-details \"" + nodeId + "\")";
    String postRaw;
    BlockchainStatus status_local = blockchainHandler_->executeBlockchainCommand("local", get_key_command, postRaw);
    LOG_DEBUG("\nStatus 'get-sender-details': %s\n", blockchainHandler_->blockchainStatusToString(status_local).c_str());
    if (status_local == BlockchainStatus::SUCCESS) {
        String packetId = String(mp.id, HEX);
        String secret = blockchainHandler_->encryptPayload(packetId.c_str());
        String received_chain_command = "(free.mesh03.add-received-with-chain \"" + nodeId + "\" \"" + secret + "\" \"19\")";
        BlockchainStatus status_send = blockchainHandler_->executeBlockchainCommand("send", received_chain_command, postRaw);
        LOG_DEBUG("\nStatus 'add-received-with-chain': %s\n", blockchainHandler_->blockchainStatusToString(status_send).c_str());
    } else {
        LOG_DEBUG("\nError occurred: %s\n", blockchainHandler_->blockchainStatusToString(status_local).c_str());
    }
}

void CrankkModule::handleTransferCommand(const meshtastic_MeshPacket &mp, const String &message)
{
    // Example message format: "TRANSFER:<transfer_string>"
    String transferString = message.substring(9);
    BlockchainStatus status = blockchainHandler_->executeTransferFromString(transferString);
    if (status == BlockchainStatus::SUCCESS) {
        LOG_DEBUG("\nTransfer successful\n");
        // Send confirmation back to original sender
        meshtastic_MeshPacket *p = router->allocForSending();
        p->to = mp.from; // Send back to original sender
        p->from = nodeDB->getNodeNum();
        p->decoded.portnum = mp.decoded.portnum;
        p->hop_limit = 3;
        p->want_ack = true; // Request acknowledgment for this important message

        // Create confirmation message
        String response = "TRANSFER_RESPONSE:" + transferString;
        p->decoded.payload.size = response.length();
        memcpy(p->decoded.payload.bytes, response.c_str(), response.length());

        service->sendToMesh(p);
    } else if (status == BlockchainStatus::NO_WIFI) {
        LOG_DEBUG("\nNo WiFi, forwarding transfer request\n");
        meshtastic_MeshPacket *p = router->allocForSending();
        p->to = NODENUM_BROADCAST;
        p->from = nodeDB->getNodeNum();
        p->decoded.portnum = mp.decoded.portnum;
        p->hop_limit = 3;
        p->want_ack = false;

        // Forward the original transfer message
        memcpy(&p->decoded.payload, &mp.decoded.payload, sizeof(mp.decoded.payload));
        service->sendToMesh(p);
    } else {
        LOG_DEBUG("\nTransfer failed: %s\n", blockchainHandler_->blockchainStatusToString(status).c_str());
        // Optionally send failure message back to sender
        meshtastic_MeshPacket *p = router->allocForSending();
        p->to = mp.from;
        p->from = nodeDB->getNodeNum();
        p->decoded.portnum = mp.decoded.portnum;
        p->hop_limit = 3;
        p->want_ack = true;

        String response = "TRANSFER_RESPONSE:" + String(blockchainHandler_->blockchainStatusToString(status).c_str());
        p->decoded.payload.size = response.length();
        memcpy(p->decoded.payload.bytes, response.c_str(), response.length());

        service->sendToMesh(p);
    }
}

void CrankkModule::handleFragmentedTransfer(const meshtastic_MeshPacket &mp, const String &message)
{
    // Format: TRANSFER_FRAG:index:total:data
    int firstColon = message.indexOf(':', 13); // Skip "TRANSFER_FRAG:"
    int secondColon = message.indexOf(':', firstColon + 1);

    int fragmentIndex = message.substring(13, firstColon).toInt();
    int totalFragments = message.substring(firstColon + 1, secondColon).toInt();
    String fragmentData = message.substring(secondColon + 1);

    // Store fragment
    if (fragmentedMessages[mp.from].size() == 0) {
        fragmentedMessages[mp.from].resize(totalFragments);
        expectedFragments[mp.from] = totalFragments;
    }

    fragmentedMessages[mp.from][fragmentIndex] = fragmentData;

    // Check if we have all fragments
    bool complete = true;
    String fullMessage = "";
    for (size_t i = 0; i < totalFragments; i++) {
        if (fragmentedMessages[mp.from][i].length() == 0) {
            complete = false;
            break;
        }
        fullMessage += fragmentedMessages[mp.from][i];
    }

    if (complete) {
        // Process the complete message
        handleTransferCommand(mp, "TRANSFER:" + fullMessage);

        // Clear the stored fragments
        fragmentedMessages.erase(mp.from);
        expectedFragments.erase(mp.from);
    }
}

void CrankkModule::sendTransfer(const String &address, const String &amount)
{
    if (blockchainHandler_->isWalletConfigValid()) {
        String transferString;
        BlockchainStatus status = blockchainHandler_->executeTransfer(address, amount, "free.crankk01", transferString);
        if (status == BlockchainStatus::NO_WIFI) {
            LOG_INFO("No WiFi connection, skipping transfer");
            LOG_INFO("Transfer string: %s", transferString.c_str());

            // Always send as fragments, even for small messages
            const size_t MAX_PAYLOAD_SIZE = 200; // Leave room for headers
            String fullMessage = transferString; // Don't add "TRANSFER:" prefix here
            size_t messageLength = fullMessage.length();
            size_t numFragments = (messageLength + MAX_PAYLOAD_SIZE - 1) / MAX_PAYLOAD_SIZE;

            LOG_DEBUG("Sending transfer in %d fragments\n", numFragments);

            for (size_t i = 0; i < numFragments; i++) {
                meshtastic_MeshPacket *p = router->allocForSending();
                p->to = NODENUM_BROADCAST;
                p->from = nodeDB->getNodeNum();
                p->decoded.portnum = meshtastic_PortNum_CRANKK_APP;
                p->hop_limit = 3;
                p->want_ack = false;

                // Format: TRANSFER_FRAG:fragment_index:total_fragments:data
                String fragment = fullMessage.substring(i * MAX_PAYLOAD_SIZE, min((i + 1) * MAX_PAYLOAD_SIZE, messageLength));
                String fragMessage = "TRANSFER_FRAG:" + String(i) + ":" + String(numFragments) + ":" + fragment;

                p->decoded.payload.size = fragMessage.length();
                memcpy(p->decoded.payload.bytes, fragMessage.c_str(), fragMessage.length());

                service->sendToMesh(p);
                LOG_DEBUG("Sent fragment %d/%d, size %d\n", i + 1, numFragments, fragMessage.length());
            }
        } else if (status == BlockchainStatus::SUCCESS) {
            LOG_INFO("Transfer successful");
            LOG_INFO("Transfer string: %s", transferString.c_str());
        } else {
            LOG_ERROR("Transfer failed: %s", blockchainHandler_->blockchainStatusToString(status).c_str());
        }
    }
}

bool CrankkModule::wantPacket(const meshtastic_MeshPacket *p)
{
    return p->decoded.portnum == meshtastic_PortNum_CRANKK_APP;
    // return MeshService::isTextPayload(p);
}

#endif

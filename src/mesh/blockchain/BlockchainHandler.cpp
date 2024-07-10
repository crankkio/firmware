#if !MESHTASTIC_EXCLUDE_WEBSERVER
#include "BlockchainHandler.h"
#include "FSCommon.h"
#include "HTTPClient.h"
#include "WiFi.h"
#include "mbedtls/aes.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/pkcs5.h"
#include "memGet.h"
#include "mesh/wifi/WiFiAPClient.h"
#include "utils.h"
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>

// Redefine strptime to avoid IRAM issue when using the HTTPClient functions
char *strptime(const char *str, const char *format, struct tm *tm)
{
    if (sscanf(str, format, &tm->tm_year, &tm->tm_mon, &tm->tm_mday, &tm->tm_hour, &tm->tm_min, &tm->tm_sec) == 6) {
        tm->tm_year -= 1900; // Adjust year to be relative to 1900
        tm->tm_mon -= 1;     // Adjust month to be 0-based
        return (char *)(str + strlen(str));
    }
    return NULL;
}

BlockchainHandler::BlockchainHandler(const std::string public_key, const std::string private_key)
    : public_key_(public_key), private_key_(private_key)
{
    kda_server_ = "http://kda.crankk.org/chainweb/0.0/mainnet01/chain/19/pact/api/v1/";
    encryptionHandler_ = std::unique_ptr<EncryptionHandler>(new EncryptionHandler());
}

bool BlockchainHandler::isWalletConfigValid()
{
    return moduleConfig.wallet.enabled && public_key_.length() == 64 && private_key_.length() == 64;
}

int32_t BlockchainHandler::performNodeSync(HttpAPI *webAPI)
{
    LOG_DEBUG("\nWallet public key: %s\n", public_key_.data());

    if (!isWalletConfigValid() || !isWifiAvailable()) {
        return 300000; // Every 5 minutes.
    }
    char nodeIdHex[9];
    sprintf(nodeIdHex, "%08x", nodeDB->getNodeNum());
    String nodeId = String(nodeIdHex);
    LOG_DEBUG("\nMy node id: %s\n", nodeId);

    BlockchainStatus status = executeBlockchainCommand("local", "(free.mesh03.get-my-node)");
    LOG_DEBUG("\nResponse: %s\n", blockchainStatusToString(status).c_str());

    if (status == BlockchainStatus::READY) { // node exists, due for sending
        uint32_t packetId = generatePacketId();
        String secret_hex = String(packetId, HEX);
        String secret = encryptPayload(secret_hex.c_str());
        status = executeBlockchainCommand("send", "(free.mesh03.update-sent \"" + secret + "\")");
        if (status == BlockchainStatus::SUCCESS) {
            // Only send the radio beacon if the update-sent command is successful
            webAPI->sendSecret(packetId);
            LOG_DEBUG("\nUpdate sent successfully\n");
        } else {
            LOG_DEBUG("\nUpdate sent failed: %s\n", blockchainStatusToString(status).c_str());
        }
    } else if (status == BlockchainStatus::NODE_NOT_FOUND) { // node doesn't exist, insert it
        status = executeBlockchainCommand("send", "(free.mesh03.insert-my-node \"" + nodeId + "\")");
        LOG_DEBUG("\nNode insert local response: %s\n", blockchainStatusToString(status).c_str());
    } else if (status == BlockchainStatus::NOT_DUE) { // node exists, not due for sending
        LOG_DEBUG("\n%s\n", "DON'T SEND beacon");
    } else {
        LOG_DEBUG("\nError occurred: %s\n", blockchainStatusToString(status).c_str());
    }
    auto newHeap = memGet.getFreeHeap();
    LOG_TRACE("Free heap: %d\n", newHeap);
    return 300000; // Every 5 minutes. That should be enough for previous txn to be complete
}

JSONObject BlockchainHandler::createCommandObject(const String &command)
{
    JSONObject cmdObject;
    JSONArray signers;
    JSONObject signerObject = {
        {"scheme", new JSONValue("ED25519")}, {"pubKey", new JSONValue(public_key_)}, {"addr", new JSONValue(public_key_)}};
    signers.push_back(new JSONValue(signerObject));
    cmdObject["signers"] = new JSONValue(signers);

    JSONObject metaObject = {{"creationTime", new JSONValue((uint)getValidTime(RTCQualityFromNet))},
                             {"ttl", new JSONValue(28800)},
                             {"chainId", new JSONValue("19")},
                             {"gasPrice", new JSONValue(0.00001)},
                             {"gasLimit", new JSONValue(1000)},
                             {"sender", new JSONValue("k:" + public_key_)}};
    cmdObject["meta"] = new JSONValue(metaObject);

    String current_timestamp = getCurrentTimestamp();
    cmdObject["nonce"] = new JSONValue(current_timestamp.c_str());
    cmdObject["networkId"] = new JSONValue("mainnet01");

    JSONObject execObject = {
        {"code", new JSONValue(command.c_str())}, {"data", new JSONValue(JSONObject())} // Directly passing an empty JSONObject
    };
    JSONObject payloadObject = {{"exec", new JSONValue(execObject)}};
    cmdObject["payload"] = new JSONValue(payloadObject);

    return cmdObject;
}

JSONObject BlockchainHandler::preparePostObject(const JSONObject &cmdObject, const String &commandType)
{
    JSONObject postObject;
    std::unique_ptr<JSONValue> cmd(new JSONValue(cmdObject));
    const String cmdString = cmd->Stringify().c_str();
    postObject["cmd"] = new JSONValue(cmdString.c_str());
    HashVector vector{"Test1", cmdString.c_str()};

    uint8_t *hashBin = encryptionHandler_->Binhash(&vector);
    String hash = encryptionHandler_->KDAhash(&vector);

    String signHex = encryptionHandler_->generateSignature(public_key_, private_key_, hashBin);
    postObject["hash"] = new JSONValue(hash.c_str());
    JSONArray sigs;
    JSONObject sigObject{{"sig", new JSONValue(signHex.c_str())}};
    sigs.push_back(new JSONValue(sigObject));
    postObject["sigs"] = new JSONValue(sigs);

    return postObject;
}

BlockchainStatus BlockchainHandler::parseBlockchainResponse(const String &response, const String &command)
{
    std::unique_ptr<JSONValue> response_value(JSON::Parse(response.c_str()));
    if (response_value == nullptr) {
        return BlockchainStatus::PARSING_ERROR;
    }
    JSONObject responseObject = response_value->AsObject();
    JSONValue *result_value = responseObject["result"];
    JSONObject resultObject = result_value->AsObject();
    JSONValue *data_value = resultObject["data"];
    JSONValue *status_value = resultObject["status"];
    String status = status_value->Stringify().c_str();
    LOG_TRACE("Status value: %s\n", status);

    BlockchainStatus returnStatus =
        command.indexOf("get-my-node") > 0 ? BlockchainStatus::NODE_NOT_FOUND : BlockchainStatus::FAILURE;
    if (status.startsWith("\"s")) {
        JSONObject dataRespObject = data_value->AsObject();
        JSONValue *pubkeyd_value = dataRespObject["pubkeyd"];
        director_pubkeyd_ = pubkeyd_value->AsString();
        LOG_DEBUG("Director PUBKEYD: %s\n", director_pubkeyd_.c_str());

        if (command.indexOf("get-my-node") > 0) {
            JSONValue *send_value = dataRespObject["send"];
            String sendValue = send_value->Stringify().c_str();
            if (sendValue == "true") {
                returnStatus = BlockchainStatus::READY;
            } else {
                returnStatus = BlockchainStatus::NOT_DUE;
            }
        } else if (command.indexOf("get-sender-details") > 0) {
            returnStatus = BlockchainStatus::SUCCESS;
        }
    }
    return returnStatus;
}

BlockchainStatus BlockchainHandler::executeBlockchainCommand(const String &commandType, const String &command)
{
    if (!isWifiAvailable()) {
        return BlockchainStatus::NO_WIFI;
    }
    HTTPClient http;
    http.begin(kda_server_ + commandType);
    http.addHeader("Content-Type", "application/json");

    JSONObject cmdObject = createCommandObject(command);
    JSONObject postObject = preparePostObject(cmdObject, commandType);

    std::unique_ptr<JSONValue> post;
    if (commandType == "local") {
        post = std::unique_ptr<JSONValue>(new JSONValue(postObject));
    } else {
        JSONArray cmds;
        JSONObject cmdsObject;
        cmds.push_back(new JSONValue(postObject));
        cmdsObject["cmds"] = new JSONValue(cmds);
        post = std::unique_ptr<JSONValue>(new JSONValue(cmdsObject));
    }

    const String postRaw = post->Stringify().c_str();
    logLongString(postRaw);

    http.setTimeout(15000);
    int httpResponseCode = http.POST(postRaw);
    LOG_DEBUG("Kadena HTTP response %d\n", httpResponseCode);
    String response = http.getString();
    logLongString(response);

    http.end();
    LOG_TRACE("Called HTTP end\n");
    // Handle HTTP response codes
    if (httpResponseCode < 0 || (httpResponseCode >= 400 && httpResponseCode <= 599)) {
        return BlockchainStatus::HTTP_ERROR;
    }
    if (httpResponseCode == HTTP_CODE_NO_CONTENT) {
        return BlockchainStatus::EMPTY_RESPONSE;
    }

    if (commandType == "local") {
        return parseBlockchainResponse(response, command);
    } else {
        return BlockchainStatus::SUCCESS;
    }
}

String BlockchainHandler::encryptPayload(const std::string &payload)
{
    if (!encryptionHandler_) {
        LOG_ERROR("Encryption handler is not initialized. Encryption failed.\n");
        return "";
    }
    return encryptionHandler_->encrypt(director_pubkeyd_, payload);
}

// Function to convert enum to string
std::string BlockchainHandler::blockchainStatusToString(BlockchainStatus status)
{
    switch (status) {
    case BlockchainStatus::SUCCESS:
        return "SUCCESS";
    case BlockchainStatus::FAILURE:
        return "FAILURE";
    case BlockchainStatus::NO_WIFI:
        return "NO_WIFI";
    case BlockchainStatus::HTTP_ERROR:
        return "HTTP_ERROR";
    case BlockchainStatus::EMPTY_RESPONSE:
        return "EMPTY_RESPONSE";
    case BlockchainStatus::PARSING_ERROR:
        return "PARSING_ERROR";
    case BlockchainStatus::NODE_NOT_FOUND:
        return "NODE_NOT_FOUND";
    case BlockchainStatus::READY:
        return "READY";
    case BlockchainStatus::NOT_DUE:
        return "NOT_DUE";
    default:
        return "UNKNOWN_STATUS";
    }
}
#endif
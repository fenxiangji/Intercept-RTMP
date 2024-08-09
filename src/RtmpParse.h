
#include <string>
#include <vector>

#include "rtmp.h"

// RTMP chunk header structure
struct ChunkHeader {
    uint32_t timestamp;
    uint32_t messageLength;
    uint8_t messageTypeId;
    uint32_t messageStreamId;
};

// RTMP chunk structure
struct Chunk {
    ChunkHeader header;
    std::vector<uint8_t> data;
};

// Class to represent a message stream
class MessageStream {
private:
    std::vector<Chunk> chunks;
    uint32_t expectedLength;
    bool isComplete;

public:
    MessageStream() : expectedLength(0), isComplete(false) {}

    void addChunk(const Chunk& chunk) {
        chunks.push_back(chunk);
        if (chunks.size() == 1) {
            expectedLength = chunk.header.messageLength;
        }

        uint32_t totalLength = 0;
        for (const auto& c : chunks) {
            totalLength += c.data.size();
        }

        isComplete = (totalLength >= expectedLength);
    }

    bool isMessageComplete() const {
        return isComplete;
    }

    std::vector<uint8_t> getCompleteMessage() const {
        std::vector<uint8_t> completeMessage;
        for (const auto& chunk : chunks) {
            completeMessage.insert(completeMessage.end(), chunk.data.begin(), chunk.data.end());
        }
        return completeMessage;
    }
};

// Class to manage RTMP chunk streams
class RTMPChunkStream {
private:
    std::map<uint32_t, std::unique_ptr<MessageStream>> messageStreams;

public:
    void processChunk(const Chunk& chunk) {
        uint32_t streamId = chunk.header.messageStreamId;

        if (messageStreams.find(streamId) == messageStreams.end()) {
            messageStreams[streamId] = std::make_unique<MessageStream>();
        }

        messageStreams[streamId]->addChunk(chunk);

        if (messageStreams[streamId]->isMessageComplete()) {
            std::vector<uint8_t> completeMessage = messageStreams[streamId]->getCompleteMessage();
            handleMessage(chunk.header.messageTypeId, completeMessage);
            messageStreams.erase(streamId);
        }
    }

private:
    void handleMessage(uint8_t messageTypeId, const std::vector<uint8_t>& messageData) {
        std::cout << "Handling message of type " << static_cast<int>(messageTypeId)
            << " with length " << messageData.size() << std::endl;
        // Here you would implement the logic to handle different types of RTMP messages
    }
};

int parseRTMPPacket(std::vector<std::uint8_t>& data);
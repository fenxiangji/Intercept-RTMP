#include "RtmpParse.h"

#include <iostream>
#include <memory>
#include <ostream>

static int
DecodeInt32LE(const char* data)
{
	unsigned char* c = (unsigned char*)data;
	unsigned int val;

	val = (c[3] << 24) | (c[2] << 16) | (c[1] << 8) | c[0];
	return val;
}

int parseRTMPPacket(std::vector<std::uint8_t>& data)
{
	int nResult = 0;
	// Parse the RTMP packet
	std::uint8_t header_buffer[RTMP_MAX_HEADER_SIZE]{ 0 };
	int  header_size = 0;
	int chunk_size = 0;
	int nSize = 0;
	int offset = 0;
	int extendedTimestamp = 0;
	static const int packetSize[] = { 12, 8, 4, 1 };
	if (data.size() < 1)
	{
		return nResult;
	}
	header_buffer[0] = data[0];
	bool didAlloc = false;
	char* header = (char*)header_buffer;
	auto packet = std::make_shared<RTMPPacket>();
	memset(packet.get(), 0, sizeof(RTMPPacket));
	packet->m_headerType = (header_buffer[0] & 0xc0) >> 6;
	packet->m_nChannel = header_buffer[0] & 0x3f;
	header++;
	if(packet->m_nChannel == 0)
	{
		header_buffer[1] = data[1];
		packet->m_nChannel = header_buffer[1] + 64;
		header++;
		offset++;
	}else if(packet->m_nChannel == 1)
	{
		int tmp = 0;
		memcpy(&header_buffer[1], &data[1], 2);
		tmp = (header_buffer[2] << 8) + header_buffer[1];
		packet->m_nChannel = tmp + 64;
		header += 2;
		offset += 2;
	}
	else
	{
		offset++;
	}
	nResult = packetSize[packet->m_headerType];
	if(data.size() < nResult || offset >= data.size())
	{
		return nResult;
	}
	nSize = nResult;
	if (nSize == 12)	/* if we get a full header the timestamp is absolute */
		packet->m_hasAbsTimestamp = TRUE;
	else if(nSize < 12)
	{
		packet->m_hasAbsTimestamp = FALSE;
		packet->m_nTimeStamp = 0;
	}
	nSize--;
	if(nSize < 0 || nSize > (int)(data.size() - offset))
	{
		return nResult;
	}
	memcpy(header, &data[offset], nSize);
	offset += nSize;
	header_size = nSize + (header - (char*)header_buffer);
	if(nSize >= 3)
	{
		packet->m_nTimeStamp = AMF_DecodeInt32(header);
		if(nSize >= 6)
		{
			packet->m_nBodySize = AMF_DecodeInt24(header + 3);
			packet->m_nBytesRead = 0;
			if(nSize > 6)
			{
				packet->m_packetType = header[6];

				if (nSize == 11)
					packet->m_nInfoField2 = DecodeInt32LE(header + 7);
				
			}
		}
	}
	if(packet->m_packetType != 0x14)
	{
		return nResult;
	}
	if(offset + 4 > data.size())
	{
		return nResult;
	}
	extendedTimestamp = packet->m_nTimeStamp == 0xffffff;
	if(extendedTimestamp)
	{
		memcpy(header + nSize, &data[offset], 4);
		packet->m_nTimeStamp = AMF_DecodeInt32(header + nSize);
		header_size += 4;
		offset += 4;
	}

	if (packet->m_nBodySize > data.size() - nResult)
	{
		return nResult;
	}
	if (packet->m_nBodySize > 0 && packet->m_body == nullptr)
	{
		if (!RTMPPacket_Alloc(packet.get(), packet->m_nBodySize))
		{
			return nResult;
		}
		didAlloc = true;
		packet->m_headerType = (header_buffer[0] & 0xc0) >> 6;
	}

	if(didAlloc)
	{
		memcpy(packet->m_body, &data[offset], packet->m_nBodySize);
		AMFObject amf_object;
		AVal method;
		if(packet->m_body[0] == 0x02)
		{
			char* ptr = nullptr;
			ptr = packet->m_body + 1;
			AMF_DecodeString(ptr, &method);
			std::cout << "Method: " << method.av_val << std::endl;
			if(!_strcmpi("connect", method.av_val))
			{
				std::cout << "Method: " << method.av_val << std::endl;
				
			}
		}
		int ret = AMF_Decode(&amf_object, packet->m_body, packet->m_nBodySize, FALSE);
		if (ret < 0)
		{
			printf("[+] AMF_Decode failed\n");
			return nResult;
		}

		AMF_Dump(&amf_object);
		AMFProp_GetString(AMF_GetProp(&amf_object, NULL, 0), &method);
		int num = AMFProp_GetNumber(AMF_GetProp(&amf_object, NULL, 1));
		std::cout << "Method: " << method.av_val << std::endl;
		if (!_strcmpi(method.av_val, "connect"))
		{
			//send connect response
		}
		else if (!_strcmpi(method.av_val, "releaseStream"))
		{
			//send releaseStream response
		}
	}
	if(packet && packet->m_body)
	{
		RTMPPacket_Free(packet.get());
	}
	std::cout << "RTMP Packet: " << std::endl;
	return  nResult;
}

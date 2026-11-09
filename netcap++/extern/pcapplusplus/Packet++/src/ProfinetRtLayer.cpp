#define LOG_MODULE PacketLogModuleProfinetRtLayer

#include "ProfinetRtLayer.h"
#include "EndianPortable.h"
#include "ProfinetRtDcpLayer.h"
#include "ProfinetRtIoLayer.h"
#include "ProfinetRtPtcpLayer.h"
#include <sstream>
#include <string.h>

namespace pcpp
{

	ProfinetRtLayer::ProfinetRtLayer(uint16_t frameID)
	{

		const size_t headerLen = sizeof(profinetrthdr);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, m_DataLen);
		m_Protocol = PROFINET_RT;

		profinetrthdr *profinetRtHeader = getProfinetRtHeader();
		profinetRtHeader->frameID = frameID;
	}

	void ProfinetRtLayer::parseNextLayer()
	{
		uint8_t *payload = m_Data + sizeof(profinetrthdr);
		size_t payloadLen = m_DataLen - sizeof(profinetrthdr);

		if ((getFrameId() >= 0x0100 &&
			 getFrameId() <= 0x0FFF) || // RT_CLASS3 with ARProperties.TimeAwareSystem == NonTimeAware
			(getFrameId() >= 0x1000 &&
			 getFrameId() <= 0x4FFF) || // RT_CLASS3 with ARProperties.TimeAwareSystem == TimeAware
			(getFrameId() >= 0x8000 && getFrameId() <= 0xBFFF)) // RT_CLASS1
		{
			m_NextLayer = new ProfinetRtIoLayer(payload, payloadLen, this, m_Packet);
		}
		else if (getFrameId() >= 0xFEFD && getFrameId() <= 0xFEFF)
		{
			m_NextLayer = new ProfinetRtDcpLayer(payload, payloadLen, this, m_Packet);
		}
		else if (getFrameId() >= 0xFF40 && getFrameId() <= 0xFF43)
		{
			m_NextLayer = new ProfinetRtPtcpLayer(payload, payloadLen, this, m_Packet);
		}
	}

	bool ProfinetRtLayer::isIo() const { return !isDcp(); }

	bool ProfinetRtLayer::isDcp() const
	{
		if (getFrameId() >= 0xFEFD && getFrameId() <= 0xFEFF)
		{
			return true;
		}
		return false;
	}

	std::string ProfinetRtLayer::toString() const
	{
		if (isIo())
		{
			std::stringstream stream;
			stream << "Profinet RT Layer, IO packet, frameID: 0x";
			stream << std::hex << getFrameId();
			return stream.str();
		}
		else
		{
			return "Profinet RT Layer, DCP packet";
		}
	}

} // namespace pcpp

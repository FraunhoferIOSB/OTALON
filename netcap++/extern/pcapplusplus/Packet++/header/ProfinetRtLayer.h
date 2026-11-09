#pragma once

#include "Layer.h"
#include "SystemUtils.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// Represents the Profinet RT layer. Contains only the frame id to
	/// destinguish between IO and DCP traffic.
	class ProfinetRtLayer : public Layer
	{
	public:
		/// @struct profinetrthdr
		/// Represents an ARP protocol header
#pragma pack(push, 1)
		struct profinetrthdr
		{
			/// Hardware type (HTYPE)
			uint16_t frameID;
		};
#pragma pack(pop)

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		ProfinetRtLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
			: Layer(data, dataLen, prevLayer, packet) { m_Protocol = PROFINET_RT; m_DataLen = sizeof(profinetrthdr); }

		/// A constructor that allocates a new ARP header
		/// @param[in] frameID The frameID of the message
		ProfinetRtLayer(uint16_t frameID);

		/// Get a pointer to the ProfinetRt header. Notice this points directly to the data,
		/// so every change will change the actual packet data
		/// @return A pointer to the profinetrthdr
		inline profinetrthdr* getProfinetRtHeader() const { return (profinetrthdr*)m_Data; }

		/// Get the frameID
		/// @return A MacAddress containing the sender hardware address (SHA)
		inline uint16_t getFrameId() const { return netToHost16(getProfinetRtHeader()->frameID); }

		/// A static method that takes a byte array and detects whether it is a Profinet RT layer message
		/// @param[in] data A byte array
		/// @param[in] dataSize The byte array size (in bytes)
		/// @return True if the data is identified as Profinet RT layer message
		static bool isDataValid(const uint8_t* data, size_t dataSize) { return true; }

		// overridden methods

		/// Checks the frame id to determine the next layer
		void parseNextLayer();

		/// @return The size of profinetrthdr
		size_t getHeaderLen() const override { return sizeof(profinetrthdr); }

		/// Does nothing for this layer
		void computeCalculateFields() override
		{}

		/// Is this packet an profinet rt io packet?
		bool isIo() const;

		/// Is this packet an profinet rt dcp packet?
		bool isDcp() const;

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const { return OsiModelApplicationLayer; }
	};

} // namespace pcpp

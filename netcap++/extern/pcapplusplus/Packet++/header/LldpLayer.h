#pragma once

#include "Layer.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// Represents the LLDP layer.
	class LldpLayer : public Layer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		LldpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
			: Layer(data, dataLen, prevLayer, packet) { m_Protocol = LLDP; m_DataLen = 0; }

		/// A constructor that allocates a new profinet rt dcp header
		LldpLayer() {}

		/// A static method that takes a byte array and detects whether it is a LLDP message
		/// @param[in] data A byte array
		/// @param[in] dataSize The byte array size (in bytes)
		/// @return True if the data is identified as LLDP message
		static bool isDataValid(const uint8_t* data, size_t dataSize) {
			return true;
		}

		// overridden methods

		/// Parses the next layer. LLDP is the always last so does nothing for this layer
		void parseNextLayer() {};

		/// Does nothing for this layer
		size_t getHeaderLen() const {
			return 0;
		}

		/// Does nothing for this layer
		void computeCalculateFields() override
		{}
		
		/// @return The OSI layer level of Wake on LAN (Data Link Layer)
		OsiModelLayer getOsiModelLayer() const override {
			return OsiModelDataLinkLayer;
		}

		/// @return Returns the protocol info as readable string
		std::string toString() const;
	};

} // namespace pcpp

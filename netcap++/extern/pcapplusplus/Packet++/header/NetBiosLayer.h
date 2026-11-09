#pragma once

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * @class Profinet RT IO
	 * Represents the Profinet RT IO layer.
	 */
	class NetBiosLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		NetBiosLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
			: Layer(data, dataLen, prevLayer, packet) { m_Protocol = NetBIOS; m_DataLen = 0; }

		/**
		 * A constructor that allocates a new profinet rt dcp header
		 */
		NetBiosLayer() {}

		~NetBiosLayer() {}


		// implement abstract methods

		/**
		 * Does nothing for this layer (Profinet RT_IO is always last)
		 */
		void parseNextLayer() {};

		/**
		 * @return The size of @ref arphdr
		 */
		size_t getHeaderLen() const { return 0; }

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() override {}

        /**
         * Check if port is a NetBIOS port for the UDP protocol
         * 
         * @param[in] port Port to test
         * @return Whether the port is a NetBIOS port
         */
        static bool isNetBiosUdpPort( uint16_t port ) { return port == 137 || port == 138; }

        /**
         * Check if port is a NetBIOS port for the TCP protocol
         * 
         * @param[in] port Port to test
         * @return Whether the port is a NetBIOS port
         */
        static bool isNetBiosTcpPort( uint16_t port ) { return port == 137 || port == 139; }

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelSesionLayer; }
	};

} // namespace pcpp

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
	 * @struct opcua_header
	 * Represents the base opcua header
	 */
#pragma pack(push, 1)
	struct opcua_header
	{
		uint8_t message_type[3];
		uint8_t chunk_type;
		uint32_t message_size;
	};
#pragma pack(pop)
	/**
	 * @class OPC-UA
	 * Represents the OPC-UA layer.
	 */
	class OpcuaLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		OpcuaLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
			: Layer(data, dataLen, prevLayer, packet) { m_Protocol = OPC_UA; m_DataLen = sizeof(opcua_header); }

		/**
		 * A constructor that allocates a new profinet rt dcp header
		 */
		OpcuaLayer() {}

		~OpcuaLayer() {}


		// implement abstract methods

		/**
		 * Does nothing for this layer (OPC-UA is always last)
		 */
		void parseNextLayer() {};

		/**
		 * @return The size of @ref arphdr
		 */
		size_t getHeaderLen() const { return sizeof(opcua_header); }

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() override {}

        static bool isOpcuaPort(const uint16_t port) { return port == 4840; }

		static bool isDataValid(const uint8_t *data, size_t dataSize);

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelApplicationLayer; }
	};

} // namespace pcpp

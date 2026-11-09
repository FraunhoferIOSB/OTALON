#pragma once

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
#pragma pack(push, 1)
	struct pn_rpc_uuid {
		uint32_t data1;
		uint16_t data2;
		uint16_t data3;
		uint8_t data4[8];
	};

	struct profinetdcerpchdr
	{
		uint8_t rPCVersion;
		uint8_t rPCPacketType;
		uint8_t rPCFlags;
		uint8_t rPCFlags2;
		uint8_t rPCDRep[3];
		uint8_t rPCSerialHigh;
		struct pn_rpc_uuid rPCObjectUUID;
		struct pn_rpc_uuid rPCInterfaceUUID;
		struct pn_rpc_uuid rPCActivityUUID;
		uint32_t rPCServerBootTime;
		struct {
			uint16_t minor;
			uint16_t major;
		} rPCInterfaceVersion;
		uint32_t rPCSequenceNmb;
		uint16_t rPCOperationNmb;
		uint16_t rPCInterfaceHint;
		uint16_t rPCActivityHint;
		uint16_t rPCLengthOfBody;
		uint16_t rPCFragmentNmb;
		uint8_t rPCAuthenticationProtocol;
		uint8_t rPCSerialLow;
	};
#pragma pack(pop)
	/**
	 * @class Profinet RT DCP
	 * Represents the Profinet RT DCP layer.
	 */
	class ProfinetDceRpcLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		ProfinetDceRpcLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
			: Layer(data, dataLen, prevLayer, packet) { m_Protocol = PROFINET_DCE_RPC; m_DataLen = sizeof(profinetdcerpchdr); }

		/**
		 * A constructor that allocates a new profinet rt dcp header
		 */
		ProfinetDceRpcLayer() {};

		~ProfinetDceRpcLayer() {}


		// implement abstract methods

		/**
		 * Does nothing for this layer (Profinet RT is always last)
		 */
		void parseNextLayer() {};

		/**
		 * @return The size of @ref arphdr
		 */
		size_t getHeaderLen() const { return 0; }

		/**
		 * Check if a matching port is used.
		 */
		static bool isProfinetDceRpcPort(uint16_t port);

		/**
		 * Check if payload contains RPCInterfaceUUID for PNIO
		 */
		static bool isDataValid(uint8_t * data, size_t data_len);

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() override {}

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelApplicationLayer; }
	};

} // namespace pcpp

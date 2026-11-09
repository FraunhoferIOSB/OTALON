#pragma once

#include "ProtocolType.h"
#include "network-capture/datatypes/protocol.hpp"

Protocol
convert_protocol_type(const pcpp::ProtocolType& p_type);

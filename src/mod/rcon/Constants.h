#pragma once

namespace rcon_server::rcon {

constexpr int MIN_PACKET_SIZE = 10;
constexpr int MAX_PACKET_SIZE = 4096;

// See https://developer.valvesoftware.com/wiki/Source_RCON_Protocol#Requests_and_Responses
enum DataType {
    SERVERDATA_RESPONSE_VALUE = 0,
    SERVERDATA_EXECCOMMAND    = 2,
    SERVERDATA_AUTH_RESPONSE  = 2,
    SERVERDATA_AUTH           = 3
};

} // namespace rcon_server::rcon
#include "Server.h"
#include "Constants.h"
#include "utils/Utils.h"
#include <format>

#define CALL_HANDLER(handler, ...)                                                                                     \
    {                                                                                                                  \
        if ((handler)) {                                                                                               \
            (handler)(__VA_ARGS__);                                                                                    \
        }                                                                                                              \
    }

namespace rcon_server::rcon {

void Server::start() {
    startAccepting();
    std::thread([this]() -> void { ioContext.run(); }).detach();
}

void Server::stop() {
    acceptor.close();
    ioContext.stop();

    std::lock_guard<std::mutex> guard(clientsMutex);
    clients.clear();
}

void Server::startAccepting() {
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(ioContext);

    acceptor.async_accept(*socket, [this, socket](boost::system::error_code ec) -> void {
        if (!ec) {
            std::lock_guard<std::mutex> guard(clientsMutex);
            if (clients.size() <= maxConnections) {
                std::shared_ptr<ConnectedClient> client = std::make_shared<ConnectedClient>(socket, false);

                CALL_HANDLER(onNewConnection, client);

                clients[socket.get()] = client;
                readPacket(client);
            } else {
                socket->close();
            }
        }

        startAccepting();
    });
}

void Server::readPacket(std::shared_ptr<ConnectedClient> client) {
    auto buffer = std::make_shared<std::vector<char>>(sizeof(int));

    boost::asio::async_read(
        *client->socket,
        boost::asio::buffer(*buffer),
        [this, client, buffer](boost::system::error_code ec, size_t) -> void {
            CALL_HANDLER(onDebugInfo, client, "[Server::readPacket] New packet.");

            if (!ec) {
                int sizeOfPacket = utils::Utils::bit32ToInt(*buffer);
                CALL_HANDLER(onDebugInfo, client, std::format("[Server::readPacket] Size of packet: {}", sizeOfPacket));

                if (sizeOfPacket <= MIN_PACKET_SIZE || sizeOfPacket > MAX_PACKET_SIZE) {
                    CALL_HANDLER(onDebugInfo, client, "[Server::readPacket] Invalid packet");

                    readPacket(client);
                    return;
                }

                CALL_HANDLER(onDebugInfo, client, "[Server::readPacket] Correct packet. Read Packet body...");

                readPacketBody(client, sizeOfPacket);
                return;
            }

            CALL_HANDLER(onClientDisconnect, client);
            if (ec != boost::asio::error::eof) {
                CALL_HANDLER(onDebugInfo, client, std::format("[Server::readPacket] Error occurred: {}", ec.message()));
            }

            std::lock_guard<std::mutex> guard(clientsMutex);
            clients.erase(client->socket.get());
        }
    );
}

void Server::readPacketBody(std::shared_ptr<ConnectedClient> client, int packetSize) {
    auto buffer = std::make_shared<std::vector<char>>(packetSize);

    boost::asio::async_read(
        *client->socket,
        boost::asio::buffer(*buffer),
        [this, client, buffer, packetSize](boost::system::error_code ec, size_t) -> void {
            CALL_HANDLER(
                onDebugInfo,
                client,
                std::format("[Server::readPacket] Reading packet body. Size: {}", packetSize)
            );

            if (!ec) {
                if (onDebugInfo) {
                    std::ostringstream oss;
                    oss << std::hex << std::uppercase << std::setfill('0');

                    for (int i = 0; i < packetSize; ++i) {
                        oss << "\\x" << std::setw(2) << static_cast<int>((*buffer)[i]);
                    }

                    onDebugInfo(client, std::format("[Server::readPacket] Raw packet data: {}", oss.str()));
                }

                CALL_HANDLER(onDebugInfo, client, "[Server::readPacket] Correct packet. Processing...");

                processPacket(client, *buffer);
                return;
            }

            CALL_HANDLER(onClientDisconnect, client);
            if (ec != boost::asio::error::eof) {
                CALL_HANDLER(onDebugInfo, client, std::format("[Server::readPacket] Error occurred: {}", ec.message()));
            }

            std::lock_guard<std::mutex> guard(clientsMutex);
            clients.erase(client->socket.get());
        }
    );
}

void Server::writePacket(std::shared_ptr<ConnectedClient> client, const Packet& packet) {
    boost::asio::async_write(
        *client->socket,
        boost::asio::buffer(packet.data.data(), packet.length),
        [this, client](boost::system::error_code ec, [[maybe_unused]] size_t length) -> void {
            if (!ec) {
                readPacket(client);
            } else {
                CALL_HANDLER(onClientDisconnect, client);
                CALL_HANDLER(onDebugInfo, client, std::format("[Server::readPacket] Error occurred: {}", ec.message()));

                std::lock_guard<std::mutex> guard(clientsMutex);
                clients.erase(client->socket.get());
            }
        }
    );
}

void Server::processPacket(std::shared_ptr<ConnectedClient> client, const std::vector<char>& buffer) {
    std::string_view packetData(buffer.begin() + 8, buffer.end() - 2);

    int id   = utils::Utils::bit32ToInt(buffer);
    int type = utils::Utils::typeToInt(buffer);

    CALL_HANDLER(onDebugInfo, client, std::format("[Server::processPacket] Packet id: {}", id));
    CALL_HANDLER(onDebugInfo, client, std::format("[Server::processPacket] Packet type: {}", type));
    CALL_HANDLER(onDebugInfo, client, std::format("[Server::processPacket] Packet data: {}", packetData));

    Packet packet;

    if (!client->isAuthenticated) {
        if (packetData == password) {
            packet = utils::Utils::compilePacket(id, DataType::SERVERDATA_AUTH_RESPONSE, "");

            client->isAuthenticated = true;
            CALL_HANDLER(onClientAuth, client);
        } else {
            packet = utils::Utils::compilePacket(-1, DataType::SERVERDATA_AUTH_RESPONSE, "");
        }
    } else {
        if (type != DataType::SERVERDATA_EXECCOMMAND) {
            CALL_HANDLER(onDebugInfo, client, std::format("[Server::processPacket] Invalid packet type ({})", type));

            packet = utils::Utils::compilePacket(
                id,
                DataType::SERVERDATA_RESPONSE_VALUE,
                std::format("Invalid packet type ({}). Double check your packets.", type)
            );
        } else {
            std::string data = "";
            if (onCommand) {
                data = onCommand(client, packetData);
            }

            CALL_HANDLER(onDebugInfo, client, std::format("[Server::processPacket] Answer for client: {}", data));
            packet = utils::Utils::compilePacket(id, DataType::SERVERDATA_RESPONSE_VALUE, data);
        }
    }

    writePacket(client, packet);
}

} // namespace rcon_server::rcon

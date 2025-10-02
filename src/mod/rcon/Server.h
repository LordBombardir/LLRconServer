#pragma once

#include "ConnectedClient.h"
#include "Packet.h"
#include <boost/asio.hpp>

namespace rcon_server::rcon {

class Server final : public std::enable_shared_from_this<Server> {
public:
    explicit Server(
        unsigned short                                              port,
        unsigned short                                              maxConnections,
        const std::string&                                          password,
        std::function<void(const std::shared_ptr<ConnectedClient>)> onNewConnection                          = nullptr,
        std::function<void(const std::shared_ptr<ConnectedClient>)> onClientAuth                             = nullptr,
        std::function<void(const std::shared_ptr<ConnectedClient>)> onClientDisconnect                       = nullptr,
        std::function<std::string(const std::shared_ptr<rcon::ConnectedClient>, std::string_view)> onCommand = nullptr,
        std::function<void(const std::shared_ptr<rcon::ConnectedClient>, const std::string&)>      onDebugInfo = nullptr
    )
    : acceptor({ioContext, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)}),
      maxConnections(maxConnections),
      password(password),
      onNewConnection(onNewConnection),
      onClientAuth(onClientAuth),
      onClientDisconnect(onClientDisconnect),
      onCommand(onCommand),
      onDebugInfo(onDebugInfo) {}

    Server(const Server&)            = delete;
    Server& operator=(const Server&) = delete;
    Server(Server&&)                 = delete;
    Server& operator=(Server&&)      = delete;

    void start();
    void stop();

private:
    boost::asio::io_context        ioContext;
    boost::asio::ip::tcp::acceptor acceptor;

    unsigned short                                                                             maxConnections;
    std::string                                                                                password;
    std::function<void(const std::shared_ptr<ConnectedClient>)>                                onNewConnection;
    std::function<void(const std::shared_ptr<ConnectedClient>)>                                onClientAuth;
    std::function<void(const std::shared_ptr<ConnectedClient>)>                                onClientDisconnect;
    std::function<std::string(const std::shared_ptr<rcon::ConnectedClient>, std::string_view)> onCommand;
    std::function<void(const std::shared_ptr<rcon::ConnectedClient>, const std::string&)>      onDebugInfo;

    std::unordered_map<boost::asio::ip::tcp::socket*, std::shared_ptr<ConnectedClient>> clients;
    std::mutex                                                                          clientsMutex;

    void startAccepting();

    void readPacket(std::shared_ptr<ConnectedClient> client);
    void readPacketBody(std::shared_ptr<ConnectedClient> client, int packetSize);
    void writePacket(std::shared_ptr<ConnectedClient> client, const Packet& packet);

    void processPacket(std::shared_ptr<ConnectedClient> client, const std::vector<char>& buffer);
};

} // namespace rcon_server::rcon
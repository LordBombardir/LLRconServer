#include "MainManager.h"
#include "../Main.h"
#include "../rcon/Server.h"
#include "config/ConfigManager.h"
#include <ll/api/service/Bedrock.h>
#include <mc/deps/core/string/HashedString.h>
#include <mc/deps/core/utility/MCRESULT.h>
#include <mc/locale/I18n.h>
#include <mc/locale/Localization.h>
#include <mc/server/commands/Command.h>
#include <mc/server/commands/CommandContext.h>
#include <mc/server/commands/CommandOutput.h>
#include <mc/server/commands/CommandVersion.h>
#include <mc/server/commands/MinecraftCommands.h>
#include <mc/server/commands/ServerCommandOrigin.h>
#include <mc/world/Minecraft.h>
#include <stdexcept>

namespace rcon_server::manager {

std::shared_ptr<rcon::Server> MainManager::rconServer = nullptr;

bool MainManager::initManagers(ll::mod::NativeMod& mod) {
    try {
        return ConfigManager::init(mod);
    } catch (...) {
        return false;
    }
}

void MainManager::startRconServer() {
    if (rconServer != nullptr) {
        throw std::runtime_error("The RCON server is already started!");
    }

    rconServer = std::make_shared<rcon::Server>(
        ConfigManager::getConfig().rconSettings.port,
        ConfigManager::getConfig().rconSettings.maxConnections,
        ConfigManager::getConfig().rconSettings.password,
        ConfigManager::getConfig().rconSettings.logOnNewConnection ? &onNewConnection : nullptr,
        ConfigManager::getConfig().rconSettings.logOnClientAuth ? &onClientAuth : nullptr,
        ConfigManager::getConfig().rconSettings.logOnClientDisconnect ? &onClientDisconnect : nullptr,
        &onCommand,
        ConfigManager::getConfig().rconSettings.logOnDebugInfo ? &onDebugInfo : nullptr
    );

    rconServer->start();
}

void MainManager::stopRconServer() {
    if (rconServer == nullptr) {
        throw std::runtime_error("The RCON server is not running!");
    }

    rconServer->stop();
}

void MainManager::onNewConnection(const std::shared_ptr<rcon::ConnectedClient> client) {
    Main::getInstance().getSelf().getLogger().info(
        "New connection from {}:{}",
        client->socket->remote_endpoint().address().to_string(),
        client->socket->remote_endpoint().port()
    );
}

void MainManager::onClientAuth(const std::shared_ptr<rcon::ConnectedClient> client) {
    Main::getInstance().getSelf().getLogger().info(
        "Client {}:{} has successfully authorized",
        client->socket->remote_endpoint().address().to_string(),
        client->socket->remote_endpoint().port()
    );
}

void MainManager::onClientDisconnect(const std::shared_ptr<rcon::ConnectedClient> client) {
    Main::getInstance().getSelf().getLogger().info(
        "Client {}:{} disconnected",
        client->socket->remote_endpoint().address().to_string(),
        client->socket->remote_endpoint().port()
    );
}

std::string MainManager::onCommand(const std::shared_ptr<rcon::ConnectedClient> client, std::string_view command) {
    if (ConfigManager::getConfig().rconSettings.logOnCommand) {
        Main::getInstance().getSelf().getLogger().info(
            "Client {}:{} has sent a new command: {}",
            client->socket->remote_endpoint().address().to_string(),
            client->socket->remote_endpoint().port(),
            command
        );
    }

    std::string         outputStr;
    ServerCommandOrigin origin =
        ServerCommandOrigin("Server", ll::service::getLevel()->asServer(), CommandPermissionLevel::Owner, 0);

    Command* commandObject = ll::service::getMinecraft()->mCommands->compileCommand(
        HashedString(command),
        origin,
        static_cast<CurrentCmdVersion>(CommandVersion::CurrentVersion()),
        [&](const std::string& error) -> void { outputStr.append(error).append("\n"); }
    );

    if (commandObject) {
        CommandOutput output(CommandOutputType::AllOutput);
        commandObject->run(origin, output);

        static const std::shared_ptr<const Localization> localization =
            getI18n().getLocaleFor(getI18n().getCurrentLanguage()->mCode);
        for (CommandOutputMessage& msg : output.mMessages) {
            outputStr += getI18n().get(msg.mMessageId, msg.mParams, localization).append("\n");
        }
    }

    return outputStr;
}

void MainManager::onDebugInfo(const std::shared_ptr<rcon::ConnectedClient> client, const std::string& debugInfo) {
    Main::getInstance().getSelf().getLogger().info(
        "[Client {}:{}] {}",
        client->socket->remote_endpoint().address().to_string(),
        client->socket->remote_endpoint().port(),
        debugInfo
    );
}

} // namespace rcon_server::manager
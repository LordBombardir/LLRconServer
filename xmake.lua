add_rules("mode.debug", "mode.release")

add_repositories("liteldev-repo https://github.com/LiteLDev/xmake-repo.git")

-- add_requires("levilamina x.x.x") for a specific version
-- add_requires("levilamina develop") to use develop version
-- please note that you should add bdslibrary yourself if using dev version
add_requires("levilamina 1.3.0")
add_requires("levibuildscript")
add_requires("boost 1.87.0", {configs = {asio = true}})

if not has_config("vs_runtime") then
    set_runtimes("MD")
end

target("RconServer") -- Change this to your mod name.
    add_rules("@levibuildscript/linkrule")
    add_rules("@levibuildscript/modpacker")

    add_cxflags( "/EHa", "/utf-8", "/W4", "/w44265", "/w44289", "/w44296", "/w45263", "/w44738", "/w45204")
    add_defines("NOMINMAX", "UNICODE", "_HAS_CXX23=1")

    add_packages("levilamina")
    add_packages("boost")

    set_exceptions("none") -- To avoid conflicts with /EHa.
    set_kind("shared")
    set_languages("c++20")
    set_symbols("debug")

    add_headerfiles("src/**.h")
    add_files("src/**.cpp")
    add_includedirs("src")

cmake_minimum_required(VERSION 3.21)
project(NetworkToolsQt VERSION 1.0.7 LANGUAGES CXX)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Network Concurrent SerialPort)

set(APP_WIN_RC)
set(APP_MAC_ICNS)

if(WIN32)
    set(APP_WIN_RC resources/windows/app.rc)
endif()

if(APPLE)
    set(APP_MAC_ICNS resources/app.icns)
    set_source_files_properties(${APP_MAC_ICNS} PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")
endif()

add_executable(NetworkToolsQt
    src/main.cpp
    src/MainWindow.cpp
    src/MainWindow.h
    src/core/Types.h
    src/core/AppPaths.cpp
    src/core/AppPaths.h
    src/core/SettingsService.cpp
    src/core/SettingsService.h
    src/core/TerminalSanitizer.cpp
    src/core/TerminalSanitizer.h
    src/core/VendorDbService.cpp
    src/core/VendorDbService.h
    src/core/SnapshotService.cpp
    src/core/SnapshotService.h
    src/network/HttpRequestService.cpp
    src/network/HttpRequestService.h
    src/network/TelnetSession.cpp
    src/network/TelnetSession.h
    src/network/SshProcessSession.cpp
    src/network/SshProcessSession.h
    src/network/TcpClientSession.cpp
    src/network/TcpClientSession.h
    src/network/UdpSocketSession.cpp
    src/network/UdpSocketSession.h
    src/network/SerialSession.cpp
    src/network/SerialSession.h
    src/network/NetworkScanService.cpp
    src/network/NetworkScanService.h
    src/widgets/CodeEditor.cpp
    src/widgets/CodeEditor.h
    ${APP_WIN_RC}
    ${APP_MAC_ICNS}
)

target_include_directories(NetworkToolsQt PRIVATE src)

target_link_libraries(NetworkToolsQt PRIVATE
    Qt6::Widgets
    Qt6::Network
    Qt6::Concurrent
    Qt6::SerialPort
)

if(APPLE)
    set_target_properties(NetworkToolsQt PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_GUI_IDENTIFIER "local.networktools.qt"
        MACOSX_BUNDLE_BUNDLE_NAME "Network Tools"
        MACOSX_BUNDLE_ICON_FILE "app.icns"
        MACOSX_BUNDLE_BUNDLE_VERSION "1.0.7"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0.7"
    )
endif()

if(WIN32)
    set_target_properties(NetworkToolsQt PROPERTIES
        WIN32_EXECUTABLE TRUE
    )
endif()

if(APPLE)
    install(TARGETS NetworkToolsQt BUNDLE DESTINATION .)
else()
    install(TARGETS NetworkToolsQt RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(UNIX AND NOT APPLE)
    install(FILES resources/app.png
        DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/1024x1024/apps
        RENAME NetworkToolsQt.png
    )
endif()

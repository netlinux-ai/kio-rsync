cmake_minimum_required(VERSION 3.16)
project(kio_rsync)

find_package(ECM REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})

include(KDEInstallDirs)
include(ECMQtDeclareLoggingCategory)

set(CMAKE_AUTOMOC ON)

find_package(Qt5 REQUIRED COMPONENTS Core Network)
find_package(KF5 REQUIRED COMPONENTS KIO I18n)

add_definitions(-DTRANSLATION_DOMAIN=\"kio5_rsync\")

add_library(kio_rsync MODULE)
set_target_properties(kio_rsync PROPERTIES
    OUTPUT_NAME "rsync"
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/kf5/kio"
)

target_sources(kio_rsync PRIVATE kio_rsync.cpp rsync_protocol.cpp)

target_include_directories(kio_rsync PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

ecm_qt_declare_logging_category(kio_rsync
    HEADER kio_rsync_debug.h
    IDENTIFIER KIO_RSYNC_LOG
    CATEGORY_NAME kf.kio.slaves.rsync
    DESCRIPTION "KIO rsync"
)

target_link_libraries(kio_rsync
    PRIVATE
        KF5::KIOCore
        KF5::I18n
        Qt5::Core
        Qt5::Network
)

install(TARGETS kio_rsync DESTINATION ${KDE_INSTALL_PLUGINDIR}/kf5/kio)

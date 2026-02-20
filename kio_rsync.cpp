/*
 * SPDX-FileCopyrightText: 2026 Graham Morrison
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "kio_rsync.h"
#include "kio_rsync_debug.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QFileInfo>
#include <QMimeDatabase>
#include <QMimeType>
#include <QUrl>

#include <KIO/AuthInfo>
#include <KIO/Global>
#include <KLocalizedString>

#include <sys/stat.h>

using namespace KIO;

// ---------------------------------------------------------------------------
// Construction / host setup
// ---------------------------------------------------------------------------

RsyncSlave::RsyncSlave(const QByteArray &poolSocket, const QByteArray &appSocket)
    : SlaveBase("rsync", poolSocket, appSocket)
{
    qCDebug(KIO_RSYNC_LOG) << "RsyncSlave created";
}

RsyncSlave::~RsyncSlave()
{
    qCDebug(KIO_RSYNC_LOG) << "RsyncSlave destroyed";
}

void RsyncSlave::setHost(const QString &host, quint16 port,
                          const QString &user, const QString &pass)
{
    m_host = host;
    m_port = (port > 0) ? port : RSYNC_DEFAULT_PORT;
    m_user = user;
    m_password = pass;
    qCDebug(KIO_RSYNC_LOG) << "setHost:" << host << "port:" << m_port
                            << "user:" << user;
}

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

void RsyncSlave::parseUrl(const QUrl &url, QString &module, QString &path)
{
    // URL: rsync://host/module/sub/path
    // path() returns "/module/sub/path"
    QString p = url.path();
    if (p.startsWith(QLatin1Char('/'))) {
        p = p.mid(1);
    }

    int slash = p.indexOf(QLatin1Char('/'));
    if (slash < 0) {
        module = p;
        path.clear();
    } else {
        module = p.left(slash);
        path = p.mid(slash + 1);
    }

    // Remove trailing slashes from path
    while (path.endsWith(QLatin1Char('/'))) {
        path.chop(1);
    }
}

// ---------------------------------------------------------------------------
// Connect, select module, authenticate, request listing
// ---------------------------------------------------------------------------

bool RsyncSlave::connectAndList(const QString &module, const QString &path,
                                 QList<RsyncFileEntry> &entries,
                                 bool appendSlash)
{
    RsyncProtocol proto;

    if (!proto.connectToHost(m_host, m_port)) {
        error(ERR_CANNOT_CONNECT, proto.lastError());
        return false;
    }

    if (!proto.handshake()) {
        error(ERR_CANNOT_CONNECT, proto.lastError());
        return false;
    }

    if (!proto.selectModule(module)) {
        error(ERR_CANNOT_ENTER_DIRECTORY, proto.lastError());
        return false;
    }

    // Handle authentication if required
    if (proto.authRequired()) {
        QString user = m_user;
        QString password = m_password;

        // Try cached credentials first, then prompt
        if (user.isEmpty() || password.isEmpty()) {
            AuthInfo info;
            info.url = QUrl(QStringLiteral("rsync://%1/%2").arg(m_host, module));
            info.username = user;
            info.prompt = i18n("Please enter credentials for rsync module \"%1\" on %2",
                               module, m_host);

            if (checkCachedAuthentication(info)) {
                user = info.username;
                password = info.password;
            } else {
                int res = openPasswordDialogV2(info);
                if (res != 0) {
                    error(res, QString());
                    return false;
                }
                user = info.username;
                password = info.password;
                cacheAuthentication(info);
            }
        }

        if (!proto.authenticate(user, password, proto.authChallenge())) {
            error(ERR_CANNOT_AUTHENTICATE, proto.lastError());
            return false;
        }
    }

    // Add trailing slash for directory listing (not for stat on files)
    QString requestPath = path;
    if (appendSlash && !requestPath.isEmpty() && !requestPath.endsWith(QLatin1Char('/'))) {
        requestPath += QLatin1Char('/');
    }

    if (!proto.sendServerArgs(requestPath, true)) {
        error(ERR_INTERNAL, proto.lastError());
        return false;
    }

    entries = proto.receiveFileList();
    if (!proto.lastError().isEmpty()) {
        error(ERR_INTERNAL, proto.lastError());
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// UDSEntry conversion
// ---------------------------------------------------------------------------

void RsyncSlave::toUDSEntry(const RsyncFileEntry &rentry, UDSEntry &uentry)
{
    uentry.reserve(10);

    // Name: use just the filename part
    QString displayName = rentry.name;
    int lastSlash = displayName.lastIndexOf(QLatin1Char('/'));
    if (lastSlash >= 0) {
        displayName = displayName.mid(lastSlash + 1);
    }
    uentry.fastInsert(UDSEntry::UDS_NAME, displayName);

    // File type and access
    uentry.fastInsert(UDSEntry::UDS_FILE_TYPE, rentry.mode & S_IFMT);
    uentry.fastInsert(UDSEntry::UDS_ACCESS, rentry.mode & 07777);

    // Size
    uentry.fastInsert(UDSEntry::UDS_SIZE, rentry.size);

    // Modification time
    uentry.fastInsert(UDSEntry::UDS_MODIFICATION_TIME, rentry.mtime);

    // Owner / group
    if (!rentry.username.isEmpty()) {
        uentry.fastInsert(UDSEntry::UDS_USER, rentry.username);
    }
    if (!rentry.groupname.isEmpty()) {
        uentry.fastInsert(UDSEntry::UDS_GROUP, rentry.groupname);
    }

    // Symlink target
    if (!rentry.symlinkTarget.isEmpty()) {
        uentry.fastInsert(UDSEntry::UDS_LINK_DEST, rentry.symlinkTarget);
    }

    // MIME type hint for directories
    if (rentry.isDirectory) {
        uentry.fastInsert(UDSEntry::UDS_MIME_TYPE, QStringLiteral("inode/directory"));
    }
}

// ---------------------------------------------------------------------------
// listDir
// ---------------------------------------------------------------------------

void RsyncSlave::listDir(const QUrl &url)
{
    qCDebug(KIO_RSYNC_LOG) << "listDir:" << url;

    QString module, path;
    parseUrl(url, module, path);

    // If no module specified, list available modules as directories
    if (module.isEmpty()) {
        RsyncProtocol proto;
        if (!proto.connectToHost(m_host, m_port)) {
            error(ERR_CANNOT_CONNECT, proto.lastError());
            return;
        }
        if (!proto.handshake()) {
            error(ERR_CANNOT_CONNECT, proto.lastError());
            return;
        }

        auto modules = proto.listModules();
        for (const auto &[name, comment] : modules) {
            UDSEntry entry;
            entry.reserve(5);
            entry.fastInsert(UDSEntry::UDS_NAME, name);
            entry.fastInsert(UDSEntry::UDS_FILE_TYPE, S_IFDIR);
            entry.fastInsert(UDSEntry::UDS_ACCESS, 0755);
            entry.fastInsert(UDSEntry::UDS_MIME_TYPE, QStringLiteral("inode/directory"));
            if (!comment.isEmpty()) {
                entry.fastInsert(UDSEntry::UDS_COMMENT, comment);
            }
            listEntry(entry);
        }
        finished();
        return;
    }

    // List directory within a module
    QList<RsyncFileEntry> entries;
    if (!connectAndList(module, path, entries)) {
        return; // error() already called
    }

    for (const auto &rentry : entries) {
        // Skip the "." entry (represents the listed directory itself)
        if (rentry.name == QLatin1String(".") || rentry.name.isEmpty()) {
            continue;
        }
        UDSEntry uentry;
        toUDSEntry(rentry, uentry);
        listEntry(uentry);
    }
    finished();
}

// ---------------------------------------------------------------------------
// stat
// ---------------------------------------------------------------------------

void RsyncSlave::stat(const QUrl &url)
{
    qCDebug(KIO_RSYNC_LOG) << "stat:" << url;

    QString module, path;
    parseUrl(url, module, path);

    if (module.isEmpty()) {
        // Root: virtual directory containing modules
        UDSEntry entry;
        entry.reserve(4);
        entry.fastInsert(UDSEntry::UDS_NAME, QStringLiteral("."));
        entry.fastInsert(UDSEntry::UDS_FILE_TYPE, S_IFDIR);
        entry.fastInsert(UDSEntry::UDS_ACCESS, 0755);
        entry.fastInsert(UDSEntry::UDS_MIME_TYPE, QStringLiteral("inode/directory"));
        statEntry(entry);
        finished();
        return;
    }

    // Stat a path within a module (no trailing slash for stat)
    QList<RsyncFileEntry> entries;
    if (!connectAndList(module, path, entries, false)) {
        return; // error() already called
    }

    if (!entries.isEmpty()) {
        const RsyncFileEntry &rentry = entries.first();
        UDSEntry uentry;
        toUDSEntry(rentry, uentry);

        // Set the display name
        QString name = QFileInfo(path).fileName();
        if (name.isEmpty()) {
            name = module;
        }
        uentry.replace(UDSEntry::UDS_NAME, name);
        statEntry(uentry);
        finished();
        return;
    }

    error(ERR_DOES_NOT_EXIST, url.toDisplayString());
}

// ---------------------------------------------------------------------------
// get (file download)
// ---------------------------------------------------------------------------

void RsyncSlave::get(const QUrl &url)
{
    qCDebug(KIO_RSYNC_LOG) << "get:" << url;

    QString module, path;
    parseUrl(url, module, path);

    if (module.isEmpty() || path.isEmpty()) {
        error(ERR_IS_DIRECTORY, url.toDisplayString());
        return;
    }

    RsyncProtocol proto;
    if (!proto.connectToHost(m_host, m_port)) {
        error(ERR_CANNOT_CONNECT, proto.lastError());
        return;
    }
    if (!proto.handshake()) {
        error(ERR_CANNOT_CONNECT, proto.lastError());
        return;
    }
    if (!proto.selectModule(module)) {
        error(ERR_CANNOT_ENTER_DIRECTORY, proto.lastError());
        return;
    }

    // Handle auth
    if (proto.authRequired()) {
        QString user = m_user;
        QString password = m_password;

        if (user.isEmpty() || password.isEmpty()) {
            AuthInfo info;
            info.url = QUrl(QStringLiteral("rsync://%1/%2").arg(m_host, module));
            info.username = user;

            if (checkCachedAuthentication(info)) {
                user = info.username;
                password = info.password;
            } else {
                int res = openPasswordDialogV2(info);
                if (res != 0) {
                    error(res, QString());
                    return;
                }
                user = info.username;
                password = info.password;
                cacheAuthentication(info);
            }
        }

        if (!proto.authenticate(user, password, proto.authChallenge())) {
            error(ERR_CANNOT_AUTHENTICATE, proto.lastError());
            return;
        }
    }

    // Request the file (not list-only)
    if (!proto.sendServerArgs(path, false)) {
        error(ERR_INTERNAL, proto.lastError());
        return;
    }

    // Receive file list (should contain just our file)
    auto entries = proto.receiveFileList();
    if (entries.isEmpty()) {
        error(ERR_DOES_NOT_EXIST, url.toDisplayString());
        return;
    }

    const RsyncFileEntry &fileEntry = entries.first();
    totalSize(fileEntry.size);

    // Set MIME type
    QMimeDatabase db;
    QMimeType mime = db.mimeTypeForFile(fileEntry.name, QMimeDatabase::MatchExtension);
    if (mime.isValid()) {
        mimeType(mime.name());
    }

    // Send generator request for the file (NDX=0 + empty checksums)
    proto.sendFileRequest(0);

    // Receive file data from sender
    QByteArray fileData = proto.receiveFileData(fileEntry.size);
    if (!proto.lastError().isEmpty()) {
        error(ERR_CANNOT_READ, proto.lastError());
        return;
    }

    data(fileData);
    data(QByteArray()); // signal EOF

    processedSize(fileData.size());
    finished();
}

// ---------------------------------------------------------------------------
// Plugin metadata and entry point
// ---------------------------------------------------------------------------

class KIOPluginForMetaData : public QObject
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.kde.kio.slave.rsync" FILE "rsync.json")
};

extern "C" {
int Q_DECL_EXPORT kdemain(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("kio_rsync"));

    qCDebug(KIO_RSYNC_LOG) << "*** Starting kio_rsync";

    if (argc != 4) {
        qCWarning(KIO_RSYNC_LOG) << "Usage: kio_rsync protocol domain-socket1 domain-socket2";
        exit(-1);
    }

    RsyncSlave slave(argv[2], argv[3]);
    slave.dispatchLoop();

    qCDebug(KIO_RSYNC_LOG) << "*** kio_rsync Done";
    return 0;
}
}

#include "kio_rsync.moc"

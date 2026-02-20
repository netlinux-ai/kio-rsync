/*
 * SPDX-FileCopyrightText: 2026 Graham Morrison
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifndef KIO_RSYNC_H
#define KIO_RSYNC_H

#include <kio/slavebase.h>

#include "rsync_protocol.h"

class RsyncSlave : public KIO::SlaveBase
{
public:
    RsyncSlave(const QByteArray &poolSocket, const QByteArray &appSocket);
    ~RsyncSlave() override;

    void setHost(const QString &host, quint16 port,
                 const QString &user, const QString &pass) override;

    void listDir(const QUrl &url) override;
    void stat(const QUrl &url) override;
    void get(const QUrl &url) override;

private:
    QString m_host;
    quint16 m_port = RSYNC_DEFAULT_PORT;
    QString m_user;
    QString m_password;

    // Extract module and relative path from an rsync:// URL
    // rsync://host/module/sub/path → module="module", path="sub/path"
    void parseUrl(const QUrl &url, QString &module, QString &path);

    // Connect, select module, authenticate, request listing.
    // Returns true on success, false on failure (error() already called).
    bool connectAndList(const QString &module, const QString &path,
                        QList<RsyncFileEntry> &entries,
                        bool appendSlash = true);

    // Convert RsyncFileEntry to KIO::UDSEntry
    void toUDSEntry(const RsyncFileEntry &rentry, KIO::UDSEntry &uentry);
};

#endif // KIO_RSYNC_H

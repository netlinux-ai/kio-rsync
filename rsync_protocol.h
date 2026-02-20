/*
 * SPDX-FileCopyrightText: 2026 Graham Morrison
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifndef RSYNC_PROTOCOL_H
#define RSYNC_PROTOCOL_H

#include <QByteArray>
#include <QCryptographicHash>
#include <QList>
#include <QPair>
#include <QString>
#include <QTcpSocket>

// Protocol version
constexpr int RSYNC_DEFAULT_PORT = 873;
constexpr int RSYNC_PROTOCOL_VERSION = 31;
constexpr int RSYNC_SUBPROTOCOL_VERSION = 0;
constexpr int MPLEX_BASE = 7;

// Multiplex message codes (added to MPLEX_BASE in the tag byte)
constexpr int MSG_DATA = 0;
constexpr int MSG_ERROR_XFER = 1;
constexpr int MSG_INFO = 2;
constexpr int MSG_ERROR = 4;

// XMIT flags for incremental file list entries
constexpr quint16 XMIT_TOP_DIR            = (1 << 0);
constexpr quint16 XMIT_SAME_MODE          = (1 << 1);
constexpr quint16 XMIT_EXTENDED_FLAGS     = (1 << 2);
constexpr quint16 XMIT_SAME_UID           = (1 << 3);
constexpr quint16 XMIT_SAME_GID           = (1 << 4);
constexpr quint16 XMIT_SAME_NAME          = (1 << 5);
constexpr quint16 XMIT_LONG_NAME          = (1 << 6);
constexpr quint16 XMIT_SAME_TIME          = (1 << 7);
constexpr quint16 XMIT_NO_CONTENT_DIR     = (1 << 8);
constexpr quint16 XMIT_HLINKED            = (1 << 9);
constexpr quint16 XMIT_USER_NAME_FOLLOWS  = (1 << 10);
constexpr quint16 XMIT_GROUP_NAME_FOLLOWS = (1 << 11);
constexpr quint16 XMIT_MOD_NSEC           = (1 << 13);

// Wire mode constants (rsync portable encoding)
constexpr quint32 WIRE_IFDIR  = 0004000;
constexpr quint32 WIRE_IFLNK  = 0012000;
constexpr quint32 WIRE_IFREG  = 0100000;
constexpr quint32 WIRE_IFBLK  = 0060000;
constexpr quint32 WIRE_IFCHR  = 0020000;
constexpr quint32 WIRE_IFSOCK = 0140000;
constexpr quint32 WIRE_IFIFO  = 0010000;

struct RsyncFileEntry {
    QString name;
    qint64 size = 0;
    quint32 mode = 0;       // Unix mode (type + permissions)
    qint64 mtime = 0;       // Seconds since epoch
    quint32 uid = 0;
    quint32 gid = 0;
    QString username;
    QString groupname;
    QString symlinkTarget;
    bool isDirectory = false;
};

class RsyncProtocol
{
public:
    RsyncProtocol();
    ~RsyncProtocol();

    // Connection management
    bool connectToHost(const QString &host, quint16 port = RSYNC_DEFAULT_PORT);
    void disconnect();

    // Text protocol phase
    bool handshake();
    QList<QPair<QString, QString>> listModules(); // name, comment pairs
    bool selectModule(const QString &module);
    bool authenticate(const QString &user, const QString &password,
                      const QString &challenge);

    // Binary protocol phase
    bool sendServerArgs(const QString &path, bool listOnly);
    QList<RsyncFileEntry> receiveFileList();

    // File transfer
    void sendFileRequest(int fileIndex);
    QByteArray receiveFileData(qint64 expectedSize);

    QString lastError() const { return m_lastError; }

    // Whether the server requested authentication
    bool authRequired() const { return m_authRequired; }
    QString authChallenge() const { return m_authChallenge; }

private:
    QTcpSocket m_socket;
    QString m_lastError;
    int m_remoteProtocol = 0;
    QStringList m_serverDigests;
    bool m_authRequired = false;
    QString m_authChallenge;

    // Buffered data from multiplex reads
    QByteArray m_dataBuffer;
    int m_dataBufferPos = 0;

    // Text I/O (used during handshake/module selection phase)
    bool writeLine(const QString &line);
    QString readLine(int timeoutMs = 10000);

    // Null-terminated arg writing (binary args phase)
    void writeArg(const QByteArray &arg);
    void writeRawBytes(const char *data, int len);
    void writeInt32(quint32 val);
    void writeByte(quint8 val);

    // Raw socket I/O
    bool waitForData(int timeoutMs = 10000);
    void readExact(char *buf, int len);

    // Multiplex I/O (binary phase)
    QByteArray readMultiplexed(int &msgCode, int timeoutMs = 10000);
    void readMplexData(char *buf, int len);
    void writeMplexData(const char *data, int len);
    void writeMplexInt32(quint32 val);
    void writeMplexByte(quint8 val);

    // Varint codec
    quint8 readByte();
    quint32 readInt32();
    QByteArray readBytes(int len);
    quint32 readVarint();
    qint64 readVarlong(int minBytes);

    // Auth helpers
    QByteArray computeAuthResponse(const QString &password,
                                   const QString &challenge,
                                   const QString &digest);

    // Wire mode conversion
    quint32 fromWireMode(quint32 wireMode);
};

#endif // RSYNC_PROTOCOL_H

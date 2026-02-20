/*
 * SPDX-FileCopyrightText: 2026 Graham Morrison
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "rsync_protocol.h"
#include "kio_rsync_debug.h"

#include <sys/stat.h>

#include <QDataStream>

RsyncProtocol::RsyncProtocol()
{
}

RsyncProtocol::~RsyncProtocol()
{
    disconnect();
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

bool RsyncProtocol::connectToHost(const QString &host, quint16 port)
{
    m_socket.connectToHost(host, port);
    if (!m_socket.waitForConnected(10000)) {
        m_lastError = QStringLiteral("Connection to %1:%2 failed: %3")
                          .arg(host)
                          .arg(port)
                          .arg(m_socket.errorString());
        return false;
    }
    return true;
}

void RsyncProtocol::disconnect()
{
    if (m_socket.state() != QAbstractSocket::UnconnectedState) {
        m_socket.disconnectFromHost();
        if (m_socket.state() != QAbstractSocket::UnconnectedState) {
            m_socket.waitForDisconnected(3000);
        }
    }
    m_dataBuffer.clear();
    m_dataBufferPos = 0;
}

// ---------------------------------------------------------------------------
// Text I/O (handshake phase — line-oriented, no multiplexing)
// ---------------------------------------------------------------------------

bool RsyncProtocol::writeLine(const QString &line)
{
    QByteArray data = line.toUtf8() + '\n';
    qCDebug(KIO_RSYNC_LOG) << ">> " << line;
    qint64 written = m_socket.write(data);
    m_socket.flush();
    return written == data.size();
}

QString RsyncProtocol::readLine(int timeoutMs)
{
    QByteArray line;
    while (true) {
        if (m_socket.canReadLine()) {
            line = m_socket.readLine().trimmed();
            qCDebug(KIO_RSYNC_LOG) << "<< " << QString::fromUtf8(line);
            return QString::fromUtf8(line);
        }
        if (!m_socket.waitForReadyRead(timeoutMs)) {
            m_lastError = QStringLiteral("Timeout reading line from server");
            return QString();
        }
    }
}

// ---------------------------------------------------------------------------
// Raw socket helpers
// ---------------------------------------------------------------------------

bool RsyncProtocol::waitForData(int timeoutMs)
{
    if (m_socket.bytesAvailable() > 0) {
        return true;
    }
    return m_socket.waitForReadyRead(timeoutMs);
}

void RsyncProtocol::readExact(char *buf, int len)
{
    int bytesRead = 0;
    while (bytesRead < len) {
        if (m_socket.bytesAvailable() == 0) {
            if (!m_socket.waitForReadyRead(10000)) {
                m_lastError = QStringLiteral("Timeout in readExact");
                return;
            }
        }
        qint64 n = m_socket.read(buf + bytesRead, len - bytesRead);
        if (n <= 0) {
            m_lastError = QStringLiteral("Read error in readExact");
            return;
        }
        bytesRead += n;
    }
}

// ---------------------------------------------------------------------------
// Multiplex I/O (binary phase)
//
// After the text handshake, all server output is wrapped in 4-byte framed
// packets: [tag][len_lo][len_mid][len_hi]
// The tag encodes (msgCode + MPLEX_BASE). Code 0 = data, 2 = info, 4 = error.
// ---------------------------------------------------------------------------

QByteArray RsyncProtocol::readMultiplexed(int &msgCode, int timeoutMs)
{
    char hdr[4];
    readExact(hdr, 4);
    if (!m_lastError.isEmpty()) {
        return {};
    }

    quint32 tag = static_cast<quint8>(hdr[3]);
    quint32 len = static_cast<quint8>(hdr[0])
                | (static_cast<quint8>(hdr[1]) << 8)
                | (static_cast<quint8>(hdr[2]) << 16);

    msgCode = static_cast<int>(tag) - MPLEX_BASE;

    QByteArray payload(len, Qt::Uninitialized);
    readExact(payload.data(), len);
    return payload;
}

void RsyncProtocol::readMplexData(char *buf, int len)
{
    // First consume any leftover buffered data
    int filled = 0;
    while (filled < len) {
        if (m_dataBufferPos < m_dataBuffer.size()) {
            int avail = m_dataBuffer.size() - m_dataBufferPos;
            int toCopy = qMin(avail, len - filled);
            memcpy(buf + filled, m_dataBuffer.constData() + m_dataBufferPos, toCopy);
            m_dataBufferPos += toCopy;
            filled += toCopy;
            continue;
        }

        // Need more data from the multiplex stream
        int msgCode = -1;
        QByteArray chunk = readMultiplexed(msgCode);
        if (!m_lastError.isEmpty()) {
            return;
        }

        if (msgCode == MSG_DATA) {
            m_dataBuffer = chunk;
            m_dataBufferPos = 0;
        } else if (msgCode == MSG_INFO) {
            qCDebug(KIO_RSYNC_LOG) << "Server info:" << QString::fromUtf8(chunk);
        } else if (msgCode == MSG_ERROR || msgCode == MSG_ERROR_XFER) {
            qCWarning(KIO_RSYNC_LOG) << "Server error:" << QString::fromUtf8(chunk);
            m_lastError = QString::fromUtf8(chunk);
        } else {
            qCDebug(KIO_RSYNC_LOG) << "Unknown mplex code:" << msgCode;
        }
    }
}

// ---------------------------------------------------------------------------
// Primitive readers (binary phase — read through multiplex layer)
// ---------------------------------------------------------------------------

quint8 RsyncProtocol::readByte()
{
    quint8 b;
    readMplexData(reinterpret_cast<char *>(&b), 1);
    return b;
}

quint32 RsyncProtocol::readInt32()
{
    quint8 buf[4];
    readMplexData(reinterpret_cast<char *>(buf), 4);
    return static_cast<quint32>(buf[0])
         | (static_cast<quint32>(buf[1]) << 8)
         | (static_cast<quint32>(buf[2]) << 16)
         | (static_cast<quint32>(buf[3]) << 24);
}

QByteArray RsyncProtocol::readBytes(int len)
{
    QByteArray data(len, Qt::Uninitialized);
    readMplexData(data.data(), len);
    return data;
}

// ---------------------------------------------------------------------------
// Varint / Varlong codec
//
// rsync uses a prefix-byte variable-length encoding (similar to UTF-8):
//   First byte:  0xxxxxxx → 0 extra bytes, value in lower 7 bits
//                10xxxxxx → 1 extra byte,  value bits in lower 6 bits
//                110xxxxx → 2 extra bytes, value bits in lower 5 bits
//                1110xxxx → 3 extra bytes, value bits in lower 4 bits
//                11110xxx → 4 extra bytes, value bits in lower 3 bits
//                ...
//
// For read_varlong(minBytes):
//   Read minBytes. The FIRST byte is the prefix header. Bytes 1..minBytes-1
//   go into the LOW positions of the result (LE). The prefix byte's value
//   bits go into the HIGHEST position. Extra bytes extend beyond minBytes.
//
// read_varint() is equivalent to read_varlong(1).
// ---------------------------------------------------------------------------

static int countLeadingOnes(quint8 byte)
{
    int count = 0;
    for (int bit = 7; bit >= 0; --bit) {
        if (byte & (1 << bit))
            count++;
        else
            break;
    }
    return count;
}

qint64 RsyncProtocol::readVarlong(int minBytes)
{
    // Read minBytes from the wire
    QByteArray b2 = readBytes(minBytes);
    if (m_lastError.isEmpty() == false) {
        return 0;
    }

    // Result buffer (8 bytes, zero-initialized)
    quint8 u[8] = {};

    // Copy bytes 1..minBytes-1 into u[0..minBytes-2] (lower LE bytes)
    for (int i = 1; i < minBytes; ++i) {
        u[i - 1] = static_cast<quint8>(b2[i]);
    }

    // Determine extra byte count from the first byte's leading 1-bits
    quint8 firstByte = static_cast<quint8>(b2[0]);
    int extra = countLeadingOnes(firstByte);

    if (extra > 0) {
        quint8 bit = static_cast<quint8>(1 << (8 - extra));

        // Read extra bytes into u[minBytes-1 .. minBytes+extra-2]
        QByteArray extraBytes = readBytes(extra);
        for (int i = 0; i < extra; ++i) {
            u[minBytes - 1 + i] = static_cast<quint8>(extraBytes[i]);
        }

        // First byte's value bits go into the highest position
        u[minBytes + extra - 1] = firstByte & static_cast<quint8>(bit - 1);
    } else {
        // No extra bytes: first byte goes into position minBytes-1
        u[minBytes - 1] = firstByte;
    }

    // Interpret u[0..7] as little-endian int64
    qint64 val = 0;
    for (int i = 0; i < 8; ++i) {
        val |= static_cast<qint64>(u[i]) << (i * 8);
    }
    return val;
}

quint32 RsyncProtocol::readVarint()
{
    return static_cast<quint32>(readVarlong(1));
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

bool RsyncProtocol::handshake()
{
    // Server sends: "@RSYNCD: 32.0 md5 md4\n" (or similar)
    QString greeting = readLine();
    if (!greeting.startsWith(QLatin1String("@RSYNCD: "))) {
        m_lastError = QStringLiteral("Invalid server greeting: %1").arg(greeting);
        return false;
    }

    QStringList parts = greeting.mid(9).split(QLatin1Char(' '));
    if (parts.isEmpty()) {
        m_lastError = QStringLiteral("No version in server greeting");
        return false;
    }

    QStringList verParts = parts[0].split(QLatin1Char('.'));
    m_remoteProtocol = verParts[0].toInt();
    m_serverDigests = parts.mid(1);

    qCDebug(KIO_RSYNC_LOG) << "Server protocol:" << m_remoteProtocol
                            << "digests:" << m_serverDigests;

    // Send our greeting — always offer md5
    writeLine(QStringLiteral("@RSYNCD: %1.%2 md5")
                  .arg(RSYNC_PROTOCOL_VERSION)
                  .arg(RSYNC_SUBPROTOCOL_VERSION));
    return true;
}

// ---------------------------------------------------------------------------
// Module listing
// ---------------------------------------------------------------------------

QList<QPair<QString, QString>> RsyncProtocol::listModules()
{
    writeLine(QStringLiteral("#list"));

    QList<QPair<QString, QString>> modules;
    while (true) {
        QString line = readLine();
        if (line.startsWith(QLatin1String("@RSYNCD: EXIT")) || line.isEmpty()) {
            break;
        }
        int tab = line.indexOf(QLatin1Char('\t'));
        QString name = (tab >= 0) ? line.left(tab).trimmed() : line.trimmed();
        QString comment = (tab >= 0) ? line.mid(tab + 1).trimmed() : QString();
        modules.append({name, comment});
    }
    return modules;
}

// ---------------------------------------------------------------------------
// Module selection
// ---------------------------------------------------------------------------

bool RsyncProtocol::selectModule(const QString &module)
{
    writeLine(module);

    m_authRequired = false;
    m_authChallenge.clear();

    QString reply = readLine();
    if (reply.startsWith(QLatin1String("@RSYNCD: AUTHREQD "))) {
        m_authRequired = true;
        m_authChallenge = reply.mid(18).trimmed();
        qCDebug(KIO_RSYNC_LOG) << "Auth required, challenge:" << m_authChallenge;
        return true; // caller must now call authenticate()
    }
    if (reply.startsWith(QLatin1String("@RSYNCD: OK"))) {
        return true;
    }
    if (reply.startsWith(QLatin1String("@ERROR"))) {
        m_lastError = reply;
        return false;
    }
    m_lastError = QStringLiteral("Unexpected reply after module select: %1").arg(reply);
    return false;
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

bool RsyncProtocol::authenticate(const QString &user, const QString &password,
                                  const QString &challenge)
{
    QString digest = QStringLiteral("md5");
    QByteArray response = computeAuthResponse(password, challenge, digest);
    QByteArray b64 = response.toBase64();
    writeLine(user + QLatin1Char(' ') + QString::fromLatin1(b64));

    QString reply = readLine();
    if (reply.startsWith(QLatin1String("@RSYNCD: OK"))) {
        return true;
    }
    m_lastError = QStringLiteral("Authentication failed: %1").arg(reply);
    return false;
}

QByteArray RsyncProtocol::computeAuthResponse(const QString &password,
                                               const QString &challenge,
                                               const QString &digest)
{
    // The challenge is a base64-encoded nonce from the server.
    // Response = MD5(nonce + password) (or MD4 for legacy).
    QByteArray challengeBytes = QByteArray::fromBase64(challenge.toLatin1());

    auto algo = (digest == QLatin1String("md5"))
                    ? QCryptographicHash::Md5
                    : QCryptographicHash::Md4;
    QCryptographicHash hash(algo);
    hash.addData(challengeBytes);
    hash.addData(password.toUtf8());
    return hash.result();
}

// ---------------------------------------------------------------------------
// Wire mode ↔ Unix mode conversion
// ---------------------------------------------------------------------------

quint32 RsyncProtocol::fromWireMode(quint32 wireMode)
{
    // Rsync uses a portable wire encoding for the file type bits.
    // The permission bits (low 12 bits) pass through unchanged.
    quint32 perm = wireMode & 07777;
    quint32 wireType = wireMode & ~static_cast<quint32>(07777);
    quint32 unixType;

    switch (wireType) {
    case WIRE_IFDIR:  unixType = S_IFDIR;  break;
    case WIRE_IFLNK:  unixType = S_IFLNK;  break;
    case WIRE_IFREG:  unixType = S_IFREG;  break;
    case WIRE_IFBLK:  unixType = S_IFBLK;  break;
    case WIRE_IFCHR:  unixType = S_IFCHR;  break;
    case WIRE_IFSOCK: unixType = S_IFSOCK; break;
    case WIRE_IFIFO:  unixType = S_IFIFO;  break;
    default:          unixType = wireType;  break; // pass through unknown
    }

    return unixType | perm;
}

// ---------------------------------------------------------------------------
// Raw write helpers
// ---------------------------------------------------------------------------

void RsyncProtocol::writeArg(const QByteArray &arg)
{
    m_socket.write(arg);
    m_socket.write("\0", 1);
}

void RsyncProtocol::writeRawBytes(const char *data, int len)
{
    m_socket.write(data, len);
}

void RsyncProtocol::writeInt32(quint32 val)
{
    char buf[4];
    buf[0] = static_cast<char>(val & 0xFF);
    buf[1] = static_cast<char>((val >> 8) & 0xFF);
    buf[2] = static_cast<char>((val >> 16) & 0xFF);
    buf[3] = static_cast<char>((val >> 24) & 0xFF);
    m_socket.write(buf, 4);
}

void RsyncProtocol::writeByte(quint8 val)
{
    char c = static_cast<char>(val);
    m_socket.write(&c, 1);
}

// ---------------------------------------------------------------------------
// Server args (request a file listing or transfer)
//
// After module selection, the rsync protocol switches to null-terminated
// args (not newline-terminated). The real rsync client sends:
//   "--server\0" "--sender\0" "-de.LsfxCIvu\0" ".\0" "path\0" "\0"
// Then: checksum negotiation string, client compat flags, client seed.
// Then reads: server compat flags + server seed.
// ---------------------------------------------------------------------------

bool RsyncProtocol::sendServerArgs(const QString &path, bool listOnly)
{
    Q_UNUSED(listOnly);

    // Send null-terminated args matching what rsync 3.2.x sends for listing
    writeArg("--server");
    writeArg("--sender");
    writeArg("-de.LsfxCIvu");
    writeArg(".");
    QByteArray pathArg = path.isEmpty() ? QByteArray(".") : path.toUtf8();
    writeArg(pathArg);
    m_socket.write("\0", 1); // terminate arg list
    m_socket.flush();

    // --- Protocol negotiation (learned from strace of rsync 3.2.7) ---
    //
    // After args, the server sends:
    //   1 byte: server compat flags
    //   1 byte: negotiate exchange signal (0xFE = "send your negotiate")
    // Then client sends its checksum negotiate string (length + data).
    // Then server sends its checksum negotiate string (length + data).
    // Then server sends 4-byte checksum seed.
    // Then client sends a MSG_DATA multiplex frame with 4 zero bytes.
    // Then server starts sending the multiplexed file list.

    // 1. Read server compat flags
    char tmp[1];
    readExact(tmp, 1);
    quint8 serverCompat = static_cast<quint8>(tmp[0]);
    qCDebug(KIO_RSYNC_LOG) << "Server compat flags:" << serverCompat;

    // 2. Read negotiate exchange signal byte
    readExact(tmp, 1);
    quint8 negotiateSignal = static_cast<quint8>(tmp[0]);
    qCDebug(KIO_RSYNC_LOG) << "Negotiate signal:" << negotiateSignal;

    // 3. Send our checksum negotiate string
    QByteArray ourDigests = "md5 md4";
    writeByte(static_cast<quint8>(ourDigests.size()));
    writeRawBytes(ourDigests.constData(), ourDigests.size());
    m_socket.flush();

    // 4. Read server's checksum negotiate string
    readExact(tmp, 1);
    int serverNegLen = static_cast<quint8>(tmp[0]);
    qCDebug(KIO_RSYNC_LOG) << "Server negotiate length:" << serverNegLen;
    if (serverNegLen > 0) {
        QByteArray serverNeg(serverNegLen, Qt::Uninitialized);
        readExact(serverNeg.data(), serverNegLen);
        qCDebug(KIO_RSYNC_LOG) << "Server negotiate:" << serverNeg;
    }

    // 5. Read 4-byte checksum seed
    char seedBuf[4];
    readExact(seedBuf, 4);
    quint32 checksumSeed = static_cast<quint8>(seedBuf[0])
                         | (static_cast<quint8>(seedBuf[1]) << 8)
                         | (static_cast<quint8>(seedBuf[2]) << 16)
                         | (static_cast<quint8>(seedBuf[3]) << 24);
    qCDebug(KIO_RSYNC_LOG) << "Checksum seed:" << checksumSeed;

    // 6. Send client response: MSG_DATA frame with 4 zero bytes
    //    Frame format: [len_lo=4][len_mid=0][len_hi=0][tag=7][data: 0,0,0,0]
    char mplexFrame[] = {0x04, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00};
    writeRawBytes(mplexFrame, 8);
    m_socket.flush();

    return m_lastError.isEmpty();
}

// ---------------------------------------------------------------------------
// File list decoding (binary, through multiplex layer)
// ---------------------------------------------------------------------------

QList<RsyncFileEntry> RsyncProtocol::receiveFileList()
{
    QList<RsyncFileEntry> entries;
    RsyncFileEntry prev;
    QString prevName;

    // Note: uid/gid are NOT sent because our option string (-de.LsfxCIvu)
    // does not include -o (preserve owner) or -g (preserve group).
    // The XMIT_SAME_UID/GID flags are irrelevant when not preserving.

    while (true) {
        // Read xflags using rsync's varint format
        // (CF_VARINT_FLIST_FLAGS is set in compat flags 0x81)
        quint32 xflags = readVarint();
        if (xflags == 0) {
            // With CF_VARINT_FLIST_FLAGS (compat flag 0x80), the server sends
            // a varint io_error value immediately after the terminator.
            quint32 ioError = readVarint();
            if (ioError != 0) {
                qCWarning(KIO_RSYNC_LOG) << "Server reported io_error:" << ioError;
            }
            break; // end of file list
        }
        if (!m_lastError.isEmpty()) {
            break;
        }

        qCDebug(KIO_RSYNC_LOG) << "xflags:" << QString::number(xflags, 16);

        RsyncFileEntry entry;

        // --- Name (incremental encoding) ---
        // sameLen uses read_byte (per rsync source, even with CF_VARINT_FLIST_FLAGS)
        int sameLen = (xflags & XMIT_SAME_NAME) ? readByte() : 0;
        // newLen: XMIT_LONG_NAME → read_varint30 (=readVarlong(3)); else read_byte
        int newLen = (xflags & XMIT_LONG_NAME)
                         ? static_cast<int>(readVarlong(3))
                         : readByte();
        QByteArray nameBytes = readBytes(newLen);
        entry.name = prevName.left(sameLen) + QString::fromUtf8(nameBytes);
        prevName = entry.name;

        // --- Size (varlong30 with 3 minimum bytes) ---
        entry.size = readVarlong(3);

        // --- Modification time ---
        if (xflags & XMIT_SAME_TIME) {
            entry.mtime = prev.mtime;
        } else {
            entry.mtime = readVarlong(4);
        }

        // --- Mod nanoseconds (comes BEFORE mode in rsync wire format) ---
        if (xflags & XMIT_MOD_NSEC) {
            readVarint(); // discard nanoseconds
        }

        // --- Mode ---
        if (xflags & XMIT_SAME_MODE) {
            entry.mode = prev.mode;
        } else {
            entry.mode = fromWireMode(readInt32());
        }

        // UID/GID are NOT in the wire data (we didn't request -o or -g)

        // --- Symlink target ---
        if (S_ISLNK(entry.mode)) {
            int len = readVarint();
            entry.symlinkTarget = QString::fromUtf8(readBytes(len));
        }

        entry.isDirectory = S_ISDIR(entry.mode);

        qCDebug(KIO_RSYNC_LOG) << "File:" << entry.name
                                << "size:" << entry.size
                                << "mtime:" << entry.mtime
                                << "mode:" << QString::number(entry.mode, 8)
                                << "dir:" << entry.isDirectory;

        entries.append(entry);
        prev = entry;
    }

    return entries;
}

// ---------------------------------------------------------------------------
// Multiplex write helpers
//
// When writing to the server in the binary phase, data must be wrapped in
// MSG_DATA multiplex frames: [len_lo][len_mid][len_hi][tag=7][payload...]
// ---------------------------------------------------------------------------

void RsyncProtocol::writeMplexData(const char *data, int len)
{
    // Write MSG_DATA frame header
    char hdr[4];
    hdr[0] = static_cast<char>(len & 0xFF);
    hdr[1] = static_cast<char>((len >> 8) & 0xFF);
    hdr[2] = static_cast<char>((len >> 16) & 0xFF);
    hdr[3] = static_cast<char>(MSG_DATA + MPLEX_BASE);
    m_socket.write(hdr, 4);
    if (len > 0) {
        m_socket.write(data, len);
    }
    m_socket.flush();
}

void RsyncProtocol::writeMplexInt32(quint32 val)
{
    char buf[4];
    buf[0] = static_cast<char>(val & 0xFF);
    buf[1] = static_cast<char>((val >> 8) & 0xFF);
    buf[2] = static_cast<char>((val >> 16) & 0xFF);
    buf[3] = static_cast<char>((val >> 24) & 0xFF);
    m_socket.write(buf, 4);
}

void RsyncProtocol::writeMplexByte(quint8 val)
{
    char c = static_cast<char>(val);
    m_socket.write(&c, 1);
}

// ---------------------------------------------------------------------------
// File request (generator role)
//
// After receiving the file list, the client acts as the "generator" and
// requests files by sending their index (NDX) + iflags + empty block
// checksums (sum_head with count=0).
//
// Wire format captured from real rsync:
//   MSG_DATA frame containing:
//     write_ndx(fileIndex) - 1 byte for small indices (diff encoding)
//     write_shortint(iflags) - 2 bytes LE (0xA000 = ITEM_IS_NEW|ITEM_TRANSFER)
//     write_sum_head(NULL) - 4 × int32 = 16 bytes (all zeros for new file)
// ---------------------------------------------------------------------------

void RsyncProtocol::sendFileRequest(int fileIndex)
{
    // Build the generator request in a buffer
    QByteArray payload;

    // write_ndx: for first file (index 0), diff from prev(-1) = 1
    quint8 ndxByte = static_cast<quint8>(fileIndex + 1);
    payload.append(static_cast<char>(ndxByte));

    // write_shortint(iflags): 0xA000 in LE = {0x00, 0xA0}
    payload.append('\x00');
    payload.append('\xA0');

    // write_sum_head(NULL): count=0, blength=0, s2length=0, remainder=0
    for (int i = 0; i < 16; ++i) {
        payload.append('\x00');
    }

    writeMplexData(payload.constData(), payload.size());
    qCDebug(KIO_RSYNC_LOG) << "Sent file request for index" << fileIndex
                            << "payload size:" << payload.size();
}

// ---------------------------------------------------------------------------
// File data reception
//
// After sendFileRequest, the server (sender) responds with:
//   NDX (1 byte) + iflags (2 bytes) + sum_head (16 bytes) +
//   token_stream (int32 lengths + data) + file_checksum (16 bytes for MD5)
//
// Token format: [int32 len][data bytes]... [int32 = 0 end marker]
//   len > 0: literal data of that many bytes follows
//   len < 0: block match reference (not used for whole-file transfer)
//   len == 0: end of file data
// ---------------------------------------------------------------------------

QByteArray RsyncProtocol::receiveFileData(qint64 expectedSize)
{
    // Read sender's NDX (1 byte for small file indices)
    quint8 senderNdx = readByte();
    if (!m_lastError.isEmpty()) {
        return {};
    }
    qCDebug(KIO_RSYNC_LOG) << "Sender NDX byte:" << senderNdx;

    // Read iflags (2 bytes, little-endian shortint)
    quint8 iflagsLo = readByte();
    quint8 iflagsHi = readByte();
    quint16 iflags = static_cast<quint16>(iflagsLo) | (static_cast<quint16>(iflagsHi) << 8);
    qCDebug(KIO_RSYNC_LOG) << "Sender iflags:" << QString::number(iflags, 16);

    // Read sum_head: count, blength, s2length, remainder (4 × int32)
    quint32 sumCount = readInt32();
    quint32 sumBlength = readInt32();
    quint32 sumS2length = readInt32();
    quint32 sumRemainder = readInt32();
    qCDebug(KIO_RSYNC_LOG) << "Sum head: count=" << sumCount
                            << "blength=" << sumBlength
                            << "s2length=" << sumS2length
                            << "remainder=" << sumRemainder;

    if (!m_lastError.isEmpty()) {
        return {};
    }

    // Read token stream: file data
    QByteArray result;
    result.reserve(expectedSize);

    while (true) {
        qint32 tokenLen = static_cast<qint32>(readInt32());
        if (!m_lastError.isEmpty()) {
            break;
        }

        if (tokenLen == 0) {
            // End of file data
            qCDebug(KIO_RSYNC_LOG) << "End of token stream, received" << result.size() << "bytes";
            break;
        }

        if (tokenLen > 0) {
            // Literal data
            QByteArray chunk = readBytes(tokenLen);
            if (!m_lastError.isEmpty()) {
                break;
            }
            result.append(chunk);
        } else {
            // Negative = block match reference (not used for whole-file transfer)
            qCDebug(KIO_RSYNC_LOG) << "Block match token:" << tokenLen;
        }
    }

    // Read file checksum (16 bytes for MD5, skip it)
    if (m_lastError.isEmpty() && sumS2length == 0) {
        // When s2length is 0, the file checksum length defaults to 16 (MD5)
        QByteArray checksum = readBytes(16);
        qCDebug(KIO_RSYNC_LOG) << "File checksum:" << checksum.toHex();
    }

    return result;
}

import { Server } from 'socket.io';
import { dbConnect } from '../../lib/db';
import Message from '../../models/Message';
import { usernameFromCookieHeader } from '../../lib/auth';
import { validateUsername, validateEncryptedBlob } from '../../lib/validate';
import { rateLimit } from '../../lib/rateLimit';

const users = {};

export const config = { api: { bodyParser: false } };

export default async function handler(req, res) {
  if (!res.socket.server.io) {
    const io = new Server(res.socket.server, { path: '/api/socketio', addTrailingSlash: false });
    res.socket.server.io = io;

    // Every connection must present a valid session cookie. The username comes
    // from the signed token — never from anything the client tells us.
    io.use((socket, next) => {
      const username = usernameFromCookieHeader(socket.handshake.headers?.cookie);
      if (!username) return next(new Error('unauthorized'));
      socket.data.username = username;
      next();
    });

    const broadcastOnline = () => {
      const map = {};
      for (const u of Object.keys(users)) map[u] = true;
      io.emit('online_users', map);
    };

    io.on('connection', (socket) => {
      const me = socket.data.username;
      users[me] = socket.id;
      broadcastOnline();

      socket.on('send_message', async ({ receiver, encryptedData, senderCopy }) => {
        try {
          // 60 messages per minute per account.
          const { allowed } = rateLimit({ key: `msg:${me}`, limit: 60, windowMs: 60 * 1000 });
          if (!allowed) return socket.emit('send_error', { error: 'Slow down — too many messages.' });

          if (validateUsername(receiver)) {
            return socket.emit('send_error', { error: 'Invalid recipient' });
          }

          const problem =
            validateEncryptedBlob(encryptedData, 'encryptedData') ||
            validateEncryptedBlob(senderCopy, 'senderCopy');
          if (problem) return socket.emit('send_error', { error: problem });

          await dbConnect();
          const doc = await Message.create({
            sender: me,          // authenticated identity, not a client-supplied field
            receiver,
            encryptedData,       // readable by the receiver
            senderCopy,          // same message sealed to the sender's own key
            timestamp: new Date()
          });

          const socketId = users[receiver];
          if (socketId) {
            io.to(socketId).emit('receive_message', {
              sender: me,
              encryptedData,
              timestamp: doc.timestamp
            });
          }
        } catch (err) {
          console.error(err);
          socket.emit('send_error', { error: 'Could not send message' });
        }
      });

      socket.on('disconnect', () => {
        // Only clear the entry if it still points at THIS socket. On a page
        // reload the new socket registers before the old one's disconnect
        // fires, and an unguarded delete would wipe the fresh registration.
        if (users[me] === socket.id) { delete users[me]; broadcastOnline(); }
      });
    });
  }
  res.end();
}

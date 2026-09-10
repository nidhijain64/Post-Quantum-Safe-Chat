import { dbConnect } from '../../lib/db';
import Message from '../../models/Message';
import { requireAuth } from '../../lib/auth';

// Every thread the signed-in user is part of, most recent first.
// The last message is returned still encrypted — the browser decrypts it for
// the preview, so the server never learns what the conversation says.
export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const me = requireAuth(req, res);
  if (!me) return;

  await dbConnect();

  const rows = await Message.aggregate([
    { $match: { $or: [{ sender: me }, { receiver: me }] } },
    { $addFields: { peer: { $cond: [{ $eq: ['$sender', me] }, '$receiver', '$sender'] } } },
    { $sort: { timestamp: 1, createdAt: 1 } },
    {
      $group: {
        _id: '$peer',
        lastAt: { $last: '$timestamp' },
        messageCount: { $sum: 1 },
        lastSender: { $last: '$sender' },
        lastEncryptedData: { $last: '$encryptedData' },
        lastSenderCopy: { $last: '$senderCopy' }
      }
    },
    { $sort: { lastAt: -1 } },
    { $limit: 100 }
  ]);

  res.status(200).json(
    rows.map((r) => {
      const fromMe = r.lastSender === me;
      return {
        username: r._id,
        lastAt: r.lastAt,
        messageCount: r.messageCount,
        fromMe,
        // The copy this user can actually open.
        lastBlob: fromMe ? r.lastSenderCopy : r.lastEncryptedData
      };
    })
  );
}

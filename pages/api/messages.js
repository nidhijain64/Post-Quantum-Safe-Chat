import { dbConnect } from '../../lib/db';
import Message from '../../models/Message';
import { requireAuth } from '../../lib/auth';
import { validateUsername } from '../../lib/validate';

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const me = requireAuth(req, res);
  if (!me) return;

  const { user1, user2 } = req.query;
  if (!user1 || !user2) return res.status(400).json({ error: 'user1 and user2 are required' });
  if (validateUsername(user1) || validateUsername(user2)) {
    return res.status(400).json({ error: 'Invalid username' });
  }

  // You may only read a conversation you are part of.
  if (me !== user1 && me !== user2) {
    return res.status(403).json({ error: 'Not your conversation' });
  }

  await dbConnect();
  const history = await Message.find({
    $or: [
      { sender: user1, receiver: user2 },
      { sender: user2, receiver: user1 }
    ]
  }).sort({ timestamp: 1, createdAt: 1 }).lean();

  res.status(200).json(history.map(({ _id, sender, receiver, encryptedData, senderCopy, timestamp, createdAt }) => ({
    id: _id, sender, receiver, encryptedData, senderCopy, timestamp, createdAt
  })));
}

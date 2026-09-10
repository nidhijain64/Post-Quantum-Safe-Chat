import { dbConnect } from "../../../lib/db";
import User from "../../../models/User";
import { requireAuth } from "../../../lib/auth";
import { validateUsername } from "../../../lib/validate";

// Public keys are only handed out to signed-in users, so the directory of
// registered accounts is not open to anonymous enumeration.
export default async function handler(req, res) {
  if (!requireAuth(req, res)) return;

  const { username } = req.query;
  if (validateUsername(username)) return res.status(400).json({ error: "Invalid username" });

  await dbConnect();
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ error: "Not found" });
  res.status(200).json({ publicKey: user.publicKey });
}

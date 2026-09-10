import bcrypt from "bcryptjs";
import { dbConnect } from "../../lib/db";
import User from "../../models/User";
import { enforceRateLimit } from "../../lib/rateLimit";
import { validateUsername, validatePassword, validatePublicKey } from "../../lib/validate";

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();

  // 5 registrations per IP per hour.
  if (enforceRateLimit(req, res, { name: "register", limit: 5, windowMs: 60 * 60 * 1000 })) return;

  const { username, password, publicKey } = req.body || {};

  const problem =
    validateUsername(username) ||
    validatePassword(password) ||
    validatePublicKey(publicKey);
  if (problem) return res.status(400).json({ error: problem });

  await dbConnect();
  const name = username.trim();

  if (await User.findOne({ username: name })) {
    return res.status(400).json({ error: "Username taken" });
  }

  const hashed = await bcrypt.hash(password, 10);
  await User.create({ username: name, password: hashed, publicKey });

  res.status(201).json({ message: "Registered" });
}

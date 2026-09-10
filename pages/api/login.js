import bcrypt from "bcryptjs";
import { dbConnect } from "../../lib/db";
import User from "../../models/User";
import { signToken, sessionCookie } from "../../lib/auth";
import { enforceRateLimit } from "../../lib/rateLimit";
import { validateUsername, validatePassword } from "../../lib/validate";

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();

  // 10 attempts per IP per 15 minutes.
  if (enforceRateLimit(req, res, { name: "login", limit: 10, windowMs: 15 * 60 * 1000 })) return;

  const { username, password } = req.body || {};

  // Validate shape before touching the database. The generic error below is
  // deliberate — it must not reveal whether the username exists.
  if (validateUsername(username) || validatePassword(password)) {
    return res.status(400).json({ error: "Invalid username or password" });
  }

  await dbConnect();
  const name = username.trim();

  const user = await User.findOne({ username: name });
  if (!user) return res.status(400).json({ error: "Invalid username or password" });

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(400).json({ error: "Invalid username or password" });

  res.setHeader("Set-Cookie", sessionCookie(signToken(name)));
  res.status(200).json({ message: "Login successful", username: name });
}

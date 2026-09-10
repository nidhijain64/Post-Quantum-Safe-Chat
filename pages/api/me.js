import { requireAuth } from "../../lib/auth";

// Who am I? Lets the client learn its identity from the signed cookie instead
// of trusting localStorage.
export default function handler(req, res) {
  const username = requireAuth(req, res);
  if (!username) return;
  res.status(200).json({ username });
}

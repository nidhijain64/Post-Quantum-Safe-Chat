import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  publicKey: { type: String, required: true }, // Stores Kyber-768 Public Key
});

export default mongoose.models.User || mongoose.model("User", userSchema);

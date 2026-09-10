import mongoose from 'mongoose';

const MessageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  receiver: { type: String, required: true },
  // Encrypted for the RECEIVER (encapsulated to the receiver's public key)
  encryptedData: {
    cipherText: { type: String, required: true },   // AES Encrypted Content
    nonce: { type: String, required: true },        // AES IV
    kemCipherText: { type: String, required: true } // Kyber Encapsulated Key
  },
  // Encrypted for the SENDER (encapsulated to the sender's own public key) so the
  // sender can still read their own history. Optional: older messages lack it.
  senderCopy: {
    cipherText: { type: String },
    nonce: { type: String },
    kemCipherText: { type: String }
  },
  timestamp: { type: Date, default: Date.now }
}, { timestamps: true });

export default mongoose.models.Message || mongoose.model('Message', MessageSchema);

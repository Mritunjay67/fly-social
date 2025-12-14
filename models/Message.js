import mongoose from "mongoose";

const messageSchema = new mongoose.Schema({
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  receiver: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  
  // --- NEW: Identify what kind of message this is ---
  messageType: {
    type: String,
    enum: ["text", "image", "post_share"], // Restricts values to these 3
    default: "text",
  },

  // --- NEW: Reference the Post if it is a "post_share" ---
  postId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Post", // Make sure this matches your Post model name
    required: false, // Not required for normal text messages
  },

  // Text is optional (e.g., user might just share a post without a caption)
  text: {
    type: String,
  },

  imageUrl: {
    type: String,
  },

  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const Message = mongoose.model("Message", messageSchema);
export default Message;
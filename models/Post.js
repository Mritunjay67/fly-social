import mongoose from "mongoose";

const postSchema = new mongoose.Schema({
    // Reference to the user who created the post
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  // We will store both images and videos here
  imageUrl: { 
    type: String,
    required: true,
  },
  // Optional caption for the post
  caption: {
    type: String,
  },
  // --- NEW FIELD: To distinguish Reels ---
  type: {
    type: String,
    enum: ['image', 'video'],
    default: 'image'
  },
  // Array of user references who liked the post
  likes: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  }],
    // Timestamp of when the post was created   
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const Post = mongoose.model("Post", postSchema);
export default Post;
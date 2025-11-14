// /models/Post.js

import mongoose from "mongoose";
const { Schema } = mongoose;

const postSchema = new Schema({
    // This is the 'user_id' from your diagram.
    // It links this post to the user who created it.
    user: {
        type: Schema.Types.ObjectId,
        ref: 'User', // This 'User' must match the name you used in mongoose.model('User', ...)
        required: true
    },
    // This is the 'image_url' from your diagram
    imageUrl: {
        type: String,
        required: true
    },
    // This is the 'caption' from your diagram
    caption: {
        type: String,
        required: false // Maybe they don't need a caption
    },
    // This is the 'created_at' from your diagram
    createdAt: {
        type: Date,
        default: Date.now
    },
    // We can add likes later, starting with an empty array
    likes: [
        {
            type: Schema.Types.ObjectId,
            ref: 'User'
        }
    ]
});

// We 'export' this model so server.js can use it
const Post = mongoose.model('Post', postSchema);
export default Post;
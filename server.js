/*# Step 1: Check which files you have modified
git status

# Step 2: Stage all your changes (prepare them for saving)
git add .

# Step 3: Commit the changes (save them with a message)
git commit -m "Added post share feature"

# Step 4: Push the changes to your remote repository (GitHub/GitLab)
git push origin main */

// password of mongo atlas is Mritunjay678

import 'dotenv/config';
import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import bodyParser from "body-parser";
import cors from "cors";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import session from "express-session";
import multer from "multer";
import path from "path";
import { createServer } from "http";
import { Server } from "socket.io";
import fs from "fs";
import { GoogleGenerativeAI } from "@google/generative-ai";

// Models
import User from "./models/User.js";
import Post from "./models/Post.js";
import Comment from "./models/Comment.js";
import Message from "./models/Message.js"; // <--- NEW IMPORT
import Notification from "./models/notification.js";

// For __dirname in ES modules

import { fileURLToPath } from 'url';

// 👇 Add these two lines to create __dirname manually
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Secrets
const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

// --- AI DIAGNOSTIC START ---
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// USE THIS EXACT NAME FROM YOUR LIST:
const model = genAI.getGenerativeModel({ model: "gemini-flash-latest" });

//const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

// --- AI DIAGNOSTIC END ---

// --- EXPRESS SETUP ---
const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

app.use(cors());

// --- REPLACE BODY PARSER WITH THIS ---
app.use(express.json()); // Handles JSON data (like bodyParser.json)
app.use(express.urlencoded({ extended: true })); // Handles form data (important for uploads)

app.use(express.static("public"));
app.use('/uploads', express.static('uploads'));

app.use(session({
    secret: 'super-secret-key',
    resave: false,
    saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());

// --- DB CONNECTION ---
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/social_media_db";
mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("MongoDB Error:", err));

// --- MULTER ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});
// File filter to accept only images and videos
const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type! Only images and videos allowed.'), false);
    }
};
// Set file size limit to 50MB
const upload = multer({ 
    storage: storage,
    fileFilter: fileFilter,
    limits: { fileSize: 50 * 1024 * 1024 } // Limit to 50MB
});

// --- MIDDLEWARE ---
const verifyToken = (req, res, next) => {
    const tokenHeader = req.headers['authorization']; 
    if (!tokenHeader) return res.status(403).json({message: "No token provided"});
    const token = tokenHeader.split(' ')[1]; 
    jwt.verify(token, JWT_SECRET, (err, decoded)=> {
        if (err) return res.status(401).json({message: "Failed to authenticate"});
        req.userId = decoded.id;
        next();
    });
};

// ================= ROUTES =================

// Auth
app.post("/signup", async (req, res) => {
  try {
    const { name, username, email, password } = req.body;
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, username, email, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "User registered" });
  } catch (err) { res.status(500).json({ message: "Server Error" }); }
});

app.post("/login", async (req, res) => {
    try {
        const { loginInput, password } = req.body;
        const isEmail = loginInput.includes('@');
        const user = await User.findOne(isEmail ? { email: loginInput } : { username: loginInput });
        if (!user) return res.status(401).json({ message: "Invalid credentials"});
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: "Invalid credentials"});
        
        const token = jwt.sign({ id: user._id, email: user.email, username: user.username }, JWT_SECRET, { expiresIn: "1h"});
        res.status(200).json({ message: "Login successful", token });
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

// Google Auth
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'], prompt: 'select_account' }));
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/Login.html' }), 
  (req, res) => {
    const token = jwt.sign({ id: req.user._id }, JWT_SECRET, { expiresIn: "1h"});
    res.send(`<html><body><script>localStorage.setItem("flySocialToken", "${token}"); window.location.href = "/Home.html";</script></body></html>`);
  }
);

// Passport Google Strategy
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
  },
  async (token, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });
        if (user) return done(null, user);
        
        const email = profile.emails[0].value;
        user = await User.findOne({ email });
        if (user) {
            user.googleId = profile.id;
            await user.save();
            return done(null, user);
        }

        let username = email.split('@')[0];
        const newUser = new User({
            googleId: profile.id,
            name: profile.displayName,
            email: email,
            username: username,
            password: await bcrypt.hash(Math.random().toString(36), 10)
        });
        await newUser.save();
        return done(null, newUser);
    } catch (err) { return done(err, false); }
  }
));
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try { const user = await User.findById(id); done(null, user); } catch (err) { done(err, null); }
});

// Posts
app.post("/createpost", verifyToken, upload.single('imageFile'), async (req, res) => {
    try {
        const { caption } = req.body;
        if (!req.file) return res.status(400).json({ message: "File required" });

        // Detect if it is a video or image
        const isVideo = req.file.mimetype.startsWith('video/');
        const postType = isVideo ? 'video' : 'image';

        const newPost = new Post({ 
            user: req.userId, 
            imageUrl: `/uploads/${req.file.filename}`, // We keep the name 'imageUrl' to save time, but it stores video paths too
            caption,
            type: postType // Save the type
        });

        await newPost.save();
        res.status(201).json({ message: "Post created", post: newPost });
    } catch (err) { 
        console.error(err);
        res.status(500).json({ message: "Server error" }); 
    }
});

app.get("/getposts", verifyToken, async (req, res) => {
    try {
        const { filter } = req.query;
        let query = {};
        if (filter === 'following') {
            const currentUser = await User.findById(req.userId);
            const ids = [...currentUser.following, req.userId];
            query = { user: { $in: ids } };
        }
        const posts = await Post.find(query).sort({ createdAt: -1 }).populate("user", "username name profilePicture");
        res.status(200).json(posts);
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.delete("/posts/:postId", verifyToken, async (req, res) => {
    try {
        const post = await Post.findById(req.params.postId);
        if (!post) return res.status(404).json({ message: "Not found" });
        if (post.user.toString() !== req.userId) return res.status(403).json({ message: "Unauthorized" });
        await post.deleteOne();
        res.status(200).json({ message: "Deleted" });
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/posts/:postId/like", verifyToken, async (req, res) => {
    try {
        const post = await Post.findById(req.params.postId);
        if (!post) return res.status(404).json({ message: "Not found" });
        const index = post.likes.indexOf(req.userId);
        if (index === -1) post.likes.push(req.userId);
        else post.likes.splice(index, 1);
        await post.save();
        res.status(200).json({ message: index === -1 ? "Liked" : "Unliked", likesCount: post.likes.length });
        if (!post.likes.includes(req.user.id) && post.user.toString() !== req.user.id) {
            
            await Notification.create({
                sender: req.user.id,    
                receiver: post.user,     
                type: 'like',
                post: post._id
            });
        }
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

// --- UPLOAD CHAT IMAGE ---
app.post("/chat/upload", verifyToken, upload.single('chatFile'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ message: "No file uploaded" });
        // Return the URL so the frontend can send it via Socket.io
        res.json({ imageUrl: `/uploads/${req.file.filename}` });
    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});

// AI Chat Endpoint - DEBUG VERSION
app.post('/chat/ai', async (req, res) => {
    try {
        console.log("--- AI Request Received ---");
        const { prompt } = req.body;
        console.log("Prompt:", prompt);

        if (!prompt) {
            console.log("Error: No prompt");
            return res.status(400).json({ error: "No prompt provided" });
        }

        // Call Gemini
        const model = genAI.getGenerativeModel({ model: "gemini-flash-latest" });
        const result = await model.generateContent(prompt);
        const response = await result.response;
        
        // Check if we actually got text
        const text = response.text();
        console.log("Gemini Response:", text); // <--- This will show in your terminal

        if (!text) {
             throw new Error("Gemini returned empty text");
        }

        // Send back the answer
        res.json({ reply: text });

    } catch (error) {
        console.error("❌ AI ERROR DETAILS:", error); // <--- READ THIS IN YOUR TERMINAL
        
        // If the error is blocked content (Safety filters)
        if (error.response && error.response.promptFeedback) {
             console.log("Safety Block:", error.response.promptFeedback);
        }

        res.status(500).json({ reply: "My brain is having trouble connecting. Check the server terminal for details." });
    }
});
// Comments
app.post("/posts/:postId/comments", verifyToken, async (req, res) => {
    try {
        const newComment = new Comment({ post: req.params.postId, user: req.userId, text: req.body.text });
        await newComment.save();
        await newComment.populate("user", "username");
        res.status(201).json(newComment);
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/posts/:postId/comments", verifyToken, async (req, res) => {
    try {
        const comments = await Comment.find({ post: req.params.postId }).sort({ createdAt: 1 }).populate("user", "username");
        res.status(200).json(comments);
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.delete("/posts/:postId/comments/:commentId", verifyToken, async (req, res) => {
    try {
        const comment = await Comment.findById(req.params.commentId);
        if (!comment) return res.status(404).json({ message: "Not found" });
        if (comment.user.toString() !== req.userId) return res.status(403).json({ message: "Unauthorized" });
        await comment.deleteOne();
        res.status(200).json({ message: "Deleted" });
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

// Profile & Users
app.get("/profile", verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select("-password");
        res.status(200).json(user);
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/users/:userId", verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId).select("-password");
        res.status(200).json(user);
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/posts/user/:userId", verifyToken, async (req, res) => {
    try {
        const posts = await Post.find({ user: req.params.userId }).sort({ createdAt: -1 }).populate("user", "username name profilePicture");
        res.status(200).json(posts);
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/search", verifyToken, async (req, res) => {
    try {
        const { query } = req.query;
        if (!query) return res.json([]);
        // Search by username OR name (Case insensitive)
        const users = await User.find({
            $or: [{ username: { $regex: query, $options: "i" } }, { name: { $regex: query, $options: "i" } }]
        }).select("name username profilePicture").limit(10);
        res.json(users);
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.put("/user/update", verifyToken, upload.single('profilePicture'), async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (req.body.name) user.name = req.body.name;
        if (req.body.bio) user.bio = req.body.bio;
        if (req.file) user.profilePicture = `/uploads/${req.file.filename}`;
        await user.save();
        res.status(200).json({ message: "Updated", user });
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/users/:id/follow", verifyToken, async (req, res) => {
    if (req.userId === req.params.id) return res.status(400).json({ message: "Cannot follow self" });
    try {
        await User.findByIdAndUpdate(req.params.id, { $addToSet: { followers: req.userId } });
        await User.findByIdAndUpdate(req.userId, { $addToSet: { following: req.params.id } });
        const existingNotif = await Notification.findOne({
            sender: req.userId,
            receiver: req.params.id,
            type: 'follow'
        });

        if (!existingNotif) {
            await Notification.create({
                sender: req.userId,
                receiver: req.params.id,
                type: 'follow'
            });
        }
        res.status(200).json({ message: "Followed" });
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/users/:id/unfollow", verifyToken, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.params.id, { $pull: { followers: req.userId } });
        await User.findByIdAndUpdate(req.userId, { $pull: { following: req.params.id } });
        await Notification.findOneAndDelete({
            sender: req.userId,
            receiver: req.params.id,
            type: 'follow'
        });
        res.status(200).json({ message: "Unfollowed" });
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/users/:userId/connections", verifyToken, async (req, res) => {
    try {
        const { type } = req.query;
        const user = await User.findById(req.params.userId).populate(type, "username name profilePicture");
        res.status(200).json(user[type]);
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

// --- CHAT ROUTES (NEW) ---
app.get("/messages/:otherUserId", verifyToken, async (req, res) => {
    try {
        const myId = req.userId;
        const otherId = req.params.otherUserId;
        const messages = await Message.find({
            $or: [
                { sender: myId, receiver: otherId },
                { sender: otherId, receiver: myId }
            ]
        }).sort({ createdAt: 1 })
        .populate({
            path: "postId", 
            select: "imageUrl caption user", // Fetch post image & caption
            populate: { path: "user", select: "username profilePicture" } // Fetch post author
        });
        res.json(messages);
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

// --- SMART AI CAPTION GENERATOR (Text + Image) ---
app.post("/ai/generate-caption", verifyToken, upload.single('imageFile'), async (req, res) => {
    try {
        const { prompt } = req.body; // User's thoughts
        const file = req.file;       // The uploaded image

        let result;

        if (file) {
            // CASE 1: Image + Text
            // Convert image to format Gemini understands
            const imagePart = {
                inlineData: {
                    data: fs.readFileSync(file.path).toString("base64"),
                    mimeType: file.mimetype,
                },
            };
            
            const promptText = prompt 
                ? `Write an engaging social media caption for this image. The user's thought about it is: "${prompt}". Use emojis and hashtags.` 
                : `Write an engaging, aesthetic social media caption for this image. Include emojis and hashtags.`;

            result = await model.generateContent([promptText, imagePart]);
        } else {
            // CASE 2: Text Only (No image uploaded yet)
            if (!prompt) return res.status(400).json({ message: "Upload a photo or type a prompt!" });
            
            result = await model.generateContent(`Write a creative social media caption based on this topic: "${prompt}". Include emojis and hashtags.`);
        }

        const response = await result.response;
        const text = response.text();
        res.json({ caption: text });

    } catch (err) {
        console.error("AI Error:", err);
        res.status(500).json({ message: "AI is having trouble seeing right now. Try again." });
    }
});

// --- SOCKET.IO LOGIC (UPDATED) ---
io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  socket.on("join_room", (userId) => {
    socket.join(userId);
  });

  // Updated to handle Image URLs
  socket.on("send_message", async (data) => {
    const { senderId, receiverId, text, imageUrl, postId } = data; // Now getting imageUrl too

    try {
        // Determine message type
        let messageType = "text";
        if (postId) messageType = "post_share";
        else if (imageUrl) messageType = "image";
        // Create and save message
        const newMessage = new Message({ 
            sender: senderId, 
            receiver: receiverId, 
            text: text || "", 
            imageUrl: imageUrl, // Save the image URL
            postId: postId || null, // Save the post ID
            messageType: messageType // Save the type
        });
        await newMessage.save();

        // 4. Populate the post details immediately so the receiver sees the card
        await newMessage.populate({
            path: "postId",
            select: "imageUrl caption user"
        });
        // Send to receiver
        io.to(receiverId).emit("receive_message", newMessage);
        
    } catch (err) { console.error("Error saving message:", err); }
  });

  socket.on("disconnect", () => { console.log("User disconnected"); });
});


// --- GET NOTIFICATIONS ---
app.get('/notifications', verifyToken, async (req, res) => {
    try {
        const notifications = await Notification.find({ receiver: req.userId }) // Note: req.userId comes from verifyToken
            .sort({ createdAt: -1 })
            .populate('sender', 'username name profilePicture')
            .populate('post', 'imageUrl');

        const formattedNotifications = notifications.map(notif => ({
            _id: notif._id,
            type: notif.type,
            isRead: notif.isRead,
            createdAt: notif.createdAt,
            commentPreview: notif.commentPreview,
            sender: notif.sender,
            postImage: notif.post ? notif.post.imageUrl : null 
        }));

        res.json(formattedNotifications);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Error fetching notifications" });
    }
});

// --- MARK READ ---
app.post('/notifications/mark-read', verifyToken, async (req, res) => {
    try {
        await Notification.updateMany(
            { receiver: req.userId, isRead: false },
            { $set: { isRead: true } }
        );
        res.json({ message: "All marked as read" });
    } catch (err) {
        res.status(500).json({ message: "Error updating notifications" });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'Home.html'));
});

const PORT = process.env.PORT || 5000;
httpServer.listen(PORT, () => {
   console.log(`Server running on port ${PORT}`);
});
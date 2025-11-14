import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import bodyParser from "body-parser";
import cors from "cors";
import User from "./models/User.js";
import Post from "./models/Post.js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
// Add these new imports
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import session from "express-session";

// --- 1. NEW IMPORTS ---
import multer from "multer";
import path from "path";

import 'dotenv/config';
// ----------------------
// Your secrets are now loaded securely from your .env file
const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

// --- 2. NEW MULTER CONFIGURATION ---
// Make the 'uploads' folder public
app.use('/uploads', express.static('uploads'));

// --- PASSPORT & SESSION CONFIGURATION ---
app.use(session({
    secret: 'a-very-secret-key-for-sessions', // Change this to any random string
    resave: false,
    saveUninitialized: false,
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Passport Strategy for Google
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:5000/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    // This function is called when Google successfully authenticates a user
    try {
        // Find user by their Google ID
        let user = await User.findOne({ googleId: profile.id });

        if (user) {
            // If user exists, log them in
            return done(null, user);
        } else {
            // If user doesn't exist, create a new user
            const newUser = new User({
                googleId: profile.id,
                name: profile.displayName,
                email: profile.emails[0].value,
                username: profile.emails[0].value.split('@')[0], // Create a username from email
                // We set a random password because our model requires one
                // This user will only log in via Google
                password: await bcrypt.hash(Math.random().toString(36), 10) 
            });
            await newUser.save();
            return done(null, newUser);
        }
    } catch (err) {
        return done(err, false);
    }
  }
));

// These functions tell Passport how to "remember" a user
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});
// --- END OF PASSPORT CONFIG ---

// Multer Storage Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Save files to the 'uploads' folder
  },
  filename: (req, file, cb) => {
    // Create a unique filename to prevent conflicts
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
    storage: storage,
    // Optional: Add file filter for images/videos
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image and video files are allowed!'), false);
        }
    }
});
// ---------------------------------

mongoose
  .connect("mongodb://localhost:27017/social_media_db")
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("MongoDB Connection Error:", err));

// --- SIGNUP ROUTE ---
app.post("/signup", async (req, res) => {
  try {
    const { name, username, email, password } = req.body;
    const existingUser = await User.findOne({
      $or: [{ email: email }, { username: username.toLowerCase() }],
    });

    if (existingUser) {
      if (existingUser.email === email) {
        return res.status(400).json({ message: "Email already exists" });
      }
      if (existingUser.username === username.toLowerCase()) {
        const baseSuggestion = name.split(' ')[0]
                                  .toLowerCase()
                                  .replace(/[^a-z0-9]/g, '');
        const suggestion = `${baseSuggestion}${Math.floor(100 + Math.random() * 900)}`;
        const suggestionTaken = await User.findOne({ username: suggestion });
        let finalSuggestion = null;
        if (!suggestionTaken) {
            finalSuggestion = suggestion;
        }
        return res.status(400).json({
            message: `Username '${username}' is already taken.`,
            suggestion: finalSuggestion 
        });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      name,
      username: username.toLowerCase(),
      email,
      password: hashedPassword,
    });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    if (err.code === 11000) {
        return res.status(400).json({ message: "Email or username already exists." })
    }
    console.error(err);
    res.status(500).json({ message: "Server Error" });
  }
});

// --- LOGIN ROUTE ---
app.post("/login", async (req, res) => {
    try {
        const { loginInput, password } = req.body;
        const isEmail = loginInput.includes('@');
        const user = await User.findOne(
            isEmail 
              ? { email: loginInput } 
              : { username: loginInput.toLowerCase() }
        );

        if (!user){
           return res.status(401).json({ message: "Invalid credentials"});
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: "Invalid credentials"});
        }
        const token = jwt.sign(
            { id: user._id, email: user.email, username: user.username },
            JWT_SECRET,
            { expiresIn: "1h"}
        );
        res.status(200).json({ message: "Login successful", token: token});
    } catch (err) {
        console.error("Login Error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// --- GOOGLE AUTH ROUTES ---

// 1. This route starts the Google login process
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'], prompt: 'select_account' })
);

// 2. This is the "callback" route Google sends the user back to
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/Login.html' }), // If login fails, send back to login
  (req, res) => {
    // Successful authentication!
    // We create a JWT token, just like in our regular login
    const token = jwt.sign(
        { id: req.user._id, email: req.user.email, username: req.user.username },
        JWT_SECRET,
        { expiresIn: "1h"}
    );
    
    // We send this token back to a simple HTML page that will save it and redirect to Home
    res.send(`
        <html>
            <body>
                <script>
                    localStorage.setItem("flySocialToken", "${token}");
                    window.location.href = "/Home.html";
                </script>
                <p>Logging you in...</p>
            </body>
        </html>
    `);
  }
);

// --- FORGOT PASSWORD ROUTE ---
app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });

        // IMPORTANT: For security, we send a "success" response 
        // even if the user is not found.
        if (!user) {
            return res.status(200).json({ message: "If a user with this email exists, a reset link has been sent." });
        }

        // 1. Create a temporary, short-lived token
        const resetToken = jwt.sign(
            { id: user._id }, 
            JWT_SECRET, 
            { expiresIn: '15m' } // Link is valid for 15 minutes
        );

        // 2. Create the reset link
        const resetLink = `http://localhost:5000/reset-password.html?token=${resetToken}`;

        // 3. Set up Nodemailer to send the email
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: EMAIL_USER,
                pass: EMAIL_PASS,
            },
        });

        // 4. Send the email
        await transporter.sendMail({
            from: `"FLY Social" <${EMAIL_USER}>`,
            to: user.email,
            subject: "Reset Your Password for FLY Social",
            html: `
                <p>Hello ${user.name},</p>
                <p>Someone requested a password reset for your FLY Social account.</p>
                <p>If this was you, please click the link below to set a new password. This link will expire in 15 minutes.</p>
                <br>
                <a href="${resetLink}" style="background-color: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Your Password</a>
                <br>
                <p>If you did not request this, you can safely ignore this email.</p>
            `
        });

        res.status(200).json({ message: "If a user with this email exists, a reset link has been sent." });

    } catch (err) {
        console.error("Forgot Password Error:", err);
        res.status(500).json({ message: "Server error" });
    }
});


// --- RESET PASSWORD ROUTE ---
app.post("/reset-password", async (req, res) => {
    const { token, newPassword } = req.body;

    // 1. Check for token and new password
    if (!token || !newPassword) {
        return res.status(400).json({ message: "Invalid request." });
    }

    try {
        // 2. Verify the temporary token
        const decoded = jwt.verify(token, JWT_SECRET);

        // 3. Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // 4. Find the user and update their password
        await User.updateOne(
            { _id: decoded.id },
            { $set: { password: hashedPassword } }
        );

        res.status(200).json({ message: "Password has been reset successfully!" });

    } catch (err) {
        // Handle expired or invalid token
        if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
            return res.status(401).json({ message: "Your reset link is invalid or has expired. Please try again." });
        }
        console.error("Reset Password Error:", err);
        res.status(500).json({ message: "Server error" });
    }
});
// --- 3. CORRECT ROUTE ORDER ---
// We MUST define verifyToken *BEFORE* we use it.

// --- VERIFY TOKEN FUNCTION ---
const verifyToken = (req, res, next) => {
    const tokenHeader = req.headers['authorization']; 
    if (!tokenHeader) {
        return res.status(403).json({message: "No token provided"});
    }
    const token = tokenHeader.split(' ')[1]; 
    jwt.verify(token, JWT_SECRET, (err, decoded)=> {
        if (err) {
            return res.status(401).json({message: "Failed to authenticate token "});
        }
        req.userId = decoded.id;
        next();
    });
};


// --- 4. NEW CREATE POST ROUTE ---
// This route is now AFTER verifyToken and uses 'upload.single()'
app.post("/createpost", verifyToken, upload.single('imageFile'), async (req, res) => {
    try {
        // The 'caption' comes from req.body (form data)
        const { caption } = req.body;
        
        // The file info comes from req.file (thanks to multer)
        if (!req.file) {
            return res.status(400).json({ message: "Image or video file is required" });
        }

        // We build the path to the file
        const fileUrl = `/uploads/${req.file.filename}`;

        // Create the new post
        const newPost = new Post({
            user: req.userId,
            imageUrl: fileUrl, // Save the local file path
            caption: caption
        });
        
        await newPost.save();
        res.status(201).json({ message: "Post created successfully", post: newPost });

    } catch (err) {
        console.error("Post Creation Error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// --- GET ALL POSTS ROUTE ---
app.get("/getposts", verifyToken, async (req, res) => {
    try {
        const posts = await Post.find()
            .sort({ createdAt: -1 })
            .populate("user", "username name"); 

        res.status(200).json(posts);
    } catch (err) {
        console.error("Get Posts Error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// --- GET PROFILE ROUTE ---
app.get("/profile", verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select("-password");
        if(!user) {
            return res.status(404).json({ message: "User not found" });
        }
        res.status(200).json(user);
    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});
// --- TEST EMAIL ROUTE ---
app.get("/test-email", async (req, res) => {
    console.log("Attempting to send a test email...");
    try {
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: EMAIL_USER,
                pass: EMAIL_PASS,
            },
        });

        await transporter.sendMail({
            from: `"FLY Social Test" <${EMAIL_USER}>`,
            to: EMAIL_USER, // Send it to yourself
            subject: "Nodemailer Test",
            html: "<p>This is a test email. If you got this, it's working!</p>"
        });

        console.log("Test email sent successfully!");
        res.send("Test email sent successfully! Check your inbox.");

    } catch (err) {
        console.error("--- NODEMAILER TEST FAILED ---");
        console.error(err); // This will show the EAUTH error if it's still broken
        res.status(500).send("Failed to send email. Check your server.js terminal.");
    }
});
app.listen(5000, () => {
    console.log("Server running on http://localhost:5000");
});
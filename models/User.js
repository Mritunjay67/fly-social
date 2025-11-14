import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: true 
  },
  // --- THIS IS THE MISSING FIELD ---
  username: {
    type: String,
    required: true,
    unique: true, // No two users can have the same username
    trim: true,     // Removes whitespace
    lowercase: true // Stores it as all lowercase
  },
  // --- END OF MISSING FIELD ---
  email: { 
    type: String, 
    required: true, 
    unique: true 
  },
  password: { 
    type: String, 
    required: true 
  },
  googleId: {
     type: String, 
     unique: true, 
     sparse: true }
});

const User = mongoose.model("User", userSchema);

export default User;
// models/Notification.js
const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema
({
  sender: 
        { type: mongoose.Schema.Types.ObjectId, 
          ref: 'User', 
          required: true },
  receiver: 
        { type: mongoose.Schema.Types.ObjectId,   
          ref: 'User', 
          required: true },
  type: 
        { type: String, 
          enum: ['like', 'comment', 'follow'], 
          required: true },
  post: 
        { type: mongoose.Schema.Types.ObjectId, 
          ref: 'Post' }, // Optional (not needed for 'follow')
  commentPreview: 
        { type: String }, // Store a snippet of the comment if type is 'comment'
  isRead:  
        { type: Boolean,
          default: false },
  createdAt: 
        { type: Date, 
          default: Date.now }
});

module.exports = mongoose.model('Notification', notificationSchema);
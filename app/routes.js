import express from "express";
import {
  login,
  register,
  logout,
  forgetPassword,
  createBookmark,
  deleteBookmark,
  getBookmark,
  getUser,
  updateUser,
  createComment,
  getComments,
  updateComment,
  deleteComment,
} from "./handler.js";
import authMiddleware from "./middleware.js";
import multer from "multer";

const router = express.Router();
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 }
});

// Register
router.post("/register", register);

// Login
router.post("/login", login);

// Forget Password
router.post("/password-reset", forgetPassword);

// Logout
router.post("/logout", authMiddleware, logout);

// Create Bookmark
router.post("/bookmark", authMiddleware, createBookmark);

// Delete Bookmark
router.delete("/bookmark/:id", authMiddleware, deleteBookmark);

// Get Bookmark
router.get("/bookmark", authMiddleware, getBookmark);

// Get user profile
router.get("/user/:id", authMiddleware, getUser);

// Update user profile
router.put("/user/:id", authMiddleware, upload.single("profileImage"), updateUser);

// Create comment
router.post("/:recipe_id/comments", authMiddleware, createComment);

// Get comments
router.get("/:recipe_id/comments", authMiddleware, getComments);

// Update comment
router.put("/comments/:comment_id", authMiddleware, updateComment);

// Delete comment
router.delete("/comments/:comment_id", authMiddleware, deleteComment);

export default router;

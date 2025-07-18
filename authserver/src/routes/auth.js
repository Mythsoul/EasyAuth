import express from "express"; 
import { login, register, logout, refreshToken, verifyEmail, resendVerificationEmail, verifyEmailPage } from "../controllers/AuthController.js";
import { originValidator, strictOriginValidator } from "../middleware/originValidator.js";
import { authenticateToken } from "../middleware/authMiddleware.js";

const router = express.Router(); 

router.use('/auth/*', originValidator);

// Public routes
router.post('/auth/register', strictOriginValidator, register);
router.post('/auth/login', strictOriginValidator, login);
router.post('/auth/refresh-token', refreshToken);

// Email verification routes
router.get('/verify-email', verifyEmailPage); 
router.post('/auth/verify-email', strictOriginValidator, verifyEmail);
router.post('/auth/resend-verification-email', strictOriginValidator, resendVerificationEmail);

// Protected routes
router.get('/auth/me', authenticateToken, (req, res) => {
  res.json({
    success: true,
    data: {
      userId: req.user.userId,
      email: req.user.email,
      username: req.user.username,
      role: req.user.role
    }
  });
});

router.post('/auth/verify-token', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'Token is valid',
    data: {
      userId: req.user.userId,
      email: req.user.email,
      username: req.user.username,
      role: req.user.role
    }
  });
});

router.post('/auth/logout', authenticateToken, logout);

export const authRoutes = router;

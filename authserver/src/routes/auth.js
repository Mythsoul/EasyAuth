import express from "express"; 
import { login, register, logout, refreshToken, verifyEmail, resendVerificationEmail, verifyEmailPage, forgotPassword, resetPassword, resetPasswordPage, checkAuthStatus } from "../controllers/AuthController.js";
import { originValidator, strictOriginValidator } from "../middleware/originValidator.js";
import { authenticateToken } from "../middleware/authMiddleware.js";
import { validate, authSchemas } from "../middleware/validation.js";
import { authRateLimit, loginRateLimit } from "../middleware/rateLimiter.js";

const router = express.Router(); 

router.use('/auth/*', originValidator);

// Public routes
router.post('/auth/register', authRateLimit, strictOriginValidator, validate(authSchemas.register), register);
router.post('/auth/login', loginRateLimit, strictOriginValidator, validate(authSchemas.login), login);
router.post('/auth/refresh-token', authRateLimit, validate(authSchemas.refreshToken), refreshToken);

// Auth status check (public - doesn't require authentication)
router.get('/auth/status', authRateLimit, checkAuthStatus);

// Email verification routes
router.get('/verify-email', verifyEmailPage); 
router.post('/auth/verify-email', authRateLimit, strictOriginValidator, validate(authSchemas.verifyEmail), verifyEmail);
router.post('/auth/resend-verification-email', authRateLimit, strictOriginValidator, validate(authSchemas.resendVerification), resendVerificationEmail);

// Password reset routes
router.get('/reset-password', resetPasswordPage);
router.post('/auth/forgot-password', authRateLimit, strictOriginValidator, validate(authSchemas.forgotPassword), forgotPassword);
router.post('/auth/reset-password', authRateLimit, strictOriginValidator, validate(authSchemas.resetPassword), resetPassword);

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

import express from 'express';
import {
  registerUser,
  verifyEmail,
  forgetPassword,
  validateResetToken,
  logoutUser,
  GoogleLogin,
} from '../controllers/authController';
import { protect } from '../middleware/authMiddleware';
import passport from 'passport';


const router = express.Router();

router.post('/register', registerUser);
router.get('/verify-email/:token', verifyEmail);
router.post('/forget-password', forgetPassword);
router.put('/reset-password', validateResetToken);
router.post('/logout', protect, logoutUser);
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback', passport.authenticate('google', { session: false }), GoogleLogin);

export default router;

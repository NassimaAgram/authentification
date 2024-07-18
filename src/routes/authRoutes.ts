import express from 'express';
import {
  registerUser,
  verifyEmail,
  forgetPassword,
  validateResetToken,
  logoutUser,
} from '../controllers/authController';
import { protect } from '../middleware/authMiddleware';

const router = express.Router();

router.post('/register', registerUser);
router.get('/verify-email/:token', verifyEmail);
router.post('/forget-password', forgetPassword);
router.post('/reset-password', validateResetToken);
router.post('/logout', protect, logoutUser);


export default router;

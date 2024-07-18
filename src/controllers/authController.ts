import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import nodemailer from '../config/mailer';
import User, { IUser } from '../models/userModel';

interface EmailOptions {
  email: string;
  subject: string;
  message: string;
}

const generateToken = (userId: string): string => {
  return jwt.sign({ userId }, process.env.JWT_SECRET!, {
    expiresIn: process.env.JWT_EXPIRES_IN!,
  });
};

const sendEmail = async (options: EmailOptions) => {
  try {
    await nodemailer.sendMail({
      from: process.env.MAIL_FROM!,
      to: options.email,
      subject: options.subject,
      html: options.message,
    });
  } catch (error) {
    console.error('Error sending email:', error);
    throw new Error('Failed to send email');
  }
};

export const registerUser = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    let user = await User.findOne({ email });

    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }

    user = new User({ email, password });

    const verificationToken = generateToken(user._id.toString());

    const verificationURL = `${req.protocol}://${req.get('host')}/verify-email/${verificationToken}`;

    const message = `
      <h1>Email Verification</h1>
      <p>Please click <a href="${verificationURL}">here</a> to verify your email.</p>
    `;

    await sendEmail({
      email: user.email,
      subject: 'Verify your email',
      message,
    });

    await user.save();

    res.status(201).json({ message: 'User registered. Verification email sent.' });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ message: 'Server Error' });
  }
};

export const verifyEmail = async (req: Request, res: Response) => {
  const token = req.params.token;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as { userId: string };

    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.emailVerified = true;
    await user.save();

    res.status(200).json({ message: 'Email verified successfully' });
  } catch (error) {
    console.error('Error verifying email:', error);
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

export const forgetPassword = async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const resetToken = Math.floor(1000 + Math.random() * 9000).toString();
    user.resetToken = resetToken;
    user.resetTokenExpires = Date.now() + 10 * 60 * 1000;
    await user.save();

    const message = `
      <h1>Password Reset</h1>
      <p>Your verification code is: <strong>${resetToken}</strong></p>
    `;

    await sendEmail({
      email: user.email,
      subject: 'Password Reset',
      message,
    });

    res.status(200).json({ message: 'Reset password email sent' });
  } catch (error) {
    console.error('Error forgetting password:', error);
    res.status(500).json({ message: 'Server Error' });
  }
};

export const validateResetToken = async (req: Request, res: Response) => {
  const { email, resetToken, newPassword } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.resetToken !== resetToken || user.resetTokenExpires < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpires = undefined;
    await user.save();

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Error validating reset token:', error);
    res.status(500).json({ message: 'Server Error' });
  }
};

export const logoutUser = async (req: Request, res: Response) => {
  try {
    res.clearCookie('jwtToken');
    res.status(200).json({ message: 'Logout successful' });
  } catch (error) {
    console.error('Error logging out user:', error);
    res.status(500).json({ message: 'Server Error' });
  }
};

export const GoogleLogin = (req: Request, res: Response) => {
    const token = generateToken(req.user!._id);
    res.status(200).json({ token });
  };

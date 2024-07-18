import mongoose, { Document, Schema } from 'mongoose';
import bcrypt from 'bcryptjs';

export interface IUser extends Document {
    _id:mongoose.ObjectId;
  email: string;
  password: string;
  resetToken?: string;
  resetTokenExpires?: number;
  emailVerified?: boolean;
  googleId?: string;
}

const userSchema = new Schema<IUser>({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetToken: String,
  resetTokenExpires: Number,
  emailVerified: { type: Boolean, default: false },
  googleId: String,
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const User = mongoose.model<IUser>('User', userSchema);
export default User;

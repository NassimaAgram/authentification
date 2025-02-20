// src/config/passport.ts
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import User, { IUser } from '../models/userModel';

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: '/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
      const { id, emails } = profile;
      const email = emails && emails[0].value;

      try {
        let user = await User.findOne({ googleId: id });

        if (!user) {
          user = await User.findOneAndUpdate(
            { email },
            { googleId: id },
            { new: true, upsert: true }
          );
        }

        done(null, user);
      } catch (error) {
        done(error, undefined);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, (user as IUser)._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

export default passport;

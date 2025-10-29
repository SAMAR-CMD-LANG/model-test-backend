import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { supabase } from "./db.js";
import dotenv from "dotenv";

dotenv.config();

// Configure Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BACKEND_URL}/auth/google/callback`,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0]?.value;
        const name = profile.displayName;
        const profilePicture = profile.photos[0]?.value;

        if (!email) {
          return done(new Error("No email found in Google profile"), null);
        }

        const { data: existingUser, error: fetchError } = await supabase
          .from("Users")
          .select("*")
          .eq("email", email)
          .single();

        if (existingUser && !fetchError) {
          console.log(
            "Google OAuth: User already exists, logging in:",
            existingUser.email
          );
          return done(null, existingUser);
        }

        const { data: newUser, error: createError } = await supabase
          .from("Users")
          .insert([
            {
              name,
              email,
              password: null,
            },
          ])
          .select()
          .single();

        if (createError) {
          console.error("Error creating new user:", createError);
          return done(createError, null);
        }

        console.log("Google OAuth: New user created:", newUser.email);
        return done(null, newUser);
      } catch (error) {
        console.error("Error in Google OAuth strategy:", error);
        return done(error, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { data: user, error } = await supabase
      .from("Users")
      .select("*")
      .eq("id", id)
      .single();

    if (error) {
      return done(error, null);
    }

    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
});

export default passport;

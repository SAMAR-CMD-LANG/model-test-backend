import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { supabase } from "./db.js";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import session from "express-session";
import passport from "./passport-config.js";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import { encryptText, decryptText } from "./utils/encryption.js";
import { sendPasswordResetEmail, sendVerificationEmail } from "./utils/emailService.js";

dotenv.config();

const app = express();


// Simple CORS configuration
app.use(cors({
    origin: [process.env.FRONTEND_URL, 'http://localhost:3000'].filter(Boolean),
    credentials: true,
}));


app.use(express.json());
app.use(cookieParser());

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000,
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // Allow cross-site cookies in production
        },
    })
);


app.use(passport.initialize());
app.use(passport.session());

const PORT = process.env.PORT || 5000;


async function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"] || "";
    const headerToken = authHeader && authHeader.split(" ")[1];
    const cookieToken = req.cookies && req.cookies[process.env.COOKIE_NAME];
    const clientCookieToken = req.cookies && req.cookies[`${process.env.COOKIE_NAME}_client`];
    const token = headerToken || cookieToken || clientCookieToken;

    console.log("Auth check - Header token:", headerToken ? "Present" : "Missing");
    console.log("Auth check - HttpOnly cookie token:", cookieToken ? "Present" : "Missing");
    console.log("Auth check - Client cookie token:", clientCookieToken ? "Present" : "Missing");
    console.log("Auth check - All cookies received:", Object.keys(req.cookies || {}));

    if (!token) {
        console.log("No token found in request");
        return res.status(401).json({ message: "Invalid or no token found" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        console.log("Token verified successfully for user:", decoded.email);
        next();
    } catch (err) {
        console.error("Token verification error:", err);
        return res.status(401).json({ message: "Invalid token" });
    }
}

function generateTokenAndSetCookie(user, res) {
    const token = jwt.sign(
        { id: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "24h" }
    );

    const isProduction = process.env.NODE_ENV === "production";

    console.log("Setting cookie - Production mode:", isProduction);
    console.log("Setting cookie - Frontend URL:", process.env.FRONTEND_URL);

    // Set httpOnly cookie (for same-origin requests)
    res.cookie(process.env.COOKIE_NAME, token, {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: isProduction ? "none" : "lax",
        secure: isProduction,
        path: "/",
    });

    // Set non-httpOnly cookie that frontend can read (for cross-origin)
    res.cookie(`${process.env.COOKIE_NAME}_client`, token, {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: false, // Frontend can read this
        sameSite: isProduction ? "none" : "lax",
        secure: isProduction,
        path: "/",
    });

    return token;
}





app.get("/auth/google",
    passport.authenticate("google", {
        scope: ["profile", "email"]
    })
);


app.get("/auth/google/callback",
    passport.authenticate("google", {
        failureRedirect: `${process.env.FRONTEND_URL}/login?error=oauth_failed`,
        session: false
    }),
    (req, res) => {
        try {
            console.log("Google OAuth callback - user data:", req.user); // Debug log

            if (!req.user) {
                console.error("No user data received from Google OAuth");
                return res.redirect(`${process.env.FRONTEND_URL}/login?error=no_user_data`);
            }


            const token = generateTokenAndSetCookie(req.user, res);

            // For cross-origin issues, include token in redirect URL
            res.redirect(`${process.env.FRONTEND_URL}/dashboard?token=${token}`);
        } catch (error) {
            console.error("Error in Google OAuth callback:", error);

            if (error.message && error.message.includes("migration required")) {
                res.redirect(`${process.env.FRONTEND_URL}/login?error=migration_required`);
            } else {
                res.redirect(`${process.env.FRONTEND_URL}/login?error=oauth_callback_failed`);
            }
        }
    }
);

// ============ REGULAR AUTH ROUTES ============

app.post("/auth/register", async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ message: "All fields are required" });
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ message: "Invalid email format" });
    }

    // Password strength validation
    if (password.length < 6) {
        return res.status(400).json({ message: "Password must be at least 6 characters long" });
    }

    try {
        const { data: existingUser } = await supabase
            .from("Users")
            .select("*")
            .eq("email", email)
            .single();

        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const { data: newUser, error: userError } = await supabase
            .from("Users")
            .insert([{
                name,
                email,
                password: hashedPassword
            }])
            .select()
            .single();

        if (userError) {
            console.error("User creation error:", userError);
            return res.status(500).json({ message: "Error creating user" });
        }

        res.status(201).json({
            message: "User created successfully.",
            user: { id: newUser.id, name: newUser.name, email: newUser.email }
        });
    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Both email and password are required" });
    }

    try {
        const { data: user, error } = await supabase
            .from("Users")
            .select("*")
            .eq("email", email)
            .single();

        if (!user || error) {
            return res.status(400).json({ message: "User not found" });
        }

        // Check if user has a password (not OAuth-only user)
        if (!user.password) {
            return res.status(400).json({
                message: "This account uses Google login. Please sign in with Google."
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        // Generate token and set cookie using helper function
        const token = generateTokenAndSetCookie(user, res);

        res.status(200).json({
            message: "Login successful",
            token: token, // Include token in response for cross-origin issues
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                profile_picture: user.profile_picture
            },
        });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

app.post("/auth/logout", (req, res) => {
    const isProduction = process.env.NODE_ENV === "production";

    // Clear both cookies
    res.clearCookie(process.env.COOKIE_NAME, {
        httpOnly: true,
        sameSite: isProduction ? "none" : "lax",
        secure: isProduction,
        path: "/",
    });

    res.clearCookie(`${process.env.COOKIE_NAME}_client`, {
        httpOnly: false,
        sameSite: isProduction ? "none" : "lax",
        secure: isProduction,
        path: "/",
    });

    res.status(200).json({ message: "logout successful" });
});

// Email verification endpoint
app.post("/auth/verify-email", async (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ message: "Verification token is required" });
    }

    try {
        const { data: user, error } = await supabase
            .from("Users")
            .select("*")
            .eq("verification_token", token)
            .single();

        if (error || !user) {
            return res.status(400).json({ message: "Invalid or expired verification token" });
        }

        if (user.email_verified) {
            return res.status(400).json({ message: "Email already verified" });
        }

        const { error: updateError } = await supabase
            .from("Users")
            .update({
                email_verified: true,
                verification_token: null
            })
            .eq("id", user.id);

        if (updateError) {
            return res.status(500).json({ message: "Error verifying email" });
        }

        res.status(200).json({ message: "Email verified successfully" });
    } catch (err) {
        console.error("Email verification error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Password reset request endpoint
app.post("/auth/forgot-password", async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: "Email is required" });
    }

    try {
        const { data: user, error } = await supabase
            .from("Users")
            .select("*")
            .eq("email", email)
            .single();

        if (error || !user) {
            // Don't reveal if user exists or not for security
            return res.status(200).json({
                message: "If an account with that email exists, a password reset link has been sent."
            });
        }

        const resetToken = uuidv4();
        const resetExpires = new Date(Date.now() + 3600000).toISOString(); // 1 hour

        const { error: updateError } = await supabase
            .from("Users")
            .update({
                reset_token: resetToken,
                reset_expires: resetExpires
            })
            .eq("id", user.id);

        if (updateError) {
            console.error("Error updating reset token:", updateError);
            return res.status(500).json({ message: "Error processing request" });
        }

        const emailSent = await sendPasswordResetEmail(email, resetToken);

        res.status(200).json({
            message: "If an account with that email exists, a password reset link has been sent.",
            emailSent
        });
    } catch (err) {
        console.error("Password reset request error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Password reset endpoint
app.post("/auth/reset-password", async (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        return res.status(400).json({ message: "Token and new password are required" });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({ message: "Password must be at least 6 characters long" });
    }

    try {
        const { data: user, error } = await supabase
            .from("Users")
            .select("*")
            .eq("reset_token", token)
            .single();

        if (error || !user) {
            return res.status(400).json({ message: "Invalid or expired reset token" });
        }

        // Check if token is expired
        if (new Date() > new Date(user.reset_expires)) {
            return res.status(400).json({ message: "Reset token has expired" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        const { error: updateError } = await supabase
            .from("Users")
            .update({
                password: hashedPassword,
                reset_token: null,
                reset_expires: null
            })
            .eq("id", user.id);

        if (updateError) {
            return res.status(500).json({ message: "Error resetting password" });
        }

        res.status(200).json({ message: "Password reset successfully" });
    } catch (err) {
        console.error("Password reset error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});
app.get("/auth/me", async (req, res) => {
    try {
        const cookieToken = req.cookies && req.cookies[process.env.COOKIE_NAME];
        if (!cookieToken) {
            return res.status(401).json({ user: null });
        }

        const decoded = jwt.verify(cookieToken, process.env.JWT_SECRET);
        const { data: user, error } = await supabase
            .from("Users")
            .select("id, name, email, created_at")
            .eq("id", decoded.id)
            .single();

        if (error || !user) {
            return res.status(401).json({ user: null });
        }

        res.json({
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                created_at: user.created_at
            }
        });
    } catch (err) {
        console.error("Auth me error:", err);
        res.status(401).json({ user: null });
    }
});
// ============ NOTES ROUTES ============

// Get all notes for authenticated user
app.get("/notes", authenticateToken, async (req, res) => {
    try {
        let page = parseInt(req.query.page) || 1;
        let limit = parseInt(req.query.limit) || 10;
        const search = req.query.search || "";
        const visibility = req.query.visibility || "all"; // all, public, private
        const sortBy = req.query.sortBy || "updated_at"; // created_at, updated_at, title
        const sortOrder = req.query.sortOrder || "desc"; // asc, desc

        if (page < 1) page = 1;
        limit = Math.min(limit, 100);

        const start = (page - 1) * limit;
        const end = start + limit - 1;

        // Build the select query
        let query = supabase
            .from("Posts")
            .select("*", { count: "exact" })
            .eq("user_id", req.user.id);

        // Apply search filter
        if (search) {
            query = query.or(`title.ilike.%${search}%,body.ilike.%${search}%`);
        }

        // Apply visibility filter
        if (visibility !== "all") {
            query = query.eq("is_public", visibility === "public");
        }

        // Apply sorting
        const validSortFields = ["created_at", "updated_at", "title"];
        const sortField = validSortFields.includes(sortBy) ? sortBy : "updated_at";
        const ascending = sortOrder === "asc";

        query = query.order(sortField, { ascending });

        // Apply pagination
        query = query.range(start, end);

        const { data: notes, count, error } = await query;

        if (error) {
            return res.status(500).json({ message: "Error fetching notes", error });
        }

        // Transform and decrypt notes (simplified for current database structure)
        const decryptedNotes = notes.map(note => {
            let content = note.body;

            if (note.encrypted_content) {
                try {
                    const decryptedContent = decryptText(JSON.parse(note.encrypted_content));
                    content = decryptedContent;
                } catch (err) {
                    console.error("Decryption error for note:", note.id);
                    content = "Error decrypting content";
                }
            }

            return {
                ...note,
                content: content,
                body: undefined,
                encrypted_content: undefined
            };
        });

        res.json({
            notes: decryptedNotes,
            totalNotes: count || 0,
            totalPages: Math.ceil((count || 0) / limit),
            currentPage: page,
            filters: {
                search,
                visibility,
                sortBy: sortField,
                sortOrder
            }
        });
    } catch (err) {
        console.error("Notes fetch error:", err);
        res.status(500).json({ message: "Notes fetch failed on server" });
    }
});

// Get public notes (no authentication required)
app.get("/notes/public", async (req, res) => {
    try {
        let page = parseInt(req.query.page) || 1;
        let limit = parseInt(req.query.limit) || 10;
        const search = req.query.search || "";

        if (page < 1) page = 1;
        limit = Math.min(limit, 100);

        const start = (page - 1) * limit;
        const end = start + limit - 1;

        let query = supabase
            .from("Posts")
            .select("id, title, body, created_at, user_id, Users(name)", { count: "exact" })
            .order("created_at", { ascending: false });

        if (search) {
            query = query.ilike("title", `%${search}%`);
        }

        query = query.range(start, end);
        const { data: notes, count, error } = await query;

        if (error) {
            return res.status(500).json({ message: "Error fetching public notes", error });
        }

        // Transform body to content for consistency
        const transformedNotes = notes.map(note => ({
            ...note,
            content: note.body,
            body: undefined
        }));

        res.json({
            notes: transformedNotes,
            totalNotes: count || 0,
            totalPages: Math.ceil((count || 0) / limit),
            currentPage: page,
        });
    } catch (err) {
        console.error("Public notes fetch error:", err);
        res.status(500).json({ message: "Public notes fetch failed" });
    }
});
// Create a new note
app.post("/notes", authenticateToken, async (req, res) => {
    const {
        title,
        content,
        isPublic = false,
        isDraft = false
    } = req.body;

    if (!title || !content) {
        return res.status(400).json({ message: "Title and content are required" });
    }

    try {
        // Encrypt content
        const encryptedContent = encryptText(content);

        const noteData = {
            title,
            body: content,
            user_id: req.user.id
        };

        // Add optional fields only if they exist in database
        // These will work after running the database update script
        if (typeof isPublic !== 'undefined') noteData.is_public = isPublic;
        if (typeof isDraft !== 'undefined') noteData.is_draft = isDraft;
        // categoryId, priority, archived will be added after database update

        // Add encrypted content if encryption is enabled
        if (encryptedContent) {
            noteData.encrypted_content = JSON.stringify(encryptedContent);
        }

        const { data: note, error } = await supabase
            .from("Posts")
            .insert([noteData])
            .select()
            .single();

        if (error) {
            console.error("Note creation error:", error);
            return res.status(500).json({ message: "Error creating note", error });
        }

        // Return the basic note structure
        const responseNote = {
            ...note,
            content: content,
            body: undefined,
            encrypted_content: undefined
        };

        res.status(201).json({
            message: "Note created successfully",
            note: responseNote
        });
    } catch (err) {
        console.error("Note creation error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Update a note
app.put("/notes/:id", authenticateToken, async (req, res) => {
    const noteId = req.params.id;
    const {
        title,
        content,
        isPublic,
        isDraft
    } = req.body;

    if (!title || !content) {
        return res.status(400).json({ message: "Title and content are required" });
    }

    try {
        // First check if note exists and belongs to user
        const { data: existingNote, error: fetchError } = await supabase
            .from("Posts")
            .select("*")
            .eq("id", noteId)
            .eq("user_id", req.user.id)
            .single();

        if (fetchError || !existingNote) {
            return res.status(404).json({ message: "Note not found or not authorized" });
        }

        // Encrypt content
        const encryptedContent = encryptText(content);

        const updateData = {
            title,
            body: content
        };

        // Add encrypted content if encryption is enabled
        if (encryptedContent) {
            updateData.encrypted_content = JSON.stringify(encryptedContent);
        }

        // Update optional fields if provided (only if columns exist)
        if (typeof isPublic !== 'undefined') updateData.is_public = isPublic;
        if (typeof isDraft !== 'undefined') updateData.is_draft = isDraft;
        // categoryId, priority, archived will work after database update

        const { data: updatedNote, error } = await supabase
            .from("Posts")
            .update(updateData)
            .select()
            .eq("id", noteId)
            .eq("user_id", req.user.id)
            .single();

        if (error) {
            console.error("Note update error:", error);
            return res.status(500).json({ message: "Error updating note" });
        }

        // Return the basic note structure
        const responseNote = {
            ...updatedNote,
            content: content,
            body: undefined,
            encrypted_content: undefined
        };

        res.status(200).json({
            message: "Note updated successfully",
            note: responseNote
        });
    } catch (err) {
        console.error("Note update error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Delete a note
app.delete("/notes/:id", authenticateToken, async (req, res) => {
    const noteId = req.params.id;

    try {
        const { data: deletedNote, error } = await supabase
            .from("Posts")
            .delete()
            .eq("id", noteId)
            .eq("user_id", req.user.id)
            .select()
            .single();

        if (error) {
            return res.status(404).json({ message: "Note not found or not authorized to delete" });
        }

        res.status(200).json({
            message: "Note deleted successfully",
            note: deletedNote
        });
    } catch (err) {
        console.error("Note deletion error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Get a single note by ID
app.get("/notes/:id", authenticateToken, async (req, res) => {
    const noteId = req.params.id;

    try {
        const { data: note, error } = await supabase
            .from("Posts")
            .select("*")
            .eq("id", noteId)
            .eq("user_id", req.user.id)
            .single();

        if (error || !note) {
            return res.status(404).json({ message: "Note not found" });
        }

        // Decrypt content if encrypted, otherwise use body
        let decryptedContent = note.body;
        if (note.encrypted_content) {
            try {
                decryptedContent = decryptText(JSON.parse(note.encrypted_content));
            } catch (err) {
                console.error("Decryption error for note:", note.id);
                decryptedContent = "Error decrypting content";
            }
        }

        const responseNote = {
            ...note,
            content: decryptedContent,
            body: undefined,
            encrypted_content: undefined
        };

        res.json({ note: responseNote });
    } catch (err) {
        console.error("Note fetch error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Auto-save draft endpoint
app.post("/notes/:id/autosave", authenticateToken, async (req, res) => {
    const noteId = req.params.id;
    const { title, content } = req.body;

    try {
        // Check if note exists and belongs to user
        const { data: existingNote, error: fetchError } = await supabase
            .from("Posts")
            .select("*")
            .eq("id", noteId)
            .eq("user_id", req.user.id)
            .single();

        if (fetchError || !existingNote) {
            return res.status(404).json({ message: "Note not found" });
        }

        // Encrypt content
        const encryptedContent = encryptText(content);

        const updateData = {
            title: title || existingNote.title,
            body: content
        };

        if (encryptedContent) {
            updateData.encrypted_content = JSON.stringify(encryptedContent);
        }

        const { error } = await supabase
            .from("Posts")
            .update(updateData)
            .eq("id", noteId)
            .eq("user_id", req.user.id);

        if (error) {
            console.error("Auto-save error:", error);
            return res.status(500).json({ message: "Error auto-saving note" });
        }

        res.status(200).json({ message: "Note auto-saved successfully" });
    } catch (err) {
        console.error("Auto-save error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// ============ FEATURE STATUS ENDPOINT ============

// Get feature availability status
app.get("/features", authenticateToken, async (req, res) => {
    res.json({
        available: {
            basicNotes: true,
            noteEncryption: true,
            userAuthentication: true,
            passwordReset: true,
            googleOAuth: true,
            sorting: true,
            basicFiltering: true,
            pagination: true
        },
        requiresDatabaseUpdate: {
            categories: true,
            labels: true,
            advancedFiltering: true,
            notePriority: true,
            noteArchiving: true,
            fullTextSearch: true,
            bulkOperations: true
        },
        message: "Run the SQL script in simple-database-updates.sql to enable advanced features.",
        databaseUpdateScript: "simple-database-updates.sql"
    });
});

// ============ CATEGORIES ROUTES (Requires Database Update) ============

// Get all categories for authenticated user
app.get("/categories", authenticateToken, async (req, res) => {
    return res.status(501).json({
        message: "Categories feature requires database update. Please run the SQL script in simple-database-updates.sql first.",
        script: "simple-database-updates.sql"
    });
    try {
        const { data: categories, error } = await supabase
            .from("Categories")
            .select("*")
            .eq("user_id", req.user.id)
            .order("name", { ascending: true });

        if (error) {
            return res.status(500).json({ message: "Error fetching categories", error });
        }

        res.json({ categories });
    } catch (err) {
        console.error("Categories fetch error:", err);
        res.status(500).json({ message: "Categories fetch failed" });
    }
});

// Create a new category
app.post("/categories", authenticateToken, async (req, res) => {
    const { name, description, color = '#6B7280', icon = 'folder' } = req.body;

    if (!name) {
        return res.status(400).json({ message: "Category name is required" });
    }

    try {
        const { data: category, error } = await supabase
            .from("Categories")
            .insert([{
                name: name.trim(),
                description: description?.trim(),
                color,
                icon,
                user_id: req.user.id
            }])
            .select()
            .single();

        if (error) {
            if (error.code === '23505') { // Unique constraint violation
                return res.status(400).json({ message: "Category name already exists" });
            }
            return res.status(500).json({ message: "Error creating category", error });
        }

        res.status(201).json({
            message: "Category created successfully",
            category
        });
    } catch (err) {
        console.error("Category creation error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Update a category
app.put("/categories/:id", authenticateToken, async (req, res) => {
    const categoryId = req.params.id;
    const { name, description, color, icon } = req.body;

    if (!name) {
        return res.status(400).json({ message: "Category name is required" });
    }

    try {
        const { data: updatedCategory, error } = await supabase
            .from("Categories")
            .update({
                name: name.trim(),
                description: description?.trim(),
                color,
                icon,
                updated_at: new Date().toISOString()
            })
            .eq("id", categoryId)
            .eq("user_id", req.user.id)
            .select()
            .single();

        if (error) {
            if (error.code === '23505') {
                return res.status(400).json({ message: "Category name already exists" });
            }
            return res.status(404).json({ message: "Category not found or not authorized" });
        }

        res.json({
            message: "Category updated successfully",
            category: updatedCategory
        });
    } catch (err) {
        console.error("Category update error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Delete a category
app.delete("/categories/:id", authenticateToken, async (req, res) => {
    const categoryId = req.params.id;

    try {
        const { data: deletedCategory, error } = await supabase
            .from("Categories")
            .delete()
            .eq("id", categoryId)
            .eq("user_id", req.user.id)
            .select()
            .single();

        if (error) {
            return res.status(404).json({ message: "Category not found or not authorized" });
        }

        res.json({
            message: "Category deleted successfully",
            category: deletedCategory
        });
    } catch (err) {
        console.error("Category deletion error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// ============ NOTE LABEL MANAGEMENT ============

// Add labels to a note
app.post("/notes/:id/labels", authenticateToken, async (req, res) => {
    const noteId = req.params.id;
    const { labelIds } = req.body;

    if (!labelIds || !Array.isArray(labelIds) || labelIds.length === 0) {
        return res.status(400).json({ message: "Label IDs array is required" });
    }

    try {
        // Verify note ownership
        const { data: note, error: noteError } = await supabase
            .from("Posts")
            .select("id")
            .eq("id", noteId)
            .eq("user_id", req.user.id)
            .single();

        if (noteError || !note) {
            return res.status(404).json({ message: "Note not found or not authorized" });
        }

        // Verify label ownership
        const { data: labels, error: labelsError } = await supabase
            .from("Labels")
            .select("id")
            .in("id", labelIds)
            .eq("user_id", req.user.id);

        if (labelsError || labels.length !== labelIds.length) {
            return res.status(400).json({ message: "One or more labels not found or not authorized" });
        }

        // Insert label associations (ignore duplicates)
        const labelInserts = labelIds.map(labelId => ({
            post_id: noteId,
            label_id: labelId
        }));

        const { error: insertError } = await supabase
            .from("PostLabels")
            .upsert(labelInserts, { onConflict: 'post_id,label_id' });

        if (insertError) {
            return res.status(500).json({ message: "Error adding labels to note" });
        }

        res.json({ message: "Labels added to note successfully" });
    } catch (err) {
        console.error("Add labels error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Remove labels from a note
app.delete("/notes/:id/labels", authenticateToken, async (req, res) => {
    const noteId = req.params.id;
    const { labelIds } = req.body;

    if (!labelIds || !Array.isArray(labelIds) || labelIds.length === 0) {
        return res.status(400).json({ message: "Label IDs array is required" });
    }

    try {
        // Verify note ownership
        const { data: note, error: noteError } = await supabase
            .from("Posts")
            .select("id")
            .eq("id", noteId)
            .eq("user_id", req.user.id)
            .single();

        if (noteError || !note) {
            return res.status(404).json({ message: "Note not found or not authorized" });
        }

        // Remove label associations
        const { error: deleteError } = await supabase
            .from("PostLabels")
            .delete()
            .eq("post_id", noteId)
            .in("label_id", labelIds);

        if (deleteError) {
            return res.status(500).json({ message: "Error removing labels from note" });
        }

        res.json({ message: "Labels removed from note successfully" });
    } catch (err) {
        console.error("Remove labels error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// ============ LABELS ROUTES ============

// Get all labels for authenticated user
app.get("/labels", authenticateToken, async (req, res) => {
    try {
        const { data: labels, error } = await supabase
            .from("Labels")
            .select("*")
            .eq("user_id", req.user.id)
            .order("name", { ascending: true });

        if (error) {
            return res.status(500).json({ message: "Error fetching labels", error });
        }

        res.json({ labels });
    } catch (err) {
        console.error("Labels fetch error:", err);
        res.status(500).json({ message: "Labels fetch failed" });
    }
});

// Create a new label
app.post("/labels", authenticateToken, async (req, res) => {
    const { name, color = '#3B82F6' } = req.body;

    if (!name) {
        return res.status(400).json({ message: "Label name is required" });
    }

    try {
        const { data: label, error } = await supabase
            .from("Labels")
            .insert([{
                name: name.trim(),
                color,
                user_id: req.user.id
            }])
            .select()
            .single();

        if (error) {
            if (error.code === '23505') {
                return res.status(400).json({ message: "Label name already exists" });
            }
            return res.status(500).json({ message: "Error creating label", error });
        }

        res.status(201).json({
            message: "Label created successfully",
            label
        });
    } catch (err) {
        console.error("Label creation error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Update a label
app.put("/labels/:id", authenticateToken, async (req, res) => {
    const labelId = req.params.id;
    const { name, color } = req.body;

    if (!name) {
        return res.status(400).json({ message: "Label name is required" });
    }

    try {
        const { data: updatedLabel, error } = await supabase
            .from("Labels")
            .update({
                name: name.trim(),
                color
            })
            .eq("id", labelId)
            .eq("user_id", req.user.id)
            .select()
            .single();

        if (error) {
            if (error.code === '23505') {
                return res.status(400).json({ message: "Label name already exists" });
            }
            return res.status(404).json({ message: "Label not found or not authorized" });
        }

        res.json({
            message: "Label updated successfully",
            label: updatedLabel
        });
    } catch (err) {
        console.error("Label update error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Delete a label
app.delete("/labels/:id", authenticateToken, async (req, res) => {
    const labelId = req.params.id;

    try {
        const { data: deletedLabel, error } = await supabase
            .from("Labels")
            .delete()
            .eq("id", labelId)
            .eq("user_id", req.user.id)
            .select()
            .single();

        if (error) {
            return res.status(404).json({ message: "Label not found or not authorized" });
        }

        res.json({
            message: "Label deleted successfully",
            label: deletedLabel
        });
    } catch (err) {
        console.error("Label deletion error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// ============ ADVANCED SEARCH & ANALYTICS ============

// Advanced search with full-text search
app.get("/notes/search", authenticateToken, async (req, res) => {
    try {
        const {
            q: searchQuery,
            page = 1,
            limit = 10,
            categoryId,
            labelIds,
            priority,
            archived = false
        } = req.query;

        if (!searchQuery) {
            return res.status(400).json({ message: "Search query is required" });
        }

        const start = (parseInt(page) - 1) * parseInt(limit);
        const end = start + parseInt(limit) - 1;

        // Use full-text search
        let query = supabase
            .from("Posts")
            .select(`
            *,
            Categories(id, name, color, icon),
            PostLabels(Labels(id, name, color))
        `, { count: "exact" })
            .eq("user_id", req.user.id)
            .eq("archived", archived === "true")
            .textSearch("title", searchQuery, { type: "websearch" });

        // Apply additional filters
        if (categoryId) query = query.eq("category_id", categoryId);
        if (priority) query = query.eq("priority", priority);

        query = query.order("updated_at", { ascending: false })
            .range(start, end);

        const { data: notes, count, error } = await query;

        if (error) {
            return res.status(500).json({ message: "Search failed", error });
        }

        // Filter by labels if specified
        let filteredNotes = notes;
        if (labelIds) {
            const labelIdArray = labelIds.split(',').map(id => parseInt(id));
            filteredNotes = notes.filter(note => {
                const noteLabels = note.PostLabels?.map(pl => pl.Labels?.id) || [];
                return labelIdArray.every(labelId => noteLabels.includes(labelId));
            });
        }

        // Transform notes
        const transformedNotes = filteredNotes.map(note => {
            let content = note.body;
            if (note.encrypted_content) {
                try {
                    content = decryptText(JSON.parse(note.encrypted_content));
                } catch (err) {
                    content = "Error decrypting content";
                }
            }

            const labels = note.PostLabels?.map(pl => pl.Labels).filter(Boolean) || [];
            return {
                ...note,
                content,
                body: undefined,
                encrypted_content: undefined,
                category: note.Categories,
                Categories: undefined,
                labels,
                PostLabels: undefined
            };
        });

        res.json({
            notes: transformedNotes,
            totalNotes: count || 0,
            totalPages: Math.ceil((count || 0) / parseInt(limit)),
            currentPage: parseInt(page),
            searchQuery
        });
    } catch (err) {
        console.error("Search error:", err);
        res.status(500).json({ message: "Search failed" });
    }
});

// Get user statistics
app.get("/stats", authenticateToken, async (req, res) => {
    try {
        // Get total notes count
        const { count: totalNotes } = await supabase
            .from("Posts")
            .select("*", { count: "exact", head: true })
            .eq("user_id", req.user.id)
            .eq("archived", false);

        // Get archived notes count
        const { count: archivedNotes } = await supabase
            .from("Posts")
            .select("*", { count: "exact", head: true })
            .eq("user_id", req.user.id)
            .eq("archived", true);

        // Get draft notes count
        const { count: draftNotes } = await supabase
            .from("Posts")
            .select("*", { count: "exact", head: true })
            .eq("user_id", req.user.id)
            .eq("is_draft", true);

        // Get public notes count
        const { count: publicNotes } = await supabase
            .from("Posts")
            .select("*", { count: "exact", head: true })
            .eq("user_id", req.user.id)
            .eq("is_public", true);

        // Get categories count
        const { count: totalCategories } = await supabase
            .from("Categories")
            .select("*", { count: "exact", head: true })
            .eq("user_id", req.user.id);

        // Get labels count
        const { count: totalLabels } = await supabase
            .from("Labels")
            .select("*", { count: "exact", head: true })
            .eq("user_id", req.user.id);

        // Get notes by priority
        const { data: priorityStats } = await supabase
            .from("Posts")
            .select("priority")
            .eq("user_id", req.user.id)
            .eq("archived", false);

        const priorityDistribution = [0, 1, 2, 3, 4, 5].map(priority => ({
            priority,
            count: priorityStats?.filter(note => note.priority === priority).length || 0
        }));

        // Get recent activity (notes created in last 7 days)
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

        const { count: recentNotes } = await supabase
            .from("Posts")
            .select("*", { count: "exact", head: true })
            .eq("user_id", req.user.id)
            .gte("created_at", sevenDaysAgo.toISOString());

        res.json({
            totalNotes: totalNotes || 0,
            archivedNotes: archivedNotes || 0,
            draftNotes: draftNotes || 0,
            publicNotes: publicNotes || 0,
            totalCategories: totalCategories || 0,
            totalLabels: totalLabels || 0,
            recentNotes: recentNotes || 0,
            priorityDistribution
        });
    } catch (err) {
        console.error("Stats error:", err);
        res.status(500).json({ message: "Failed to fetch statistics" });
    }
});

// Bulk operations
app.post("/notes/bulk", authenticateToken, async (req, res) => {
    const { action, noteIds, data } = req.body;

    if (!action || !noteIds || !Array.isArray(noteIds)) {
        return res.status(400).json({ message: "Action and note IDs are required" });
    }

    try {
        let updateData = {};
        let message = "";

        switch (action) {
            case "archive":
                updateData = { archived: true };
                message = "Notes archived successfully";
                break;
            case "unarchive":
                updateData = { archived: false };
                message = "Notes unarchived successfully";
                break;
            case "delete":
                const { error: deleteError } = await supabase
                    .from("Posts")
                    .delete()
                    .in("id", noteIds)
                    .eq("user_id", req.user.id);

                if (deleteError) {
                    return res.status(500).json({ message: "Error deleting notes" });
                }
                return res.json({ message: "Notes deleted successfully" });
            case "category":
                if (!data?.categoryId) {
                    return res.status(400).json({ message: "Category ID is required" });
                }
                updateData = { category_id: data.categoryId };
                message = "Notes category updated successfully";
                break;
            case "priority":
                if (data?.priority === undefined) {
                    return res.status(400).json({ message: "Priority is required" });
                }
                updateData = { priority: Math.max(0, Math.min(5, data.priority)) };
                message = "Notes priority updated successfully";
                break;
            default:
                return res.status(400).json({ message: "Invalid action" });
        }

        if (Object.keys(updateData).length > 0) {
            const { error } = await supabase
                .from("Posts")
                .update(updateData)
                .in("id", noteIds)
                .eq("user_id", req.user.id);

            if (error) {
                return res.status(500).json({ message: "Error updating notes" });
            }
        }

        res.json({ message });
    } catch (err) {
        console.error("Bulk operation error:", err);
        res.status(500).json({ message: "Bulk operation failed" });
    }
});

// Change Password Endpoint
app.post("/auth/change-password", authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ message: "Current password and new password are required" });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ message: "New password must be at least 6 characters long" });
        }

        // Get user's current password hash
        const { data: user, error: userError } = await supabase
            .from("Users")
            .select("password")
            .eq("id", req.user.id)
            .single();

        if (userError || !user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Verify current password
        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
        if (!isCurrentPasswordValid) {
            return res.status(400).json({ message: "Current password is incorrect" });
        }

        // Hash new password
        const saltRounds = 12;
        const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

        // Update password in database
        const { error: updateError } = await supabase
            .from("Users")
            .update({ password: hashedNewPassword })
            .eq("id", req.user.id);

        if (updateError) {
            console.error("Password update error:", updateError);
            return res.status(500).json({ message: "Failed to update password" });
        }

        res.json({ message: "Password changed successfully" });
    } catch (error) {
        console.error("Change password error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Health check endpoint
app.get("/health", (req, res) => {
    res.json({
        status: "OK",
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        cors_origins: allowedOrigins,
        frontend_url: process.env.FRONTEND_URL
    });
});

// Debug endpoint to check authentication
app.get("/debug/auth", (req, res) => {
    const authHeader = req.headers["authorization"] || "";
    const headerToken = authHeader && authHeader.split(" ")[1];
    const cookieToken = req.cookies && req.cookies[process.env.COOKIE_NAME];

    res.json({
        hasAuthHeader: !!authHeader,
        hasHeaderToken: !!headerToken,
        hasCookieToken: !!cookieToken,
        cookies: Object.keys(req.cookies || {}),
        headers: {
            origin: req.headers.origin,
            referer: req.headers.referer,
            'user-agent': req.headers['user-agent']
        },
        environment: process.env.NODE_ENV,
        cookieName: process.env.COOKIE_NAME,
        frontendUrl: process.env.FRONTEND_URL,
        backendUrl: process.env.BACKEND_URL
    });
});

// Test login endpoint for debugging
app.post("/debug/test-login", async (req, res) => {
    try {
        // Create a test token
        const testUser = { id: 1, email: 'test@example.com' };
        const token = jwt.sign(testUser, process.env.JWT_SECRET, { expiresIn: "24h" });

        const isProduction = process.env.NODE_ENV === "production";

        res.cookie(process.env.COOKIE_NAME, token, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: true,
            sameSite: isProduction ? "none" : "lax",
            secure: isProduction,
            path: "/",
        });

        res.json({
            message: "Test login successful",
            token: token,
            user: testUser,
            cookieSettings: {
                sameSite: isProduction ? "none" : "lax",
                secure: isProduction,
                httpOnly: true
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`server running on port ${PORT}`);
});

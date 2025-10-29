-- Database setup for Notes App
-- Run this in your Supabase SQL editor

-- First, let's update the Users table to include new fields
ALTER TABLE "Users" 
ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS verification_token TEXT,
ADD COLUMN IF NOT EXISTS reset_token TEXT,
ADD COLUMN IF NOT EXISTS reset_expires TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS profile_picture TEXT,
ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW(),
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- Create Notes table
CREATE TABLE IF NOT EXISTS "Notes" (
    id BIGSERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    content TEXT, -- Plain text content for public notes (for search)
    encrypted_content TEXT, -- Encrypted content JSON
    user_id BIGINT NOT NULL REFERENCES "Users"(id) ON DELETE CASCADE,
    is_public BOOLEAN DEFAULT FALSE,
    is_draft BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_notes_user_id ON "Notes"(user_id);
CREATE INDEX IF NOT EXISTS idx_notes_public ON "Notes"(is_public) WHERE is_public = TRUE;
CREATE INDEX IF NOT EXISTS idx_notes_updated_at ON "Notes"(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_notes_title_search ON "Notes" USING gin(to_tsvector('english', title));

-- Create RLS (Row Level Security) policies
ALTER TABLE "Notes" ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their own notes
CREATE POLICY "Users can view own notes" ON "Notes"
    FOR SELECT USING (auth.uid()::text = user_id::text OR is_public = TRUE);

-- Policy: Users can only insert their own notes
CREATE POLICY "Users can insert own notes" ON "Notes"
    FOR INSERT WITH CHECK (auth.uid()::text = user_id::text);

-- Policy: Users can only update their own notes
CREATE POLICY "Users can update own notes" ON "Notes"
    FOR UPDATE USING (auth.uid()::text = user_id::text);

-- Policy: Users can only delete their own notes
CREATE POLICY "Users can delete own notes" ON "Notes"
    FOR DELETE USING (auth.uid()::text = user_id::text);

-- Create a function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to automatically update updated_at
CREATE TRIGGER update_notes_updated_at 
    BEFORE UPDATE ON "Notes" 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Create trigger for Users table as well
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON "Users" 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Grant necessary permissions
GRANT ALL ON "Notes" TO authenticated;
GRANT ALL ON "Users" TO authenticated;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO authenticated;
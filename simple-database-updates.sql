-- Enhanced database updates for notes app with labels and categories
-- Run this in your Supabase SQL editor

-- Add columns to Users table for password reset functionality
ALTER TABLE "Users" 
ADD COLUMN IF NOT EXISTS reset_token TEXT,
ADD COLUMN IF NOT EXISTS reset_expires TIMESTAMPTZ;

-- Add columns to Posts table for notes functionality
ALTER TABLE "Posts" 
ADD COLUMN IF NOT EXISTS encrypted_content TEXT,
ADD COLUMN IF NOT EXISTS is_public BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS is_draft BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS category_id BIGINT,
ADD COLUMN IF NOT EXISTS priority INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS archived BOOLEAN DEFAULT FALSE;

-- Create Categories table
CREATE TABLE IF NOT EXISTS "Categories" (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    color VARCHAR(7) DEFAULT '#6B7280', -- Hex color code
    icon VARCHAR(50) DEFAULT 'folder',
    user_id BIGINT NOT NULL REFERENCES "Users"(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(name, user_id) -- User can't have duplicate category names
);

-- Create Labels table
CREATE TABLE IF NOT EXISTS "Labels" (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    color VARCHAR(7) DEFAULT '#3B82F6', -- Hex color code
    user_id BIGINT NOT NULL REFERENCES "Users"(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(name, user_id) -- User can't have duplicate label names
);

-- Create junction table for Posts-Labels (many-to-many)
CREATE TABLE IF NOT EXISTS "PostLabels" (
    id BIGSERIAL PRIMARY KEY,
    post_id BIGINT NOT NULL REFERENCES "Posts"(id) ON DELETE CASCADE,
    label_id BIGINT NOT NULL REFERENCES "Labels"(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(post_id, label_id) -- Prevent duplicate label assignments
);

-- Add foreign key constraint for category
ALTER TABLE "Posts" 
ADD CONSTRAINT fk_posts_category 
FOREIGN KEY (category_id) REFERENCES "Categories"(id) ON DELETE SET NULL;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_posts_category_id ON "Posts"(category_id);
CREATE INDEX IF NOT EXISTS idx_posts_archived ON "Posts"(archived);
CREATE INDEX IF NOT EXISTS idx_posts_priority ON "Posts"(priority DESC);
CREATE INDEX IF NOT EXISTS idx_posts_user_created ON "Posts"(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_user_updated ON "Posts"(user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_categories_user_id ON "Categories"(user_id);
CREATE INDEX IF NOT EXISTS idx_labels_user_id ON "Labels"(user_id);
CREATE INDEX IF NOT EXISTS idx_postlabels_post_id ON "PostLabels"(post_id);
CREATE INDEX IF NOT EXISTS idx_postlabels_label_id ON "PostLabels"(label_id);

-- Create full-text search index for better search performance
CREATE INDEX IF NOT EXISTS idx_posts_search ON "Posts" USING gin(to_tsvector('english', title || ' ' || COALESCE(body, '')));

-- Enable RLS (Row Level Security) for new tables
ALTER TABLE "Categories" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Labels" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PostLabels" ENABLE ROW LEVEL SECURITY;

-- RLS Policies for Categories
CREATE POLICY "Users can view own categories" ON "Categories"
    FOR SELECT USING (auth.uid()::text = user_id::text);

CREATE POLICY "Users can insert own categories" ON "Categories"
    FOR INSERT WITH CHECK (auth.uid()::text = user_id::text);

CREATE POLICY "Users can update own categories" ON "Categories"
    FOR UPDATE USING (auth.uid()::text = user_id::text);

CREATE POLICY "Users can delete own categories" ON "Categories"
    FOR DELETE USING (auth.uid()::text = user_id::text);

-- RLS Policies for Labels
CREATE POLICY "Users can view own labels" ON "Labels"
    FOR SELECT USING (auth.uid()::text = user_id::text);

CREATE POLICY "Users can insert own labels" ON "Labels"
    FOR INSERT WITH CHECK (auth.uid()::text = user_id::text);

CREATE POLICY "Users can update own labels" ON "Labels"
    FOR UPDATE USING (auth.uid()::text = user_id::text);

CREATE POLICY "Users can delete own labels" ON "Labels"
    FOR DELETE USING (auth.uid()::text = user_id::text);

-- RLS Policies for PostLabels
CREATE POLICY "Users can view own post labels" ON "PostLabels"
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM "Posts" 
            WHERE "Posts".id = "PostLabels".post_id 
            AND "Posts".user_id::text = auth.uid()::text
        )
    );

CREATE POLICY "Users can insert own post labels" ON "PostLabels"
    FOR INSERT WITH CHECK (
        EXISTS (
            SELECT 1 FROM "Posts" 
            WHERE "Posts".id = "PostLabels".post_id 
            AND "Posts".user_id::text = auth.uid()::text
        )
    );

CREATE POLICY "Users can delete own post labels" ON "PostLabels"
    FOR DELETE USING (
        EXISTS (
            SELECT 1 FROM "Posts" 
            WHERE "Posts".id = "PostLabels".post_id 
            AND "Posts".user_id::text = auth.uid()::text
        )
    );

-- Create triggers for updated_at timestamps
CREATE TRIGGER update_categories_updated_at 
    BEFORE UPDATE ON "Categories" 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions
GRANT ALL ON "Categories" TO authenticated;
GRANT ALL ON "Labels" TO authenticated;
GRANT ALL ON "PostLabels" TO authenticated;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO authenticated;

-- Insert some default categories for new users (optional)
-- You can customize these or remove them
INSERT INTO "Categories" (name, description, color, icon, user_id) 
SELECT 
    'Personal', 'Personal notes and thoughts', '#10B981', 'user', id
FROM "Users" 
WHERE NOT EXISTS (
    SELECT 1 FROM "Categories" 
    WHERE "Categories".user_id = "Users".id 
    AND "Categories".name = 'Personal'
);

INSERT INTO "Categories" (name, description, color, icon, user_id) 
SELECT 
    'Work', 'Work-related notes and tasks', '#3B82F6', 'briefcase', id
FROM "Users" 
WHERE NOT EXISTS (
    SELECT 1 FROM "Categories" 
    WHERE "Categories".user_id = "Users".id 
    AND "Categories".name = 'Work'
);

INSERT INTO "Categories" (name, description, color, icon, user_id) 
SELECT 
    'Ideas', 'Creative ideas and inspiration', '#F59E0B', 'lightbulb', id
FROM "Users" 
WHERE NOT EXISTS (
    SELECT 1 FROM "Categories" 
    WHERE "Categories".user_id = "Users".id 
    AND "Categories".name = 'Ideas'
);
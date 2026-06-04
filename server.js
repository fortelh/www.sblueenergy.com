const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');

const app = express();
const db = new sqlite3.Database('./database.db');

// --- 1. SYSTEM CONFIGURATION & MIDDLEWARE ---
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: 'sblue_enterprise_secret_2026',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000, path: '/', httpOnly: true }
}));

// --- 2. STORAGE ENGINE (MULTIPLE UPLOADS) ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = './public/uploads';
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});
const upload = multer({ storage: storage });

// --- 3. SECURITY SHIELDS ---
const checkAuth = (req, res, next) => {
    if (req.session.userId) return next();
    res.status(401).redirect('/login.html');
};

const authorize = (roles) => (req, res, next) => {
    if (roles.includes(req.session.role)) return next();
    res.status(403).send("Access Denied: Insufficient Clearance.");
};

// --- 4. DATABASE ARCHITECTURE ---
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT, account_number TEXT UNIQUE, name TEXT, address TEXT, phone TEXT, email TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS services (id INTEGER PRIMARY KEY, title TEXT, description TEXT, content TEXT, image_url TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS projects (id INTEGER PRIMARY KEY, title TEXT, location TEXT, content TEXT, image_url TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, key TEXT UNIQUE, value TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY, title TEXT, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`);
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS staff (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE, 
        role TEXT, 
        password TEXT
    )`);
    // Default Settings Initialization
    const defaults = [
        ['logo', '/uploads/default-logo.png'],
        ['dossier_text', 'Engineering Next-Generation Industrial Infrastructure Models.'],
        ['about_text', 'S-Blue Energy global operational portfolio narrative metrics.'],
        ['smtp_host', 'smtp.gmail.com'], ['smtp_port', '587'], ['smtp_user', ''], ['smtp_pass', '']
    ];
    defaults.forEach(pair => db.run("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", pair));
});
});

db.get("SELECT COUNT(*) as count FROM staff", (err, row) => {
    if (row && row.count === 0) {
        console.log("No staff found. Creating default Owner account...");
        db.run("INSERT INTO staff (username, role, password) VALUES (?, ?, ?)", 
        ['Owner', 'Owner', 'password123'], (err) => {
            if (err) console.error("Error creating default staff:", err);
            else console.log("Default Owner account created: Owner / password123");
        });
    }
});
// --- 5. AUTHENTICATION NODES ---
app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // 1. Check Staff Table First
        const staff = await new Promise((resolve) => {
            db.get("SELECT * FROM staff WHERE username = ?", [username], (err, row) => resolve(row));
        });

        if (staff) {
            const match = await bcrypt.compare(password, staff.password);
            if (match) {
                req.session.userId = staff.id;
                req.session.role = staff.role;
                req.session.fullname = staff.username;
                return res.redirect('/admin.html');
            }
        }

        // 2. Check Users Table Second (only if staff not found or password wrong)
        const user = await new Promise((resolve) => {
            db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => resolve(row));
        });

        if (user) {
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                req.session.userId = user.id;
                req.session.role = user.role;
                req.session.fullname = user.name;
                return res.redirect(user.role === 'User' ? '/profile.html' : '/admin.html');
            }
        }

        // 3. Fallback
        res.status(401).send("Invalid Signature. <a href='/login.html'>Retry</a>");
        
    } catch (err) {
        console.error("Login System Error:", err);
        res.status(500).send("System Error");
    }
});

// Route to CREATE a new staff member
// --- FIX: Update the Create Staff route ---
app.post('/admin/staff/create', checkAuth, authorize(['Owner', 'Manager']), async (req, res) => {
    const { username, role, password } = req.body;
    
    // Debug: Check if data is arriving
    console.log("DEBUG CREATION ATTEMPT:", { username, role, password });

    if (!username || !password) return res.status(400).send("Username and Password required.");

    try {
        const hash = await bcrypt.hash(password, 10);
        db.run("INSERT INTO staff (username, role, password) VALUES (?, ?, ?)", 
        [username, role, hash], 
        function(err) {
            if (err) {
                console.error("DEBUG DB ERROR:", err.message);
                return res.status(500).send("Database Error: " + err.message);
            }
            res.sendStatus(200);
        });
    } catch (e) {
        res.status(500).send("Hashing Error: " + e.message);
    }
});

app.post('/api/admin/update-text', (req, res) => {
    // Only allow Owners/Managers
    if (req.session.role !== 'Owner' && req.session.role !== 'Manager') return res.sendStatus(403);

    const { key, value } = req.body; 
    // Key will be 'about_text' or 'dossier_text'
    
    db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`, [key, value], (err) => {
        if (err) return res.status(500).send("Database Error");
        res.sendStatus(200);
    });
});
app.post('/auth/signup', async (req, res) => {
    const { username, password, name, email, phone, address } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10);
        const acc = 'SBLU-' + Math.floor(100000 + Math.random() * 900000);
        db.run(`INSERT INTO users (username, password, role, account_number, name, address, phone, email) VALUES (?,?,'User',?,?,?,?,?)`,
            [username, hash, acc, name, address, phone, email], (err) => {
                if (err) return res.status(400).send("Registration Error: User already exists.");
                res.send("Success! <a href='/login.html'>Login</a>");
            });
    } catch (e) { res.sendStatus(500); }
});

app.get('/auth/status', (req, res) => {
    if (!req.session.userId) return res.json({ loggedIn: false });

    res.json({ 
        loggedIn: true, 
        role: req.session.role, 
        userId: req.session.userId,
        // Match the HTML key 'auth.name'
        name: req.session.fullname 
    });
});
app.get('/auth/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

// --- 6. ADMINISTRATIVE CONTROL APIS ---

// Settings Management
app.get('/api/settings/all', (req, res) => {
    db.all("SELECT key, value FROM settings", (err, rows) => {
        if (err) return res.status(500).json({});
        
        // Convert array [ {key: 'about', value: '...'} ] 
        // to object { about: '...' } so the Admin JS can read it
        const settingsMap = {};
        if (rows) {
            rows.forEach(row => {
                settingsMap[row.key] = row.value;
            });
        }
        res.json(settingsMap);
    });
});
app.post('/admin/update-settings', (req, res) => {
    if (req.session.role !== 'Owner' && req.session.role !== 'Manager') return res.sendStatus(403);
    const { key, value } = req.body;
    
    db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`, [key, value], (err) => {
        if (err) return res.status(500).send(err);
        res.sendStatus(200);
    });
});
app.post('/admin/update-logo', checkAuth, authorize(['Owner']), upload.single('logo'), (req, res) => {
    if (!req.file) return res.redirect('/admin.html');
    const path = `/uploads/${req.file.filename}`;
    db.run("UPDATE settings SET value = ? WHERE key = 'logo'", [path], () => res.redirect('/admin.html'));
});

// User Management
app.get('/api/users/customers', checkAuth, (req, res) => db.all("SELECT * FROM users WHERE role='User'", (err, r) => res.json(r)));
app.get('/api/users/staff', checkAuth, (req, res) => db.all("SELECT * FROM users WHERE role!='User'", (err, r) => res.json(r)));

app.post('/admin/users/update', checkAuth, async (req, res) => {
    const { id, name, email, phone, address, new_password } = req.body;
    if (new_password) {
        const hash = await bcrypt.hash(new_password, 10);
        db.run("UPDATE users SET name=?, email=?, phone=?, address=?, password=? WHERE id=?", [name, email, phone, address, hash, id], () => res.sendStatus(200));
    } else {
        db.run("UPDATE users SET name=?, email=?, phone=?, address=? WHERE id=?", [name, email, phone, address, id], () => res.sendStatus(200));
    }
});

// Dedicated route for users to update their own profile
app.post('/api/user/update-profile', async (req, res) => {
    if (!req.session.userId) return res.sendStatus(401);

    const { name, email, phone, address, new_password } = req.body;
    const userId = req.session.userId; // Securely get ID from session

    try {
        if (new_password && new_password.trim() !== "") {
            const hash = await bcrypt.hash(new_password, 10);
            db.run(
                "UPDATE users SET name=?, email=?, phone=?, address=?, password=? WHERE id=?",
                [name, email, phone, address, hash, userId],
                (err) => {
                    if (err) return res.status(500).send(err);
                    req.session.fullname = name; // Update session name immediately
                    res.sendStatus(200);
                }
            );
        } else {
            db.run(
                "UPDATE users SET name=?, email=?, phone=?, address=? WHERE id=?",
                [name, email, phone, address, userId],
                (err) => {
                    if (err) return res.status(500).send(err);
                    req.session.fullname = name; // Update session name immediately
                    res.sendStatus(200);
                }
            );
        }
    } catch (error) {
        res.status(500).send("Security Hashing Error");
    }
});

app.post('/admin/users/delete', checkAuth, authorize(['Owner']), (req, res) => {
    db.run("DELETE FROM users WHERE id = ? AND role != 'Owner'", [req.body.id], () => res.sendStatus(200));
});

// --- 7. CONTENT ENGINE (SERVICES & PROJECTS) ---

// READ
app.get('/api/services', (req, res) => db.all("SELECT * FROM services", (err, r) => res.json(r || [])));
app.get('/api/projects', (req, res) => db.all("SELECT * FROM projects", (err, r) => res.json(r || [])));

// CREATE
app.post('/admin/services/create', checkAuth, upload.single('image'), (req, res) => {
    const img = req.file ? `/uploads/${req.file.filename}` : '';
    db.run("INSERT INTO services (title, description, content, image_url) VALUES (?,?,?,?)", 
        [req.body.title, req.body.description, req.body.content, img], () => res.redirect('/admin.html'));
});

app.post('/admin/projects/create', checkAuth, upload.single('image'), (req, res) => {
    const img = req.file ? `/uploads/${req.file.filename}` : '';
    db.run("INSERT INTO projects (title, location, content, image_url) VALUES (?,?,?,?)", 
        [req.body.title, req.body.location, req.body.content || '', img], () => res.redirect('/admin.html'));
});

// DELETE (Required for your Admin Panel updates)
app.post('/admin/services/delete', checkAuth, authorize(['Owner', 'Manager']), (req, res) => {
    db.run("DELETE FROM services WHERE id = ?", [req.body.id], () => res.sendStatus(200));
});

app.post('/admin/projects/delete', checkAuth, authorize(['Owner', 'Manager']), (req, res) => {
    db.run("DELETE FROM projects WHERE id = ?", [req.body.id], () => res.sendStatus(200));
});

// --- Update Core Services ---

   // Ensure this route matches the structure of your existing 'create' route
app.post('/admin/services/update', checkAuth, authorize(['Owner', 'Manager']), upload.single('image'), (req, res) => {
    const { id, title, description, content } = req.body;
    
    if (!id) return res.status(400).send("ID missing");

    if (req.file) {
        // If user uploaded a new image, update the image path too
        const image_url = '/uploads/' + req.file.filename; 
        const query = "UPDATE services SET title = ?, description = ?, content = ?, image_url = ? WHERE id = ?";
        db.run(query, [title, description, content, image_url, id], (err) => {
            if (err) return res.status(500).send("Database Error");
            res.redirect('/admin.html');
        });
    } else {
        // If NO file provided, update text ONLY, keep the old image_url
        const query = "UPDATE services SET title = ?, description = ?, content = ? WHERE id = ?";
        db.run(query, [title, description, content, id], (err) => {
            if (err) return res.status(500).send("Database Error");
            res.redirect('/admin.html');
        });
    }
});
// --- Update Site Projects ---
app.post('/admin/projects/update', checkAuth, authorize(['Owner', 'Manager']), upload.single('image'), (req, res) => {
    const { id, title, location, content } = req.body;
    
    if (!id) return res.status(400).send("ID missing");

    if (req.file) {
        // A new photo was uploaded
        const image_url = '/uploads/' + req.file.filename; 
        const query = "UPDATE projects SET title = ?, location = ?, content = ?, image_url = ? WHERE id = ?";
        db.run(query, [title, location, content, image_url, id], (err) => {
            if (err) return res.status(500).send("Database Error");
            res.redirect('/admin.html');
        });
    } else {
        // No photo uploaded, update TEXT only
        const query = "UPDATE projects SET title = ?, location = ?, content = ? WHERE id = ?";
        db.run(query, [title, location, content, id], (err) => {
            if (err) return res.status(500).send("Database Error");
            res.redirect('/admin.html');
        });
    }
});// --- 8. PUBLIC CONTENT FETCH ---
app.get('/api/settings/:key', (req, res) => {
    const query = "SELECT value FROM settings WHERE key = ?";
    db.get(query, [req.params.key], (err, row) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ value: "Error retrieving data." });
        }
        // If the row exists, send the value; otherwise send an empty string
        res.json({ value: row ? row.value : "" });
    });
});
// --- 9. PROFILE & SYSTEM START ---
app.get('/api/profile/me', checkAuth, (req, res) => {
    db.get("SELECT * FROM users WHERE id = ?", [req.session.userId], (err, user) => res.json(user));
});
// --- 10. Staff Data Edit ---
app.get('/admin/staff/list', checkAuth, authorize(['Owner', 'Manager']), (req, res) => {
    // This specifically hits your 'staff' table
    db.all("SELECT id, username, role FROM staff", [], (err, rows) => {
        if (err) return res.status(500).send("Database Error");
        res.json(rows || []);
    });
});
app.post('/admin/staff/update', checkAuth, authorize(['Owner', 'Manager']), async (req, res) => {
    const { id, username, role, password } = req.body;

    try {
        if (password && password.trim() !== "") {
            const hash = await bcrypt.hash(password, 10);
            
            db.run("UPDATE staff SET username=?, role=?, password=? WHERE id=?", 
            [username, role, hash, id], (err) => {
                if (err) {
                    console.error("DEBUG DB ERROR:", err.message); // Server log
                    return res.status(500).send("DB Error: " + err.message); // Client response
                }
                res.sendStatus(200);
            });
        } else {
            db.run("UPDATE staff SET username=?, role=? WHERE id=?", 
            [username, role, id], (err) => {
                if (err) {
                    console.error("DEBUG DB ERROR:", err.message);
                    return res.status(500).send("DB Error: " + err.message);
                }
                res.sendStatus(200);
            });
        }
    } catch (err) {
        console.error("Critical Update Failure:", err);
        res.status(500).send("Update Failed");
    }
});
app.get('/emergency-create-admin', async (req, res) => {
    const hash = await bcrypt.hash('password123', 10);
    
    // 1. Remove existing to prevent conflict
    db.run("DELETE FROM staff WHERE username = 'Admin'", () => {
        // 2. Insert fresh
        db.run("INSERT INTO staff (username, role, password) VALUES (?, ?, ?)", 
        ['Admin', 'Owner', hash], (err) => {
            if (err) {
                console.error("Force Add Failed:", err);
                res.send("Critical DB Error: " + err.message);
            } else {
                res.send("Admin forced into DB! Now delete this code and redeploy.");
            }
        });
    });
});

app.post('/admin/staff/delete', checkAuth, authorize(['Owner']), (req, res) => {
    const { id } = req.body;

    // Safety check: Don't allow deleting the last Owner if you want to prevent lockout
    db.run("DELETE FROM staff WHERE id = ?", [id], function(err) {
        if (err) {
            console.error("Deletion Error:", err.message);
            return res.status(500).send("Failed to delete staff.");
        }
        if (this.changes === 0) {
            return res.status(404).send("Staff member not found.");
        }
        res.sendStatus(200);
    });
});

// Static Files & Landing
app.get('/admin.html', checkAuth, authorize(['Owner', 'Manager']), (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.use(express.static(path.join(__dirname, 'public')));

app.listen(3000, () => console.log("S-Blue Enterprise Core: http://localhost:3000"));

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const port = 3001;

// Middlewares
app.use(express.json());

// Intentionally bad CORS configuration (allows any origin, vulnerable to CORS misconfiguration)
app.use(cors({
    origin: function (origin, callback) {
        callback(null, true);
    },
    credentials: true
}));

// Serve static files, but with directory traversal vulnerability
app.use('/static', (req, res) => {
    // Intentionally vulnerable to path traversal (e.g. /static/../../../etc/passwd)
    const filePath = path.join(__dirname, 'public', req.url);
    try {
        if (fs.existsSync(filePath)) {
            res.sendFile(filePath);
        } else {
            res.status(404).send('Not found');
        }
    } catch (e) {
        res.status(500).send('Error');
    }
});


// Database setup
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
    db.run("CREATE TABLE users (id INT, username TEXT, password TEXT, role TEXT)");
    db.run("INSERT INTO users VALUES (1, 'admin', 'supersecretpassword123', 'admin')");
    db.run("INSERT INTO users VALUES (2, 'john', 'password123', 'user')");
    db.run("INSERT INTO users VALUES (3, 'jane', 'qwerty', 'user')");
    
    db.run("CREATE TABLE posts (id INT, title TEXT, content TEXT, author TEXT)");
    db.run("INSERT INTO posts VALUES (1, 'Welcome', 'Welcome to our vulnerable blog!', 'admin')");
    db.run("INSERT INTO posts VALUES (2, 'Hidden Secrets', 'This post should be private.', 'admin')");
});


// --- VULNERABLE ENDPOINTS ---

// 1. SQL Injection (SQLi)
app.get('/api/users', (req, res) => {
    // VULNERABLE: Directly concatenating user input into SQL query
    const username = req.query.username;
    
    let query = "SELECT id, username, role FROM users";
    if (username) {
        query += ` WHERE username = '${username}'`;
    }

    db.all(query, (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message }); // Error-based SQLi possible
            return;
        }
        res.json(rows);
    });
});

// 2. Broken Authentication / Insecure Login (SQLi)
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    // VULNERABLE: SQL injection in login
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    db.get(query, (err, row) => {
        if (err) {
            return res.status(500).json({ error: "Database error" });
        }
        if (row) {
            // Intentionally returning everything including password
            res.json({ message: "Login successful", user: row });
        } else {
            res.status(401).json({ error: "Invalid credentials" });
        }
    });
});

// 3. Information Disclosure / Broken Access Control
// Exposing internal API specs
app.get('/openapi.json', (req, res) => {
    res.json({
        openapi: "3.0.0",
        info: { title: "Vulnerable API", version: "1.0" },
        paths: {
            "/api/users": { get: { description: "Get users. Vulnerable to SQLi." } },
            "/api/admin/system": { get: { description: "Internal system details." } }
        }
    });
});

// 4. Cross-Site Scripting (XSS) via reflection
app.get('/api/search', (req, res) => {
    const q = req.query.q || '';
    // VULNERABLE: Reflecting unescaped input directly into HTML/JSON response
    res.send(`
        <html>
            <body>
                <h2>Search Results for: ${q}</h2>
                <p>No results found.</p>
            </body>
        </html>
    `);
});

// 5. Verbose Errors (Information Disclosure)
app.get('/api/error', (req, res) => {
    try {
        throw new Error("Cannot connect to internal database 192.168.1.100:5432 with user 'root'");
    } catch (e) {
        // VULNERABLE: Leaking internal stack traces and secrets
        res.status(500).json({ 
            error: e.message,
            stack: e.stack
        });
    }
});


// 6. GraphQL (Mocked Introspection for scanning)
app.post('/graphql', (req, res) => {
    const body = req.body;
    if (body && typeof body.query === 'string' && body.query.includes('__schema')) {
        // Mock introspection response
        return res.json({
            data: {
                __schema: {
                    queryType: { name: 'Query' },
                    mutationType: { name: 'Mutation' }
                }
            }
        });
    }
    res.json({ error: 'GraphQL endpoint requires query' });
});


// Intentionally exposing dangerous methods (OPTIONS)
app.options('/api/data', (req, res) => {
    res.header('Allow', 'GET, POST, PUT, DELETE, TRACE, CONNECT, OPTIONS');
    res.send();
});


app.listen(port, () => {
    console.log(`[Vulnerable Target] running at http://localhost:${port}`);
    console.log(`WARNING: This app is intentionally vulnerable. Do not run in production.`);
});

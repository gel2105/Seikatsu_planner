// server.js - COMPLETE BACKEND
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const moment = require('moment');

const app = express();
app.use(cors());
app.use(express.json());

// DATABASE CONNECTION
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'your_password',
  database: 'seikatsu_planner'
});

const JWT_SECRET = 'seikatsu_secret_key_2024';

// MIDDLEWARE - Authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// LOG SYSTEM ACTIVITY
const logActivity = (userId, action, description, platform = 'web', req) => {
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent') || '';
  
  db.query(
    'INSERT INTO system_logs (user_id, action, description, ip_address, user_agent, platform) VALUES (?, ?, ?, ?, ?, ?)',
    [userId, action, description, ip, userAgent, platform],
    (err) => {
      if (err) console.error('Log error:', err);
    }
  );
};

// LOGIN API
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = results[0];
    
    // For demo purposes, accept 'password' as password
    const validPassword = password === 'password' || await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Log login activity
    logActivity(user.id, 'user_login', 'User logged in successfully', 'web', req);

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role
      }
    });
  });
});

// DASHBOARD DATA API
app.get('/api/dashboard', authenticateToken, (req, res) => {
  // Get all dashboard statistics
  const queries = [
    'SELECT COUNT(*) as totalUsers FROM users WHERE role = "user"',
    'SELECT COUNT(*) as totalTasks FROM tasks',
    'SELECT COUNT(*) as totalEvents FROM events',
    'SELECT COUNT(*) as pendingTasks FROM tasks WHERE status = "pending"',
    'SELECT COUNT(*) as completedTasks FROM tasks WHERE status = "completed"',
    'SELECT * FROM system_logs ORDER BY created_at DESC LIMIT 10',
    'SELECT u.*, DATE(u.created_at) as join_date FROM users u WHERE u.role = "user" ORDER BY u.created_at DESC LIMIT 5'
  ];

  Promise.all(queries.map(query => {
    return new Promise((resolve, reject) => {
      db.query(query, (err, results) => {
        if (err) reject(err);
        else resolve(results);
      });
    });
  }))
  .then(results => {
    res.json({
      totalUsers: results[0][0].totalUsers,
      totalTasks: results[1][0].totalTasks,
      totalEvents: results[2][0].totalEvents,
      pendingTasks: results[3][0].pendingTasks,
      completedTasks: results[4][0].completedTasks,
      recentLogs: results[5],
      recentUsers: results[6]
    });
  })
  .catch(err => {
    res.status(500).json({ message: 'Database error', error: err.message });
  });
});

// USERS CRUD APIs
app.get('/api/users', authenticateToken, (req, res) => {
  db.query('SELECT id, email, full_name, role, status, created_at FROM users ORDER BY created_at DESC', (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(results);
  });
});

app.post('/api/users', authenticateToken, (req, res) => {
  const { email, full_name, role = 'user' } = req.body;
  const password = bcrypt.hashSync('password', 10); // Default password

  db.query(
    'INSERT INTO users (email, password, full_name, role) VALUES (?, ?, ?, ?)',
    [email, password, full_name, role],
    (err, result) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ message: 'Email already exists' });
        }
        return res.status(500).json({ message: 'Database error' });
      }

      logActivity(req.user.id, 'user_created', `Created new user: ${email}`, 'admin', req);
      res.json({ message: 'User created successfully', id: result.insertId });
    }
  );
});

app.put('/api/users/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { email, full_name, role, status } = req.body;

  db.query(
    'UPDATE users SET email = ?, full_name = ?, role = ?, status = ? WHERE id = ?',
    [email, full_name, role, status, id],
    (err) => {
      if (err) return res.status(500).json({ message: 'Database error' });
      
      logActivity(req.user.id, 'user_updated', `Updated user ID: ${id}`, 'admin', req);
      res.json({ message: 'User updated successfully' });
    }
  );
});

app.delete('/api/users/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  db.query('DELETE FROM users WHERE id = ?', [id], (err) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    
    logActivity(req.user.id, 'user_deleted', `Deleted user ID: ${id}`, 'admin', req);
    res.json({ message: 'User deleted successfully' });
  });
});

// TASKS CRUD APIs
app.get('/api/tasks', authenticateToken, (req, res) => {
  db.query(`
    SELECT t.*, u.full_name as user_name 
    FROM tasks t 
    LEFT JOIN users u ON t.user_id = u.id 
    ORDER BY t.created_at DESC
  `, (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(results);
  });
});

app.post('/api/tasks', authenticateToken, (req, res) => {
  const { title, description, user_id, priority = 'medium', due_date } = req.body;

  db.query(
    'INSERT INTO tasks (title, description, user_id, priority, due_date) VALUES (?, ?, ?, ?, ?)',
    [title, description, user_id, priority, due_date],
    (err, result) => {
      if (err) return res.status(500).json({ message: 'Database error' });
      
      logActivity(req.user.id, 'task_created', `Created task: ${title}`, 'admin', req);
      res.json({ message: 'Task created successfully', id: result.insertId });
    }
  );
});

app.put('/api/tasks/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { title, description, status, priority, due_date } = req.body;

  db.query(
    'UPDATE tasks SET title = ?, description = ?, status = ?, priority = ?, due_date = ? WHERE id = ?',
    [title, description, status, priority, due_date, id],
    (err) => {
      if (err) return res.status(500).json({ message: 'Database error' });
      
      logActivity(req.user.id, 'task_updated', `Updated task ID: ${id}`, 'admin', req);
      res.json({ message: 'Task updated successfully' });
    }
  );
});

// EVENTS CRUD APIs
app.get('/api/events', authenticateToken, (req, res) => {
  db.query(`
    SELECT e.*, u.full_name as user_name 
    FROM events e 
    LEFT JOIN users u ON e.user_id = u.id 
    ORDER BY e.event_date DESC
  `, (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(results);
  });
});

app.post('/api/events', authenticateToken, (req, res) => {
  const { title, description, user_id, event_date, event_time, location } = req.body;

  db.query(
    'INSERT INTO events (title, description, user_id, event_date, event_time, location) VALUES (?, ?, ?, ?, ?, ?)',
    [title, description, user_id, event_date, event_time, location],
    (err, result) => {
      if (err) return res.status(500).json({ message: 'Database error' });
      
      logActivity(req.user.id, 'event_created', `Created event: ${title}`, 'admin', req);
      res.json({ message: 'Event created successfully', id: result.insertId });
    }
  );
});

// SYSTEM LOGS API
app.get('/api/logs', authenticateToken, (req, res) => {
  db.query(`
    SELECT l.*, u.full_name as user_name 
    FROM system_logs l 
    LEFT JOIN users u ON l.user_id = u.id 
    ORDER BY l.created_at DESC 
    LIMIT 100
  `, (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(results);
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Seikatsu Planner API running on port ${PORT}`);
  console.log(`📱 Ready for Flutter app connection!`);
});
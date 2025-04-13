const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const dbPath = path.join(__dirname, 'adminPanel.db');
let db = null;

const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    await createCategoryTable();
    app.listen(3000, () => {
      console.log('Server running at http://localhost:3000/');
    });
  } catch (error) {
    console.error(`DB Error: ${error.message}`);
    process.exit(1);
  }
};

initializeDbAndServer();

// Create Category Table with additional fields (item_count and image_url)
const createCategoryTable = async () => {
  const query = `
    CREATE TABLE IF NOT EXISTS category (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      item_count INTEGER DEFAULT 0,
      image_url TEXT
    );
  `;
  await db.run(query);
};

// JWT Middleware
const authenticateToken = (request, response, next) => {
  const authHeader = request.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token === undefined) {
    return response.status(401).send('Invalid JWT Token');
  } else {
    jwt.verify(token, 'SECRET_KEY', (error, payload) => {
      if (error) {
        return response.status(401).send('Invalid JWT Token');
      } else {
        request.username = payload.username;
        next();
      }
    });
  }
};

// Admin Signup
app.post('/register', async (request, response) => {
  const { username, password } = request.body;

  if (!username || !password) {
    return response.status(400).send('Username and password are required');
  }

  const userExists = await db.get(
    `SELECT * FROM admin WHERE username = ?`,
    [username]
  );

  if (userExists) {
    return response.status(400).send('Admin already exists');
  } else if (password.length < 6) {
    return response.status(400).send('Password is too short');
  } else {
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.run(
      `INSERT INTO admin (username, password) VALUES (?, ?)`,
      [username, hashedPassword]
    );
    response.send('Admin created successfully');
  }
});

// Admin Login
app.post('/api/auth/login', async (request, response) => {
  const { username, password } = request.body;
  const admin = await db.get(`SELECT * FROM admin WHERE username = ?`, [
    username,
  ]);

  if (!admin) {
    return response.status(400).send('Invalid user');
  } else {
    const isPasswordMatch = await bcrypt.compare(password, admin.password);
    if (isPasswordMatch) {
      const jwtToken = jwt.sign({ username }, 'SECRET_KEY');
      response.send({ jwtToken });
    } else {
      return response.status(400).send('Invalid password');
    }
  }
});

// Get all categories
app.get('/api/categories', authenticateToken, async (request, response) => {
  try {
    const categories = await db.all(`SELECT * FROM category`);
    response.send(categories);
  } catch (error) {
    response.status(500).send('Error fetching categories');
  }
});

// Add a new category
app.post('/api/categories', authenticateToken, async (request, response) => {
  const { name, item_count = 0, image_url = '' } = request.body;

  if (!name) {
    return response.status(400).send('Category name is required');
  }

  try {
    await db.run(
      `INSERT INTO category (name, item_count, image_url) VALUES (?, ?, ?)`,
      [name, item_count, image_url]
    );
    response.send('Category added successfully');
  } catch (error) {
    response.status(500).send('Error adding category');
  }
});

// Update a category
app.put('/api/categories/:id', authenticateToken, async (request, response) => {
  const { id } = request.params;
  const { name, item_count, image_url } = request.body;

  if (!name || item_count === undefined || image_url === undefined) {
    return response.status(400).send('All fields (name, item_count, image_url) are required');
  }

  try {
    const result = await db.run(
      `UPDATE category SET name = ?, item_count = ?, image_url = ? WHERE id = ?`,
      [name, item_count, image_url, id]
    );

    if (result.changes === 0) {
      return response.status(404).send('Category not found');
    }

    response.send('Category updated successfully');
  } catch (error) {
    response.status(500).send('Error updating category');
  }
});
// Get a category by ID
// Get category by ID
app.get('/api/categories/:id',async (request, response) => {
  const { id } = request.params;

  try {
    const category = await db.get(`SELECT * FROM category WHERE id = ?`, [id]);

    if (!category) {
      return response.status(404).send('Category not found');
    }

    response.send(category);
  } catch (error) {
    console.error(error);
    response.status(500).send('Error fetching category');
  }
});


module.exports = app;

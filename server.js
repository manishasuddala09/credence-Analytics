const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

const port = 3000;

// MySQL Connection
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'sqluser', 
    password: 'password', 
    database: 'mydb'
});

connection.connect(err => {
    if (err) {
        console.error('Error connecting to MySQL database:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

app.use(express.json());


// User Registration Endpoint
app.post('/register', (req, res) => {
    const { username, password } = req.body;

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        const newUser = { username, password_hash: hash };
        connection.query('INSERT INTO Users SET ?', newUser, (err, result) => {
            if (err) {
                console.error('Error registering user:', err);
                return res.status(500).json({ message: 'Internal server error' });
            }

            res.status(201).json({ message: 'User registered successfully' });
        });
    });
});

// User Login Endpoint
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    connection.query('SELECT * FROM Users WHERE username = ?', username, (err, results) => {
        if (err) {
            console.error('Error fetching user:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const user = results[0];

        bcrypt.compare(password, user.password_hash, (err, isValid) => {
            if (err) {
                console.error('Error comparing passwords:', err);
                return res.status(500).json({ message: 'Internal server error' });
            }

            if (!isValid) {
                return res.status(401).json({ message: 'Invalid username or password' });
            }

            const token = jwt.sign({ id: user.id, username: user.username }, 'MY_SECRET_TOKEN', { expiresIn: '1000d'});
            res.status(200).json({ token });
        });
    });
});



function authenticateToken(req, res, next) {
    // Get the JWT token from the Authorization header
    const authHeader = req.headers['authorization'];
    const token = authHeader.split(' ')[1];
    console.log(token);

    // If token is not provided, return 401 Unauthorized
    if (!token) {
        return res.status(401).json({ message: 'Authentication required' });
    }

    // Verify the JWT token
    jwt.verify(token, 'MY_SECRET_TOKEN', (err, decodedToken) => {
        if (err) {
            console.error('Error verifying token:', err);
            return res.status(403).json({ message: 'Invalid token' });
        }
        // If token is valid, set the user object in the request
        req.user = decodedToken;
        next(); // Call the next middleware
    });
}




// CRUD Endpoints for Tasks

app.post('/movies', authenticateToken,(req, res) => {
    const { name, img, summary } = req.body;
    const insertQuery = `INSERT INTO usersdata (name, img, summary) VALUES (?, ?, ?)`;
    connection.query(insertQuery, [name, img, summary], (err, result) => {
      if (err) {
        console.error('Error inserting movie:', err);
        res.status(500).send('Error inserting movie');
        return;
      }
      res.send({ id: result.insertId, name, img, summary });
    });
  });
  
  // Get all movies
  app.get('/movies',authenticateToken, (req, res) => {
    const selectQuery = `SELECT * FROM usersdata`;
    connection.query(selectQuery, (err, results) => {
      if (err) {
        console.error('Error fetching movies:', err);
        res.status(500).send('Error fetching movies');
        return;
      }
      res.send(results);
    });
  });
  
  // Get a specific movie by ID
  app.get('/movies/:id',authenticateToken, (req, res) => {
    const { id } = req.params;
    const selectQuery = `SELECT * FROM usersdata WHERE id = ?`;
    connection.query(selectQuery, [id], (err, results) => {
      if (err) {
        console.error('Error fetching movie:', err);
        res.status(500).send('Error fetching movie');
        return;
      }
      if (results.length === 0) {
        res.status(404).send('Movie not found');
        return;
      }
      res.send(results[0]);
    });
  });
  
  // Update a movie
  app.put('/movies/:id',authenticateToken, (req, res) => {
    const { id } = req.params;
    const { name, img, summary } = req.body;
    const updateQuery = `UPDATE usersdata SET name = ?, img = ?, summary = ? WHERE id = ?`;
    connection.query(updateQuery, [name, img, summary, id], (err, result) => {
      if (err) {
        console.error('Error updating movie:', err);
        res.status(500).send('Error updating movie');
        return;
      }
      if (result.affectedRows === 0) {
        res.status(404).send('Movie not found');
        return;
      }
      res.send({ id, name, img, summary });
    });
  });
  
  // Delete a movie
  app.delete('/movies/:id',authenticateToken, (req, res) => {
    const { id } = req.params;
    const deleteQuery = `DELETE FROM usersdata WHERE id = ?`;
    connection.query(deleteQuery, [id], (err, result) => {
      if (err) {
        console.error('Error deleting movie:', err);
        res.status(500).send('Error deleting movie');
        return;
      }
      if (result.affectedRows === 0) {
        res.status(404).send('Movie not found');
        return;
      }
      res.send('Movie deleted successfully');
    });
  });
  
  // Start the server
  app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

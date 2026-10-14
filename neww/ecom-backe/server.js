// server.js
require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const mysql = require('mysql2/promise'); // Using promise-based API
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors()); // Allow cross-origin requests from frontend
app.use(express.json()); // Parse JSON request bodies

// Database connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'Mysqlkapass', // Change this!
    database: process.env.DB_NAME || 'ecommerce_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// JWT Secret (generate a strong, random one in production)
const jwtSecret = process.env.JWT_SECRET || 'Mysqlkapass'; // Change this!

// Middleware to protect routes (verify JWT)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.sendStatus(401); // No token

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.sendStatus(403); // Invalid token
        req.user = user; // Add user payload to request
        next();
    });
};

// --- Routes ---

// 1. User Registration
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Please enter all fields' });
    }

    try {
        // Check if user already exists
        const [existingUsers] = await pool.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );
        if (existingUsers.length > 0) {
            return res.status(400).json({ message: 'User with that username or email already exists' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Insert new user
        const [result] = await pool.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );

        res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error during registration' });
    }
});

// 2. User Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Please enter email and password' });
    }

    try {
        // Find user by email
        const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        const user = users[0];

        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Generate JWT
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },
            jwtSecret,
            { expiresIn: '1h' } // Token expires in 1 hour
        );

        res.json({ message: 'Logged in successfully', token, user: { id: user.id, username: user.username, email: user.email } });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login' });
    }
});

// 3. Get All Products (Public)
app.get('/api/products', async (req, res) => {
    try {
        const [products] = await pool.execute('SELECT * FROM products');
        res.json(products);
    } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).json({ message: 'Server error fetching products' });
    }
});

// 4. Get Single Product by ID (Public)
app.get('/api/products/:id', async (req, res) => {
    try {
        const [products] = await pool.execute('SELECT * FROM products WHERE id = ?', [req.params.id]);
        if (products.length === 0) {
            return res.status(404).json({ message: 'Product not found' });
        }
        res.json(products[0]);
    } catch (error) {
        console.error('Error fetching product by ID:', error);
        res.status(500).json({ message: 'Server error fetching product' });
    }
});

// 5. Create Product (Admin only - requires authentication)
// You'll need to add logic to check for admin role in a real app
app.post('/api/products', authenticateToken, async (req, res) => {
    const { name, description, price, image_url, stock_quantity } = req.body;
    if (!name || !price || !stock_quantity) {
        return res.status(400).json({ message: 'Name, price, and stock quantity are required' });
    }
    try {
        const [result] = await pool.execute(
            'INSERT INTO products (name, description, price, image_url, stock_quantity) VALUES (?, ?, ?, ?, ?)',
            [name, description, price, image_url, stock_quantity]
        );
        res.status(201).json({ message: 'Product created successfully', productId: result.insertId });
    } catch (error) {
        console.error('Error creating product:', error);
        res.status(500).json({ message: 'Server error creating product' });
    }
});

// 6. Update Product (Admin only)
app.put('/api/products/:id', authenticateToken, async (req, res) => {
    const { name, description, price, image_url, stock_quantity } = req.body;
    try {
        const [result] = await pool.execute(
            'UPDATE products SET name = ?, description = ?, price = ?, image_url = ?, stock_quantity = ? WHERE id = ?',
            [name, description, price, image_url, stock_quantity, req.params.id]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Product not found' });
        }
        res.json({ message: 'Product updated successfully' });
    } catch (error) {
        console.error('Error updating product:', error);
        res.status(500).json({ message: 'Server error updating product' });
    }
});

// 7. Delete Product (Admin only)
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    try {
        const [result] = await pool.execute('DELETE FROM products WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Product not found' });
        }
        res.json({ message: 'Product deleted successfully' });
    } catch (error) {
        console.error('Error deleting product:', error);
        res.status(500).json({ message: 'Server error deleting product' });
    }
});

// 8. Place Order (User authenticated)
app.post('/api/orders', authenticateToken, async (req, res) => {
    const { items } = req.body; // items: [{ productId, quantity }]
    const userId = req.user.id; // From JWT payload

    if (!items || items.length === 0) {
        return res.status(400).json({ message: 'Order must contain items' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction(); // Start transaction for atomicity

        let totalAmount = 0;
        const orderItemsData = [];

        // Validate products and calculate total amount
        for (const item of items) {
            const [products] = await connection.execute('SELECT id, price, stock_quantity FROM products WHERE id = ?', [item.productId]);
            const product = products[0];

            if (!product || product.stock_quantity < item.quantity) {
                await connection.rollback();
                return res.status(400).json({ message: `Product ${item.productId} out of stock or not found` });
            }

            totalAmount += product.price * item.quantity;
            orderItemsData.push({ ...item, price_at_purchase: product.price });

            // Decrement stock (this is a simple example, real e-commerce uses more robust inventory management)
            await connection.execute(
                'UPDATE products SET stock_quantity = stock_quantity - ? WHERE id = ?',
                [item.quantity, item.productId]
            );
        }

        // Create the order
        const [orderResult] = await connection.execute(
            'INSERT INTO orders (user_id, total_amount, status) VALUES (?, ?, ?)',
            [userId, totalAmount, 'completed'] // For simplicity, marking as completed immediately
        );
        const orderId = orderResult.insertId;

        // Insert order items
        for (const itemData of orderItemsData) {
            await connection.execute(
                'INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase) VALUES (?, ?, ?, ?)',
                [orderId, itemData.productId, itemData.quantity, itemData.price_at_purchase]
            );
        }

        await connection.commit(); // Commit transaction
        res.status(201).json({ message: 'Order placed successfully', orderId });

    } catch (error) {
        if (connection) await connection.rollback(); // Rollback on error
        console.error('Error placing order:', error);
        res.status(500).json({ message: 'Server error placing order' });
    } finally {
        if (connection) connection.release(); // Release connection back to pool
    }
});

// 9. Get User Orders (Authenticated user)
app.get('/api/orders/my-orders', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    try {
        const [orders] = await pool.execute(
            'SELECT id, total_amount, order_date, status FROM orders WHERE user_id = ? ORDER BY order_date DESC',
            [userId]
        );

        // For each order, fetch its items
        for (let order of orders) {
            const [items] = await pool.execute(
                'SELECT oi.quantity, oi.price_at_purchase, p.name as product_name, p.image_url ' +
                'FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?',
                [order.id]
            );
            order.items = items;
        }

        res.json(orders);
    } catch (error) {
        console.error('Error fetching user orders:', error);
        res.status(500).json({ message: 'Server error fetching orders' });
    }
});


// Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`Access backend at http://localhost:${port}`);
});
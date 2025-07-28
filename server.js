const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, 'public', 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    fileFilter: function (req, file, cb) {
        if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
            return cb(new Error('Only image files are allowed!'), false);
        }
        cb(null, true);
    },
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware
app.use(express.json());
app.use(cors());

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public')));
app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

// Initialize data arrays
let users = [];
let workers = [];
let dealers = [];
let materials = [];
let orders = [];

// Load data from JSON files
function loadData() {
    try {
        const dataDir = path.join(__dirname, 'data');
        // Create data directory if it doesn't exist
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
            console.log('[DATA] Created data directory:', dataDir);
        }

        // Load users data
        const usersPath = path.join(dataDir, 'users.json');
        if (fs.existsSync(usersPath)) {
            const usersData = fs.readFileSync(usersPath, 'utf8');
            users = JSON.parse(usersData);
            console.log('[DATA] Loaded users:', users.length);
        } else {
            fs.writeFileSync(usersPath, JSON.stringify([], null, 2));
            users = [];
            console.log('[DATA] Created users.json');
        }

        // Load workers data
        const workersPath = path.join(dataDir, 'workers.json');
        if (fs.existsSync(workersPath)) {
            const workersData = fs.readFileSync(workersPath, 'utf8');
            workers = JSON.parse(workersData);
            console.log('[DATA] Loaded workers:', workers.length);
        } else {
            fs.writeFileSync(workersPath, JSON.stringify([], null, 2));
            workers = [];
            console.log('[DATA] Created workers.json');
        }

        // Load dealers data
        const dealersPath = path.join(dataDir, 'dealers.json');
        if (fs.existsSync(dealersPath)) {
            const dealersData = fs.readFileSync(dealersPath, 'utf8');
            dealers = JSON.parse(dealersData);
            console.log('[DATA] Loaded dealers:', dealers.length);
        } else {
            fs.writeFileSync(dealersPath, JSON.stringify([], null, 2));
            dealers = [];
            console.log('[DATA] Created dealers.json');
        }

        // Load materials data
        const materialsPath = path.join(dataDir, 'materials.json');
        if (fs.existsSync(materialsPath)) {
            const materialsData = fs.readFileSync(materialsPath, 'utf8');
            materials = JSON.parse(materialsData);
            console.log('[DATA] Loaded materials:', materials.length);
        } else {
            fs.writeFileSync(materialsPath, JSON.stringify([], null, 2));
            materials = [];
            console.log('[DATA] Created materials.json');
        }

        // Load orders data
        const ordersPath = path.join(dataDir, 'orders.json');
        if (fs.existsSync(ordersPath)) {
            const ordersData = fs.readFileSync(ordersPath, 'utf8');
            orders = JSON.parse(ordersData);
            console.log('[DATA] Loaded orders:', orders.length);
        } else {
            fs.writeFileSync(ordersPath, JSON.stringify([], null, 2));
            orders = [];
            console.log('[DATA] Created orders.json');
        }
    } catch (error) {
        console.error('[DATA] Error loading data:', error);
        // Initialize empty arrays if files don't exist
        users = [];
        workers = [];
        dealers = [];
        materials = [];
        orders = [];
    }
}

// Save data to JSON files
function saveData(filename, data) {
    try {
        const dataDir = path.join(__dirname, 'data');
        // Create data directory if it doesn't exist
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
            console.log('[DATA] Created data directory:', dataDir);
        }

        const filePath = path.join(dataDir, filename);
        const jsonData = JSON.stringify(data, null, 2);
        fs.writeFileSync(filePath, jsonData);
        console.log(`[DATA] Successfully saved ${filename} with ${data.length} records`);
        
        // Verify the data was written correctly
        const savedData = fs.readFileSync(filePath, 'utf8');
        const parsedData = JSON.parse(savedData);
        if (parsedData.length !== data.length) {
            throw new Error(`Data verification failed for ${filename}`);
        }
    } catch (error) {
        console.error(`[DATA] Error saving ${filename}:`, error);
        throw error;
    }
}

// Load initial data
loadData();

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Middleware to verify admin token
function verifyAdminToken(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// JWT verification middleware
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (error) {
        res.status(400).json({ error: 'Invalid token' });
    }
};

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Public API routes
app.get('/api/materials', (req, res) => {
    try {
        // Set proper JSON content type
        res.setHeader('Content-Type', 'application/json');
        
        // Check if materials array exists and is valid
        if (!Array.isArray(materials)) {
            console.error('Materials data is not an array:', materials);
            return res.status(500).json({ error: 'Invalid materials data structure' });
        }
        
        // Send the materials array as JSON
    res.json(materials);
    } catch (error) {
        console.error('Error fetching materials:', error);
        res.status(500).json({ error: 'Failed to fetch materials' });
    }
});

app.get('/api/materials/:id', (req, res) => {
    try {
        // Set proper JSON content type
        res.setHeader('Content-Type', 'application/json');
        
        const materialId = req.params.id;
        const material = materials.find(m => m.id === materialId);
        
        if (!material) {
            return res.status(404).json({ error: 'Material not found' });
        }
        
        res.json(material);
    } catch (error) {
        console.error('Error fetching material details:', error);
        res.status(500).json({ error: 'Failed to fetch material details' });
    }
});

app.get('/api/dealers', (req, res) => {
    // Remove sensitive information
    const publicDealers = dealers.map(dealer => {
        const { password, ...publicData } = dealer;
        return publicData;
    });
    res.json(publicDealers);
});

app.get('/api/workers', (req, res) => {
    try {
        // Filter for visible workers and remove sensitive information
        const publicWorkers = workers
            .filter(worker => worker.visible !== false) // Show workers unless explicitly hidden
            .map(worker => {
        const { password, ...publicData } = worker;
                return {
                    ...publicData,
                    available: worker.available !== false // Default to true if not set
                };
    });
    res.json(publicWorkers);
    } catch (error) {
        console.error('Error fetching workers:', error);
        res.status(500).json({ error: 'Failed to fetch workers' });
    }
});

app.get('/api/workers/:id', (req, res) => {
    try {
        const workerId = req.params.id;
        const worker = workers.find(w => w.id === workerId);

    if (!worker) {
        return res.status(404).json({ error: 'Worker not found' });
    }

        // Return worker data without sensitive information
        const { password, ...publicData } = worker;
        res.json({
            ...publicData,
            reviews: worker.reviews || [],
            rating: worker.rating || 0
        });
    } catch (error) {
        console.error('Error fetching worker details:', error);
        res.status(500).json({ error: 'Failed to fetch worker details' });
    }
});

// Protected API routes (Admin and Dealer)
app.post('/api/materials', verifyToken, upload.single('image'), (req, res) => {
    try {
        console.log('[MATERIAL] Request received for adding material:', req.body);
        console.log('[MATERIAL] User role:', req.user.role);
        
        // Only allow dealers to add materials
        if (req.user.role !== 'dealer') {
            if (req.file) {
                fs.unlinkSync(req.file.path);
            }
            return res.status(403).json({ error: 'Access denied. Only dealers can add materials.' });
        }

        // Find the dealer
        const dealer = dealers.find(d => d.id === req.user.id);
        if (!dealer) {
            if (req.file) {
                fs.unlinkSync(req.file.path);
            }
            return res.status(404).json({ error: 'Dealer not found' });
        }

        // Validate required fields
        const requiredFields = ['name', 'category', 'price', 'unit', 'description'];
        for (const field of requiredFields) {
            if (!req.body[field]) {
                if (req.file) {
                    fs.unlinkSync(req.file.path);
                }
                console.log('[MATERIAL] Missing required field:', field);
                return res.status(400).json({ error: `Missing required field: ${field}` });
            }
        }

        const newMaterial = {
            id: Date.now().toString(),
            name: req.body.name,
            category: req.body.category,
            price: parseFloat(req.body.price),
            unit: req.body.unit,
            description: req.body.description,
            inStock: true,
            supplier: dealer.company,
            dealerId: dealer.id,
            image: req.file ? '/uploads/' + req.file.filename : '/assets/images/placeholder.jpg',
            createdAt: new Date().toISOString()
        };

        console.log('[MATERIAL] Adding new material:', newMaterial);
        materials.push(newMaterial);
        saveData('materials.json', materials);

        res.status(201).json(newMaterial);
    } catch (error) {
        console.error('[MATERIAL] Error adding material:', error);
        if (req.file) {
            try {
                fs.unlinkSync(req.file.path);
            } catch (unlinkError) {
                console.error('Error deleting uploaded file:', unlinkError);
            }
        }
        res.status(500).json({ error: 'Failed to add material: ' + error.message });
    }
});

app.post('/api/dealers', verifyAdminToken, (req, res) => {
    const newDealer = {
        id: Date.now().toString(),
        ...req.body
    };
    dealers.push(newDealer);
    saveData('dealers.json', dealers);
    res.json(newDealer);
});

app.post('/api/workers', verifyAdminToken, (req, res) => {
    const newWorker = {
        id: Date.now().toString(),
        ...req.body
    };
    workers.push(newWorker);
    saveData('workers.json', workers);
    res.json(newWorker);
});

// Registration endpoint with debug logging
app.post('/api/register', (req, res) => {
    try {
        console.log('[REGISTER] Received registration request:', req.body);
        const { username, password, firstName, lastName, email, phone, role, company, address, specialty, experience } = req.body;
        
        // Validate required fields
        if (!username || !password || !firstName || !lastName || !email || !phone || !role) {
            console.log('[REGISTER] Missing required fields');
            return res.status(400).json({ error: 'All required fields must be filled' });
        }

        // Additional validation for workers
        if (role === 'worker' && (!specialty || !experience)) {
            console.log('[REGISTER] Missing worker-specific fields');
            return res.status(400).json({ error: 'Specialty and experience are required for workers' });
        }

        // Check if username already exists in any collection
        if (users.some(u => u.username === username) || 
            workers.some(w => w.username === username) || 
            dealers.some(d => d.username === username)) {
            console.log('[REGISTER] Username already exists:', username);
            return res.status(400).json({ error: 'Username already exists' });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);
        const userId = Date.now().toString();
        const createdAt = new Date().toISOString();

        // Create base user object
        const newUser = {
            id: userId,
            username,
            password: hashedPassword,
            firstName,
            lastName,
            email,
            phone,
            role,
            createdAt
        };

        // Add role-specific fields
        if (role === 'worker') {
            const workerData = {
                ...newUser,
                specialty,
                experience,
                available: true,
                visible: true,
                name: `${firstName} ${lastName}`,
                contact: phone,
                location: address || '',
                rate: '0',
                skills: [],
                description: ''
            };
            workers.push(workerData);
            saveData('workers.json', workers);
            console.log('[REGISTER] Added to workers.json:', username);
        } else if (role === 'dealer') {
            const dealerData = {
                ...newUser,
                company: company || '',
                address: address || ''
            };
            dealers.push(dealerData);
            saveData('dealers.json', dealers);
            console.log('[REGISTER] Added to dealers.json:', username);
        }

        // Always save to users.json
        users.push(newUser);
        saveData('users.json', users);
        console.log('[REGISTER] Added to users.json:', username);

        const token = jwt.sign({ 
            id: userId, 
            role: role,
            username: username 
        }, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({ 
            token,
            username: username,
            role: role,
            firstName: firstName,
            lastName: lastName
        });
    } catch (error) {
        console.error('[REGISTER] Error:', error);
        res.status(500).json({ error: 'Registration failed. Please try again.' });
    }
});

// Login endpoint with clear file-based logic
app.post('/api/login', (req, res) => {
    try {
        const { username, password, role } = req.body;
        
        if (!username || !password || !role) {
            console.log('[LOGIN] Missing required fields');
            return res.status(400).json({ error: 'Missing required fields' });
        }

        console.log('[LOGIN] Attempting login for:', username, 'role:', role);

        let user;
        if (role === 'worker') {
            // For workers, first check workers.json
            user = workers.find(w => w.username === username);
            if (!user) {
                // If not found in workers.json, check users.json
                user = users.find(u => u.username === username && u.role === 'worker');
            }
            if (!user) {
                console.log('[LOGIN] Worker not found:', username);
                return res.status(400).json({ error: 'Invalid username or password' });
            }
        } else if (role === 'dealer') {
            // For dealers, first check dealers.json
            user = dealers.find(d => d.username === username);
            if (!user) {
                // If not found in dealers.json, check users.json
                user = users.find(u => u.username === username && u.role === 'dealer');
            }
            if (!user) {
                console.log('[LOGIN] Dealer not found:', username);
                return res.status(400).json({ error: 'Invalid username or password' });
            }
        } else {
            // For regular users, only check users.json
            user = users.find(u => u.username === username && u.role === 'user');
            if (!user) {
                console.log('[LOGIN] User not found:', username);
                return res.status(400).json({ error: 'Invalid username or password' });
            }
        }

        console.log('[LOGIN] User found:', user.username);

        const validPassword = bcrypt.compareSync(password, user.password);
        if (!validPassword) {
            console.log('[LOGIN] Invalid password for:', username);
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        console.log('[LOGIN] Password verified for:', username);

        const token = jwt.sign({ 
            id: user.id, 
            role: user.role,
            username: user.username 
        }, JWT_SECRET, { expiresIn: '1h' });

        console.log('[LOGIN] Token generated for:', username);

        return res.json({ 
            token,
            username: user.username,
            role: user.role,
            firstName: user.firstName,
            lastName: user.lastName
        });
    } catch (error) {
        console.error('[LOGIN] Error:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// Dealer profile endpoint
app.get('/api/dealer/profile', verifyToken, async (req, res) => {
    try {
        // Find the dealer by ID from the token
        const dealer = dealers.find(d => d.id === req.user.id);
        if (!dealer) {
            return res.status(404).json({ error: 'Dealer not found' });
        }

        // Return dealer data without sensitive information
        const { password, ...dealerProfile } = dealer;
        res.json({
            id: dealerProfile.id,
            name: `${dealerProfile.firstName} ${dealerProfile.lastName}`,
            company: dealerProfile.company,
            email: dealerProfile.email,
            phone: dealerProfile.phone
        });
    } catch (error) {
        console.error('Error fetching dealer profile:', error);
        res.status(500).json({ error: 'Failed to fetch dealer profile' });
    }
});

// Add material endpoint
app.post('/api/materials', authenticateToken, upload.single('image'), (req, res) => {
    try {
        const dealer = dealers.find(d => d.id === req.user.id);
        if (!dealer) {
            return res.status(404).json({ error: 'Dealer not found' });
        }

        const { name, category, price, unit, description } = req.body;
        const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

        const newMaterial = {
            id: Date.now().toString(),
            name,
            category,
            price: parseFloat(price),
            unit,
            description,
            image: imagePath,
            supplier: dealer.company,
            inStock: true,
            createdAt: new Date().toISOString()
        };

        materials.push(newMaterial);
        saveData('materials.json', materials);

        res.status(201).json(newMaterial);
    } catch (error) {
        console.error('Error adding material:', error);
        res.status(500).json({ error: 'Failed to add material' });
    }
});

// Worker Profile and Dashboard Routes
app.post('/api/bookings', verifyToken, async (req, res) => {
    try {
        console.log('Booking request received:', req.body);
        const { workerId, date, projectDetails, address, name, contact } = req.body;
        
        // Validate required fields
        if (!workerId || !date || !projectDetails || !address) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const userId = req.user.id;
        console.log('User ID:', userId);

        // Read existing users data
        const usersPath = path.join(__dirname, 'data', 'users.json');
        let users = [];
        
        try {
            if (fs.existsSync(usersPath)) {
                const data = await fs.promises.readFile(usersPath, 'utf8');
                users = JSON.parse(data);
                console.log('Users data loaded:', users.length, 'users found');
            } else {
                console.log('Users file not found');
                return res.status(500).json({ error: 'Users data file not found' });
            }
        } catch (error) {
            console.error('Error reading users file:', error);
            return res.status(500).json({ error: 'Failed to read users data' });
        }

        // Find user
        const userIndex = users.findIndex(u => u.id === userId);
        console.log('User index:', userIndex);
        if (userIndex === -1) {
            console.log('User not found with ID:', userId);
            return res.status(404).json({ error: 'User not found' });
        }

        // Initialize selectedWorkers array if it doesn't exist
        if (!users[userIndex].selectedWorkers) {
            console.log('Initializing selectedWorkers array');
            users[userIndex].selectedWorkers = [];
        }

        // Add new booking
        const newBooking = {
            workerId,
            date,
            projectDetails,
            address,
            name: name || 'Anonymous',
            contact: contact || 'Not provided',
            status: 'pending'
        };
        console.log('Adding new booking:', newBooking);
        users[userIndex].selectedWorkers.push(newBooking);

        // Save updated data
        try {
            await fs.promises.writeFile(usersPath, JSON.stringify(users, null, 2));
            console.log('Booking saved successfully');
            return res.json({ message: 'Booking created successfully' });
        } catch (error) {
            console.error('Error saving booking:', error);
            return res.status(500).json({ error: 'Failed to save booking data' });
        }
    } catch (error) {
        console.error('Error creating booking:', error);
        return res.status(500).json({ error: 'Failed to create booking: ' + error.message });
    }
});

app.get('/api/worker/profile', verifyToken, (req, res) => {
    try {
        console.log('[WORKER] Profile request received from:', req.user);
        
        // Check if the user is a worker
        if (req.user.role !== 'worker') {
            console.log('[WORKER] Access denied - not a worker role:', req.user.role);
            return res.status(403).json({ error: 'Access denied. Only workers can access this endpoint.' });
        }

        // Find the worker by ID
        const worker = workers.find(w => w.id === req.user.id);
        if (!worker) {
            console.log('[WORKER] Worker not found with ID:', req.user.id);
            return res.status(404).json({ error: 'Worker not found' });
        }

        console.log('[WORKER] Found worker:', worker.username);

        // Get worker's bookings
        const workerBookings = users.reduce((bookings, user) => {
            if (user.selectedWorkers) {
                const userBookings = user.selectedWorkers.filter(booking => booking.workerId === worker.id);
                bookings.push(...userBookings);
            }
            return bookings;
        }, []);

        // Return worker data without sensitive information
        const { password, ...workerData } = worker;
        const response = {
            ...workerData,
            bookings: workerBookings
        };

        console.log('[WORKER] Sending response:', response);
        res.json(response);
    } catch (error) {
        console.error('[WORKER] Error fetching worker profile:', error);
        res.status(500).json({ error: 'Failed to fetch worker profile: ' + error.message });
    }
});

app.put('/api/worker/profile', verifyToken, (req, res) => {
    try {
        console.log('[WORKER] Profile update request received:', req.body);
        console.log('[WORKER] User:', req.user);
        
        // Check if the user is a worker
        if (req.user.role !== 'worker') {
            console.log('[WORKER] Access denied - not a worker role:', req.user.role);
            return res.status(403).json({ error: 'Access denied. Only workers can update their profile.' });
        }

        // Find the worker
        const workerIndex = workers.findIndex(w => w.id === req.user.id);
        if (workerIndex === -1) {
            console.log('[WORKER] Worker not found with ID:', req.user.id);
            return res.status(404).json({ error: 'Worker not found' });
        }

        // Update worker data while preserving existing fields
        const currentWorker = workers[workerIndex];
        const updatedWorker = {
            ...currentWorker,
            name: req.body.name || currentWorker.name,
            specialty: req.body.specialty || currentWorker.specialty,
            contact: req.body.contact || currentWorker.contact,
            location: req.body.location || currentWorker.location,
            experience: req.body.experience || currentWorker.experience,
            rate: req.body.rate || currentWorker.rate,
            skills: req.body.skills ? req.body.skills.split(',').map(skill => skill.trim()).filter(Boolean) : currentWorker.skills,
            description: req.body.description || currentWorker.description,
            updatedAt: new Date().toISOString()
        };

        console.log('[WORKER] Updated worker data:', updatedWorker);

        // Save updated worker data
        workers[workerIndex] = updatedWorker;
        saveData('workers.json', workers);

        // Return updated worker data without sensitive information
        const { password, ...workerData } = updatedWorker;
        console.log('[WORKER] Sending response:', workerData);
        res.json(workerData);
    } catch (error) {
        console.error('[WORKER] Error updating worker profile:', error);
        res.status(500).json({ error: 'Failed to update worker profile: ' + error.message });
    }
});

// Edit material endpoint
app.put('/api/materials/:id', verifyToken, upload.single('image'), async (req, res) => {
    try {
        const materialId = req.params.id;
        const materialIndex = materials.findIndex(m => m.id === materialId);
        
        if (materialIndex === -1) {
            return res.status(404).json({ error: 'Material not found' });
        }

        // Check if the dealer owns this material
        const dealer = dealers.find(d => d.id === req.user.id);
        if (!dealer || materials[materialIndex].supplier !== dealer.company) {
            return res.status(403).json({ error: 'Not authorized to edit this material' });
        }

        // Update material data
        const updatedMaterial = {
            ...materials[materialIndex],
            name: req.body.name || materials[materialIndex].name,
            category: req.body.category || materials[materialIndex].category,
            price: parseFloat(req.body.price) || materials[materialIndex].price,
            unit: req.body.unit || materials[materialIndex].unit,
            description: req.body.description || materials[materialIndex].description,
            inStock: req.body.inStock === 'true',
            image: req.file ? `/uploads/${req.file.filename}` : materials[materialIndex].image
        };

        materials[materialIndex] = updatedMaterial;
        saveData('materials.json', materials);
        
        // Return the updated material
        return res.status(200).json(updatedMaterial);
    } catch (error) {
        console.error('Error updating material:', error);
        return res.status(500).json({ error: 'Failed to update material' });
    }
});

// Worker availability endpoint
app.patch('/api/worker/availability', verifyToken, async (req, res) => {
    try {
        // Check if the user is a worker
        if (req.user.role !== 'worker') {
            return res.status(403).json({ error: 'Access denied. Only workers can update their availability.' });
        }

        const { available } = req.body;
        if (typeof available !== 'boolean') {
            return res.status(400).json({ error: 'Invalid availability status' });
        }

        // Find the worker
        const workerIndex = workers.findIndex(w => w.id === req.user.id);
        if (workerIndex === -1) {
            return res.status(404).json({ error: 'Worker not found' });
        }

        // Update availability
        workers[workerIndex].available = available;
        workers[workerIndex].updatedAt = new Date().toISOString();
        
        // Save changes
        saveData('workers.json', workers);

        res.json({ 
            message: 'Availability updated successfully',
            available 
        });
    } catch (error) {
        console.error('[WORKER] Error updating availability:', error);
        res.status(500).json({ error: 'Failed to update availability' });
    }
});

// Get material details with all dealers who have it
app.get('/api/materials/:id', (req, res) => {
    try {
        const materialId = req.params.id;
        console.log('Looking for material with ID:', materialId);
        
        const material = materials.find(m => {
            const currentId = m.id ? m.id.toString() : '';
            const searchId = materialId.toString();
            console.log('Checking material ID:', currentId, 'against:', searchId);
            return currentId === searchId;
        });
        
        if (!material) {
            console.log('Material not found with ID:', materialId);
            return res.status(404).json({ error: 'Material not found' });
        }

        console.log('Found material:', material);

        // Find all dealers who have this material
        const dealersWithMaterial = dealers.filter(d => {
            const dealerMaterials = d.materials || [];
            return dealerMaterials.includes(materialId.toString());
        });

        console.log('Found dealers with material:', dealersWithMaterial.length);

        // Format dealer information
        const dealerInfo = dealersWithMaterial.map(dealer => ({
            id: dealer.id,
            name: dealer.name || 
                 (dealer.firstName && dealer.lastName ? `${dealer.firstName} ${dealer.lastName}` : '') || 
                 'Not specified',
            company: dealer.company || 'Not specified',
            email: dealer.email || 'Not specified',
            phone: dealer.phone || dealer.contact || 'Not specified',
            address: dealer.address || dealer.location || 'Not specified',
            price: material.price || 0,
            inStock: material.inStock !== undefined ? material.inStock : true
        }));

        // Clean up any undefined or null values
        dealerInfo.forEach(dealer => {
            Object.keys(dealer).forEach(key => {
                if (dealer[key] === undefined || dealer[key] === null) {
                    dealer[key] = 'Not specified';
                }
            });
        });

        console.log('Returning material with dealers:', {
            ...material,
            dealers: dealerInfo
        });

        // Return material with all dealers who have it
        res.json({
            ...material,
            dealers: dealerInfo
        });
    } catch (error) {
        console.error('[MATERIAL] Error fetching material details:', error);
        res.status(500).json({ error: 'Failed to fetch material details' });
    }
});

app.get('/api/dealers/:id', (req, res) => {
    try {
        const dealerId = req.params.id;
        console.log('Looking for dealer with ID:', dealerId);
        
        // Find dealer by ID (handle both string and number IDs)
        const dealer = dealers.find(d => {
            const currentId = d.id ? d.id.toString() : '';
            const searchId = dealerId.toString();
            console.log('Checking dealer ID:', currentId, 'against:', searchId);
            return currentId === searchId;
        });
        
        if (!dealer) {
            console.log('Dealer not found with ID:', dealerId);
            return res.status(404).json({ error: 'Dealer not found' });
        }

        console.log('Found dealer:', dealer);

        // Handle both types of dealer entries
        const dealerData = {
            id: dealer.id,
            name: dealer.name || 
                 (dealer.firstName && dealer.lastName ? `${dealer.firstName} ${dealer.lastName}` : '') || 
                 'Not specified',
            company: dealer.company || 'Not specified',
            email: dealer.email || 'Not specified',
            phone: dealer.phone || dealer.contact || 'Not specified',
            address: dealer.address || dealer.location || 'Not specified',
            workingHours: dealer.workingHours || 'Not specified',
            rating: dealer.rating || 'Not rated',
            materials: dealer.materials || []
        };

        // Clean up any undefined or null values
        Object.keys(dealerData).forEach(key => {
            if (dealerData[key] === undefined || dealerData[key] === null) {
                dealerData[key] = 'Not specified';
            }
        });

        console.log('Returning dealer data:', dealerData);
        res.json(dealerData);
    } catch (error) {
        console.error('[DEALER] Error fetching dealer details:', error);
        res.status(500).json({ error: 'Failed to fetch dealer details' });
    }
});

// Delete material endpoint
app.delete('/api/materials/:id', verifyToken, (req, res) => {
    try {
        const materialId = req.params.id;
        const materialIndex = materials.findIndex(m => m.id === materialId);

        if (materialIndex === -1) {
            return res.status(404).json({ error: 'Material not found' });
        }

        // Only allow the dealer who owns the material or an admin to delete
        const material = materials[materialIndex];
        if (req.user.role !== 'admin' && material.dealerId !== req.user.id) {
            return res.status(403).json({ error: 'Not authorized to delete this material' });
        }

        materials.splice(materialIndex, 1);
        saveData('materials.json', materials);

        res.json({ message: 'Material deleted successfully' });
    } catch (error) {
        console.error('Error deleting material:', error);
        res.status(500).json({ error: 'Failed to delete material' });
    }
});

// Add review endpoint
app.post('/api/reviews', verifyToken, async (req, res) => {
    try {
        const { itemId, itemType, rating, text } = req.body;
        
        if (!itemId || !itemType || !rating || !text) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Get user information
        const user = users.find(u => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

        const review = {
            id: Date.now().toString(),
            userId: user.id,
            userName: user.username,
            rating: parseInt(rating),
            text,
            date: new Date().toISOString()
        };

        // Add review based on item type
        if (itemType === 'material') {
            const materialIndex = materials.findIndex(m => m.id === itemId);
            if (materialIndex === -1) {
                return res.status(404).json({ error: 'Material not found' });
            }

            // Initialize reviews array if it doesn't exist
            if (!materials[materialIndex].reviews) {
                materials[materialIndex].reviews = [];
            }

            // Add the review
            materials[materialIndex].reviews.push(review);

            // Update average rating
            const avgRating = materials[materialIndex].reviews.reduce((sum, r) => sum + r.rating, 0) 
                            / materials[materialIndex].reviews.length;
            materials[materialIndex].rating = parseFloat(avgRating.toFixed(1));

            // Save updated materials data
            saveData('materials.json', materials);
        } else if (itemType === 'worker') {
            const workerIndex = workers.findIndex(w => w.id === itemId);
            if (workerIndex === -1) {
                return res.status(404).json({ error: 'Worker not found' });
            }

            // Initialize reviews array if it doesn't exist
            if (!workers[workerIndex].reviews) {
                workers[workerIndex].reviews = [];
            }

            // Add the review
            workers[workerIndex].reviews.push(review);

            // Update average rating
            const avgRating = workers[workerIndex].reviews.reduce((sum, r) => sum + r.rating, 0) 
                            / workers[workerIndex].reviews.length;
            workers[workerIndex].rating = parseFloat(avgRating.toFixed(1));

            // Save updated workers data
            saveData('workers.json', workers);
        }

        res.status(201).json({ message: 'Review added successfully', review });
    } catch (error) {
        console.error('Error adding review:', error);
        res.status(500).json({ error: 'Failed to add review' });
    }
});

// Order endpoints
app.post('/api/orders', verifyToken, (req, res) => {
    try {
        console.log('[ORDER] Creating new order:', req.body);
        const { materialId, quantity, deliveryAddress, contactNumber } = req.body;

        // Validate required fields
        if (!materialId || !quantity || !deliveryAddress || !contactNumber) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Find the material
        const material = materials.find(m => m.id === materialId);
        if (!material) {
            return res.status(404).json({ error: 'Material not found' });
        }

        // Find the dealer who owns this material
        const dealer = dealers.find(d => d.company === material.supplier);
        if (!dealer) {
            return res.status(404).json({ error: 'Dealer not found for this material' });
        }

        // Create new order
        const newOrder = {
            id: Date.now().toString(),
            userId: req.user.id,
            dealerId: dealer.id,
            materialId,
            quantity: parseInt(quantity),
            totalPrice: material.price * parseInt(quantity),
            status: 'pending',
            orderDate: new Date().toISOString(),
            deliveryAddress,
            contactNumber,
            material: {
                name: material.name,
                category: material.category,
                unit: material.unit
            }
        };

        console.log('[ORDER] New order created:', newOrder);
        orders.push(newOrder);
        saveData('orders.json', orders);

        res.status(201).json(newOrder);
    } catch (error) {
        console.error('[ORDER] Error creating order:', error);
        res.status(500).json({ error: 'Failed to create order' });
    }
});

// Get dealer's orders
app.get('/api/dealer/orders', verifyToken, (req, res) => {
    try {
        console.log('[ORDER] Dealer orders request received:', req.user);
        
        // Check if user is a dealer
        if (req.user.role !== 'dealer') {
            console.log('[ORDER] Access denied - not a dealer role:', req.user.role);
            return res.status(403).json({ error: 'Access denied. Only dealers can view their orders.' });
        }

        // Find the dealer
        const dealer = dealers.find(d => d.id === req.user.id);
        if (!dealer) {
            console.log('[ORDER] Dealer not found:', req.user.id);
            return res.status(404).json({ error: 'Dealer not found' });
        }

        console.log('[ORDER] Found dealer:', dealer.company);

        // Find dealer's orders
        const dealerOrders = orders.filter(order => {
            const material = materials.find(m => m.id === order.materialId);
            return material && material.supplier === dealer.company;
        });

        console.log('[ORDER] Found orders:', dealerOrders.length);

        // Enhance orders with material and user details
        const enhancedOrders = dealerOrders.map(order => {
            const material = materials.find(m => m.id === order.materialId);
            const user = users.find(u => u.id === order.userId);
            
            return {
                ...order,
                material: material ? {
                    name: material.name,
                    category: material.category,
                    unit: material.unit
                } : null,
                customer: user ? {
                    name: user.firstName && user.lastName ? `${user.firstName} ${user.lastName}` : user.username,
                    email: user.email
                } : null
            };
        });

        console.log('[ORDER] Sending enhanced orders:', enhancedOrders);
        res.json(enhancedOrders);
    } catch (error) {
        console.error('[ORDER] Error fetching dealer orders:', error);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

// Update order status
app.patch('/api/orders/:id/status', verifyToken, (req, res) => {
    try {
        const { status } = req.body;
        const orderId = req.params.id;

        // Validate status
        const validStatuses = ['pending', 'processing', 'delivered', 'cancelled'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        // Find the order
        const orderIndex = orders.findIndex(o => o.id === orderId);
        if (orderIndex === -1) {
            return res.status(404).json({ error: 'Order not found' });
        }

        // Check if user is the dealer for this order
        if (req.user.role === 'dealer' && orders[orderIndex].dealerId !== req.user.id) {
            return res.status(403).json({ error: 'Not authorized to update this order' });
        }

        // Update status
        orders[orderIndex].status = status;
        orders[orderIndex].updatedAt = new Date().toISOString();

        saveData('orders.json', orders);
        res.json(orders[orderIndex]);
    } catch (error) {
        console.error('[ORDER] Error updating order status:', error);
        res.status(500).json({ error: 'Failed to update order status' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
}); 
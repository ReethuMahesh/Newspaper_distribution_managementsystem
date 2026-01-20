const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Nodemailer Transporter ---
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "r363523@gmail.com",
    pass: "fxif viqb czdb fdio"
  }
});

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/newspaperDatabase', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('MongoDB connected');
}).catch((err) => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// --- SCHEMAS ---
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, default: 'admin' },
  dob: { type: String },
  gender: { type: String },
  city: { type: String },
  zipcode: { type: String },
  otp: String,
  otpExpires: Date
});
const User = mongoose.model('User', userSchema);

const EmployeeSchema = new mongoose.Schema({
  employeeId: { type:String ,required:true, unique: true },
  empname: String,
  phonenumber: String,
  email: String,
  assignedarea: String,
  empstatus: String
});
const Employee = mongoose.model('Employee', EmployeeSchema);

const SubscriptionSchema = new mongoose.Schema({
  subscriptionId: { type: String, unique: true },
  customerId: String,
  customerName: String,
  address: String,
  contact: String,
  email: { type: String, required: true, unique: true },
  subscriptionType: String,
  newspapers: String,
  startDate: String,
  endDate: String,
  deliveryTime: String,
  status: String,
  price: Number
});
const Subscription = mongoose.model('Subscription', SubscriptionSchema);

const CustomerSchema = new mongoose.Schema({
  customerId: String,
  customerName: String,
  address: String,
  contact: String,
  email: String,
  newspaper: String,
  status: String,
  price: Number
});
const Customer = mongoose.model('Customer', CustomerSchema);

const ReceiptSchema = new mongoose.Schema({
    customerId: String,
    customerName: String,
    newspaper: String,
    price: String,
    receiptGeneratedOn: String,
    timestamp: { type: Date, default: Date.now }
});
const Receipt = mongoose.model('Receipt', ReceiptSchema);

const retailSchema = new mongoose.Schema({
  outletName: String,
  newspaperName: String,
  quantitySold: Number,
  unitPrice: Number,
  saleDate: Date
});
const RetailSale = mongoose.model('RetailSale', retailSchema);

const complaintSchema = new mongoose.Schema({
  customerId: { type: String, required: true },
  customerName: { type: String, required: true },
  complaint: { type: String, required: true },
  status: { type: String, enum: ["open", "pending", "closed"], default: "open" },
  createdAt: { type: Date, default: Date.now },
});
const Complaint = mongoose.model("Complaint", complaintSchema);

// --- MIDDLEWARE SETUP (ORDER MATTERS) ---
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({
  secret: 'your-session-secret',
  resave: false,
  saveUninitialized: false
}));

// --- PROTECT STATIC HTML PAGES ---
const protectedPages = [
  '/dashboard.html',
  '/employees.html',
  '/customers.html',
  '/subscriptions.html',
  '/receipts.html',
  '/complaints.html'
  // Add more as needed
];

app.use((req, res, next) => {
  // Allow public pages
  if (
    req.path === '/login.html' ||
    req.path === '/register.html' ||
    req.path === '/reset-password.html' ||
    req.path === '/forgot-password.html'
  ) {
    return next();
  }
  // Protect sensitive pages
  if (protectedPages.includes(req.path)) {
    if (req.session && req.session.user) {
      return next();
    } else {
      return res.redirect('/login.html');
    }
  }
  next();
});

// --- PROTECT ALL API ENDPOINTS (except login, register, reset) ---
function requireLogin(req, res, next) {
  // Allow login, register, reset endpoints
  if (
    req.path === '/login' ||
    req.path === '/register' ||
    req.path === '/request-reset' ||
    req.path === '/reset-password'
  ) {
    return next();
  }
  if (req.session && req.session.user) {
    return next();
  }
  return res.status(401).send('Unauthorized: Please log in');
}
app.use('/api', requireLogin);

// --- SERVE STATIC FILES ---
app.use(express.static(path.join(__dirname, 'public')));

// --- ADMIN REGISTRATION ROUTE (Allow only if no admin exists) ---
app.post('/api/register', async (req, res) => {
  try {
    const adminExists = await User.findOne({ role: 'admin' });
    if (adminExists) {
      return res.status(403).send('Admin already registered. Registration is disabled.');
    }
    const { email, password, dob, gender, city, zipcode } = req.body;
    if (!email || !password || !dob || !gender || !city || !zipcode) {
      return res.status(400).send('All fields are required.');
    }
    if (password.length < 8) {
      return res.status(400).send('Password must be at least 8 characters.');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({
      email,
      password: hashedPassword,
      role: 'admin',
      dob,
      gender,
      city,
      zipcode
    });
    res.redirect('/login.html');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// --- Login Route: Only seeded admin can login ---
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, role: 'admin' });
    if (!user) {
      return res.status(401).send('Invalid credentials');
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).send('Invalid credentials');
    }
    req.session.user = {
      id: user._id,
      email: user.email,
      role: user.role,
      dob: user.dob,
      gender: user.gender,
      city: user.city,
      zipcode: user.zipcode
    };
    res.redirect('/dashboard.html');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Logout Route
app.get('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// --- OTP & PASSWORD RESET ROUTES ---
app.post('/api/request-reset', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email, role: 'admin' });
  if (!user) return res.status(404).send('Not found');
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpExpires = new Date(Date.now() + 10 * 60 * 1000);
  user.otp = otp;
  user.otpExpires = otpExpires;
  await user.save();
  try {
    await transporter.sendMail({
      from: '"PathraVahak" <r363523@gmail.com>',
      to: user.email,
      subject: 'Your OTP for Password Reset',
      text: `Your OTP is ${otp}. It is valid for 10 minutes.`
    });
    res.send('OTP sent to your email');
  } catch (error) {
    console.error(error);
    res.status(500).send('Failed to send OTP email');
  }
});

app.post('/api/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  const user = await User.findOne({ email, role: 'admin' });
  if (!user || user.otp !== otp || !user.otpExpires || user.otpExpires < Date.now()) {
    return res.status(400).send('Invalid or expired OTP');
  }
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).send('Password must be at least 8 characters');
  }
  user.password = await bcrypt.hash(newPassword, 10);
  user.otp = undefined;
  user.otpExpires = undefined;
  await user.save();
  res.send('Password has been reset');
});

// ==================== EMPLOYEE ROUTE ====================
app.post('/api/employees', async (req, res) => {
  try {
    const { empname, phonenumber, email, assignedarea, empstatus } = req.body;
    if (!empname || !phonenumber || !email || !assignedarea || !empstatus) {
      return res.status(400).send('All fields are required.');
    }
    if (!/^[0-9]{10}$/.test(phonenumber)) {
      return res.status(400).send('Phone number must be 10 digits.');
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).send('Invalid email address.');
    }
    const existingEmployee = await Employee.findOne({ email });
    if (existingEmployee) {
      return res.status(400).send('Employee with this email already exists.');
    }
    const lastEmployee = await Employee.findOne().sort({ employeeId: -1 }).exec();
    let newId = '001';
    if (lastEmployee && lastEmployee.employeeId) {
      const lastIdNum = parseInt(lastEmployee.employeeId, 10);
      newId = String(lastIdNum + 1).padStart(3, '0');
    }
    const newEmployee = new Employee({
      employeeId: newId,
      empname,
      phonenumber,
      email,
      assignedarea,
      empstatus
    });
    await newEmployee.save();
    res.status(201).send('Employee added successfully');
  } catch (err) {
    console.error('Error adding employee:', err);
    res.status(500).send('Server error while adding employee');
  }
});

app.get('/api/employees', async (req, res) => {
  try {
    const employees = await Employee.find().sort({ employeeId: 1 });
    res.json(employees);
  } catch (err) {
    console.error('Fetch error:', err);
    res.status(500).send('Error fetching employees');
  }
});

app.get('/api/employees/latest-id', async (req, res) => {
  try {
    const last = await Employee.findOne().sort({ employeeId: -1 });
    let nextId = '001';
    if (last && last.employeeId) {
      const lastIdNum = parseInt(last.employeeId, 10);
      nextId = String(lastIdNum + 1).padStart(3, '0');
    }
    res.json({ nextId });
  } catch (err) {
    console.error('ID gen error:', err);
    res.status(500).json({ nextId: '001' });
  }
});

const { ObjectId } = require('mongoose').Types;

app.get('/api/employees/:id', async (req, res) => {
  try {
    const employee = await Employee.findById(req.params.id);
    if (!employee) return res.status(404).send('Employee not found');
    res.json(employee);
  } catch (err) {
    console.error('Error fetching employee by ID:', err);
    res.status(500).send('Internal server error');
  }
});

app.put('/api/employees/:id', async (req, res) => {
  try {
    const { empname, phonenumber, email, assignedarea, empstatus } = req.body;
    const updatedEmployee = await Employee.findByIdAndUpdate(
      req.params.id,
      { empname, phonenumber, email, assignedarea, empstatus },
      { new: true }
    );
    if (!updatedEmployee) return res.status(404).send('Employee not found');
    res.send('Employee updated successfully');
  } catch (err) {
    console.error('Error updating employee:', err);
    res.status(500).send('Server error while updating employee');
  }
});

app.delete('/api/employees/:id', async (req, res) => {
  try {
    const deletedEmployee = await Employee.findByIdAndDelete(req.params.id);
    if (!deletedEmployee) return res.status(404).send('Employee not found');
    res.send('Employee deleted successfully');
  } catch (err) {
    console.error('Error deleting employee:', err);
    res.status(500).send('Server error while deleting employee');
  }
});

// ==================== SUBSCRIPTIONS ====================
app.post('/api/subscriptions', async (req, res) => {
  try {
    const {
      subscriptionId, customerId, customerName, address, contact,
      email, subscriptionType, newspapers, startDate, endDate,
      deliveryTime, status, price
    } = req.body;

    const existingSubscription = await Subscription.findOne({ email });
    if (existingSubscription) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    const newSub = new Subscription({
      subscriptionId, customerId, customerName, address, contact,
      email, subscriptionType, newspapers, startDate, endDate,
      deliveryTime, status, price
    });
    await newSub.save();

    const newCustomer = new Customer({
      customerId,
      customerName,
      address,
      contact,
      email,
      newspaper: newspapers,
      status,
      price
    });
    await newCustomer.save();

    res.status(201).json({ message: 'Subscription and Customer added successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error adding subscription and customer' });
  }
});

async function updateExpiredSubscriptions() {
  const today = new Date().toISOString().split('T')[0];
  try {
    const result = await Subscription.updateMany(
      { endDate: { $lt: today }, status: { $ne: 'Expired' } },
      { $set: { status: 'Expired' } }
    );
    console.log(`[${new Date().toLocaleString()}] Expired subscriptions updated: ${result.modifiedCount}`);
  } catch (err) {
    console.error(`[${new Date().toLocaleString()}] Error updating expired subscriptions:`, err);
  }
}
setInterval(updateExpiredSubscriptions, 86400000);

app.get('/api/subscriptions', async (req, res) => {
  try {
    await updateExpiredSubscriptions();
    const subscriptions = await Subscription.find();
    res.json(subscriptions);
  } catch (err) {
    console.error('Error fetching subscriptions:', err);
    res.status(500).send('Failed to fetch subscriptions');
  }
});

// API to get monthly sales count for a specific newspaper
app.get('/api/newspaper-sales/monthly', async (req, res) => {
  const newspaper = req.query.newspaper;
  if (!newspaper) return res.status(400).json({ error: "Newspaper is required" });

  try {
    const pipeline = [
      {
        $match: {
          newspapers: { $regex: new RegExp(`\\b${newspaper}\\b`, 'i') }
        }
      },
      {
        $addFields: {
          startDateObj: { $toDate: "$startDate" }
        }
      },
      {
        $group: {
          _id: {
            year: { $year: "$startDateObj" },
            month: { $month: "$startDateObj" }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { "_id.year": 1, "_id.month": 1 } }
    ];
    const results = await Subscription.aggregate(pipeline);
    const formatted = results.map(r => ({
      month: `${r._id.year}-${String(r._id.month).padStart(2, '0')}`,
      count: r.count
    }));
    res.json(formatted);
  } catch (err) {
    res.status(500).json({ message: 'Failed to aggregate newspaper sales' });
  }
});

app.get('/api/customers/by-id/:customerId', async (req, res) => {
  try {
    const customer = await Customer.findOne({ customerId: req.params.customerId });
    if (!customer) return res.status(404).json({ error: 'Customer not found' });
    res.json({ customerName: customer.customerName });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== MONTHLY REVENUE API ====================
app.get('/api/revenue/monthly', async (req, res) => {
  try {
    const pipeline = [
      {
        $addFields: {
          startDateObj: { $toDate: "$startDate" }
        }
      },
      {
        $group: {
          _id: {
            year: { $year: "$startDateObj" },
            month: { $month: "$startDateObj" }
          },
          totalRevenue: { $sum: "$price" }
        }
      },
      { $sort: { "_id.year": 1, "_id.month": 1 } }
    ];
    const results = await Subscription.aggregate(pipeline);
    const formatted = results.map(r => ({
      month: `${r._id.year}-${String(r._id.month).padStart(2, '0')}`,
      totalRevenue: r.totalRevenue
    }));
    res.json(formatted);
  } catch (err) {
    res.status(500).json({ message: 'Failed to aggregate revenue' });
  }
});

// --- START SERVER ---
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

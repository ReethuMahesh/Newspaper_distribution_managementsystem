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
    user: "r363523@gmail.com", // your admin Gmail address
    pass: "fxif viqb czdb fdio"  // your Gmail app password (not your Gmail login password)
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

// User Schema (only for admin)
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },      // NEW
  phone: { type: String, required: true },
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
  employeeId: { type:String ,required:true, unique: true }, // e.g., "001", "002"
  empname: String,
  phonenumber: String,
  email: String,
  assignedarea: String,
  empstatus: String
});
const Employee = mongoose.model('Employee', EmployeeSchema);

// Subsciption.html
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

// Customers.html
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

// New Schema for storing receipts
const ReceiptSchema = new mongoose.Schema({
    customerId: String,
    customerName: String,
    newspaper: String,
    price: String,  // Store price as string, as in your frontend
    receiptGeneratedOn: String,
    timestamp: { type: Date, default: Date.now } // Add timestamp for sorting
});
const Receipt = mongoose.model('Receipt', ReceiptSchema);


// Define schema and model
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


// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'your-session-secret',
  resave: false,
  saveUninitialized: false
}));
// Session authentication middleware
function requireLogin(req, res, next) {
  if (!req.session.user) {
    // Not logged in or session expired
    return res.status(401).send('Session expired or unauthorized. Please log in.');
  }
  next();
}

app.use(session({
  secret: 'your-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 60 * 1000 } // 30 minutes
}));


app.use(express.static(path.join(__dirname, 'public')));

// --- ADMIN REGISTRATION ROUTE (Allow only if no admin exists) ---
app.post('/api/register', async (req, res) => {
  try {
    const adminExists = await User.findOne({ role: 'admin' });
    if (adminExists) {
      return res.status(403).send('Admin already registered. Registration is disabled.');
    }

    const { name, phone, email, password, dob, gender, city, zipcode } = req.body;

    // Validate all fields
    if (!name || !phone || !email || !password || !dob || !gender || !city || !zipcode) {
      return res.status(400).send('All fields are required.');
    }
    if (password.length < 8) {
      return res.status(400).send('Password must be at least 8 characters.');
    }
    if (!/^[0-9]{10}$/.test(phone)) {
      return res.status(400).send('Phone number must be 10 digits.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      name,
      phone,
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
// Store all user info in session
req.session.user = {
  id: user._id,
  name: user.name,         // <-- ADD THIS
  phone: user.phone,       // <-- ADD THIS
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

  // Generate 6-digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min expiry

  user.otp = otp;
  user.otpExpires = otpExpires;
  await user.save();

  // Send OTP via email
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

//profile-section
app.get('/api/admin/profile', requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const user = await User.findById(userId).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});


app.put('/api/admin/profile', requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;
    // Destructure all editable fields from the request body
    const { name, phone, dob, gender, city, zipcode } = req.body;
    // Build an update object
    const updateFields = { name, phone, dob, gender, city, zipcode };
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $set: updateFields },
      { new: true }
    ).select('-password');
    if (!updatedUser) return res.status(404).json({ error: 'User not found' });
    res.json(updatedUser);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});




// --- REST OF YOUR ROUTES (Employee, Subscription, Customer, Analytics, etc.) ---
// ... (No changes to your other code, keep your existing routes as they are)
// ==================== EMPLOYEE ROUTE ====================

app.post('/api/employees', requireLogin,async (req, res) => {
  try {
    const { empname, phonenumber, email, assignedarea, empstatus } = req.body;

    // --- Server-side validation ---
    if (!empname || !phonenumber || !email || !assignedarea || !empstatus) {
      return res.status(400).send('All fields are required.');
    }
    if (!/^[0-9]{10}$/.test(phonenumber)) {
      return res.status(400).send('Phone number must be 10 digits.');
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).send('Invalid email address.');
    }

    // Check if email already exists
    const existingEmployee = await Employee.findOne({ email });
    if (existingEmployee) {
      return res.status(400).send('Employee with this email already exists.');
    }

    // Generate next 3-digit employeeId
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



// Get all employees
app.get('/api/employees',requireLogin, async (req, res) => {
  try {
    const employees = await Employee.find().sort({ employeeId: 1 });
    res.json(employees);
  } catch (err) {
    console.error('Fetch error:', err);
    res.status(500).send('Error fetching employees');
  }
});

// Get next employee ID
app.get('/api/employees/latest-id', requireLogin,async (req, res) => {
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

// GET employee by ID
app.get('/api/employees/:id', requireLogin,async (req, res) => {
  try {
    const employee = await Employee.findById(req.params.id); // Use Employee model instead of raw DB query
    if (!employee) return res.status(404).send('Employee not found');
    res.json(employee);
  } catch (err) {
    console.error('Error fetching employee by ID:', err);
    res.status(500).send('Internal server error');
  }
});

// ==================== UPDATE EMPLOYEE ====================
app.put('/api/employees/:id',requireLogin, async (req, res) => {
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

// ==================== DELETE EMPLOYEE ====================
app.delete('/api/employees/:id',requireLogin, async (req, res) => {
  try {
    const deletedEmployee = await Employee.findByIdAndDelete(req.params.id);
    if (!deletedEmployee) return res.status(404).send('Employee not found');
    res.send('Employee deleted successfully');
  } catch (err) {
    console.error('Error deleting employee:', err);
    res.status(500).send('Server error while deleting employee');
  }
});


app.post('/api/subscriptions',requireLogin, async (req, res) => {
  try {
    const {
      subscriptionId, customerId, customerName, address, contact,
      email, subscriptionType, newspapers, startDate, endDate,
      deliveryTime, status, price
    } = req.body;

    // Check for existing subscription
    const existingSubscription = await Subscription.findOne({ email });
    if (existingSubscription) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    // Save new subscription
    const newSub = new Subscription({
      subscriptionId, customerId, customerName, address, contact,
      email, subscriptionType, newspapers, startDate, endDate,
      deliveryTime, status, price
    });
    await newSub.save();

    // Save customer
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

    // Send confirmation email (do not block response if fails)
    transporter.sendMail({
      from: '"PathraVahak" <r363523@gmail.com>',
      to: email,
      subject: 'Your Newspaper Subscription is Active!',
      html: `
        <h2>Dear ${customerName},</h2>
        <p>Thank you for subscribing to our newspaper service.</p>
        <p><strong>Subscription Details:</strong></p>
        <ul>
          <li>Subscription Type: ${subscriptionType}</li>
          <li>Newspapers: ${newspapers}</li>
          <li>Start Date: ${startDate}</li>
          <li>End Date: ${endDate}</li>
          <li>Delivery Time: ${deliveryTime}</li>
          <li>Price: ₹${price}</li>
        </ul>
        <p>If you have any questions, feel free to reply to this email.</p>
        <p>Thank you,<br/>PathraVahak Team</p>
      `
    }).catch(emailErr => {
      console.error('Failed to send subscription email:', emailErr);
    });

    // Respond to client
    res.status(201).json({ message: 'Subscription and Customer added successfully' });

  } catch (err) {
    console.error('Error in /api/subscriptions:', err);
    res.status(500).json({ message: 'Error adding subscription and customer' });
  }
});
//montly-summary
app.get('/api/subscriptions/monthly-summary',requireLogin, async (req, res) => {
  try {
    const summary = await Subscription.aggregate([
      {
        // Convert startDate string to Date
        $addFields: {
          startDateObj: {
            $dateFromString: {
              dateString: "$startDate",
              format: "%Y-%m-%d" // Adjust this if your format is different
            }
          }
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m", date: "$startDateObj" } },
          count: { $sum: 1 },
          revenue: { $sum: "$price" }
        }
      },
      { $sort: { "_id": 1 } }
    ]);
    res.json(summary.map(row => ({
      month: row._id,
      count: row.count,
      revenue: row.revenue
    })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to get summary' });
  }
});

app.get('/api/newspaper-sales/monthly', requireLogin,async (req, res) => {
  try {
    const sales = await Subscription.aggregate([
      {
        $addFields: {
          startDateObj: {
            $dateFromString: {
              dateString: "$startDate",
              format: "%Y-%m-%d" // adjust if your format is different
            }
          }
        }
      },
      {
        $group: {
          _id: {
            month: { $dateToString: { format: "%Y-%m", date: "$startDateObj" } },
            newspaper: "$newspapers"
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { "_id.month": 1, "_id.newspaper": 1 } }
    ]);
    res.json(sales.map(s => ({
      month: s._id.month,
      newspaper: s._id.newspaper,
      count: s.count
    })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to get sales data' });
  }
});



app.get('/api/subscriptions/newspaper-summary',requireLogin, async (req, res) => {
  try {
    const summary = await Subscription.aggregate([
      { $unwind: "$newspapers" },
      { $group: {
          _id: "$newspapers",
          count: { $sum: 1 },
          revenue: { $sum: "$price" }
        }
      },
      { $sort: { count: -1 } }
    ]);
    res.json(summary.map(row => ({
      newspaper: row._id,
      count: row.count,
      revenue: row.revenue
    })));
  } catch (err) {
    res.status(500).json({ error: 'Failed to get newspaper summary' });
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

// Automatically check for expired subscriptions every 24 hours
setInterval(updateExpiredSubscriptions, 86400000);


app.get('/api/subscriptions', requireLogin,async (req, res) => {
  try {
    await updateExpiredSubscriptions(); // auto-update
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
    // If your subscriptions.newspapers is a comma-separated string:
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

// Get customer name by customerId
app.get('/api/customers/by-id/:customerId',requireLogin, async (req, res) => {
  try {
    const customer = await Customer.findOne({ customerId: req.params.customerId });
    if (!customer) return res.status(404).json({ error: 'Customer not found' });
    res.json({ customerName: customer.customerName });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});



// ==================== MONTHLY REVENUE API (NEW) ====================
app.get('/api/revenue/monthly',requireLogin, async (req, res) => {
  try {
    // Assumes startDate is stored as "YYYY-MM-DD"
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

// ==================== UPDATE SUBSCRIPTION ====================
// ==================== UPDATE SUBSCRIPTION ====================
app.put('/api/subscriptions/:id',requireLogin, async (req, res) => {
  try {
    const { id } = req.params;

    // Step 1: Update subscription
    const updatedSubscription = await Subscription.findByIdAndUpdate(
      id,
      req.body,
      { new: true }
    );

    if (!updatedSubscription) {
      return res.status(404).send('Subscription not found.');
    }

    // Step 2: Update matching customer
    const customer = await Customer.findOne({ customerId: updatedSubscription.customerId });

    if (customer) {
      // Update the customer document with data from the updated subscription
      customer.customerName = updatedSubscription.customerName;
      customer.address = updatedSubscription.address;
      customer.contact = updatedSubscription.contact;
      customer.email = updatedSubscription.email;
      customer.newspaper = updatedSubscription.newspapers;
      customer.status = updatedSubscription.status;
      customer.price = updatedSubscription.price;
      await customer.save(); // Save the changes to the customer document

    }

    res.status(200).json({
      message: 'Subscription and linked customer updated successfully.',
      subscription: updatedSubscription
    });

  } catch (err) {
    console.error('Error updating subscription and customer:', err);
    res.status(500).send('Server error while updating subscription and customer.');
  }
});


// ==================== DELETE SUBSCRIPTION ====================
// Delete a subscription and update the customer
app.delete('/api/subscriptions/:id', requireLogin,async (req, res) => {
  try {
    const { id } = req.params;

    // Find the subscription to delete
    const subscription = await Subscription.findById(id);
    if (!subscription) {
      return res.status(404).send('Subscription not found.');
    }

    // Get the customerId from the subscription
    const customerId = subscription.customerId;

    // Delete the subscription
    await Subscription.findByIdAndDelete(id);

    // Now check if the customer still has any active subscriptions
    const remainingSubscriptions = await Subscription.find({ customerId });

    if (remainingSubscriptions.length === 0) {
      // If no more subscriptions exist for this customer, delete or reset the customer
      await Customer.findOneAndDelete({ customerId }); // Delete customer record
      // Or alternatively, you can reset customer fields instead of deleting:
      // await Customer.updateOne(
      //   { customerId },
      //   { $set: { newspaper: null, status: null, price: null } }
      // );
    }

    res.status(200).json({ message: 'Subscription deleted and customer updated.' });
  } catch (err) {
    console.error('Error deleting subscription:', err);
    res.status(500).send('Server error while deleting subscription.');
  }
});


// Check if a subscription email already exists
app.get('/api/subscriptions/check-email/:email',requireLogin, async (req, res) => {
  const { email } = req.params;
  try {
    const existingSubscription = await Subscription.findOne({ email });
    if (existingSubscription) {
      return res.json({ exists: true });
    } else {
      return res.json({ exists: false });
    }
  } catch (err) {
    console.error('Error checking email:', err);
    res.status(500).json({ error: 'Server error while checking email' });
  }
});

// --- Update Expired Subscriptions and Send Email on Expiry Day ---
async function updateExpiredSubscriptions() {
  const today = new Date().toISOString().split('T')[0];
  try {
    // Find subscriptions expiring today or before, and not already marked as Expired
    const expiringSubs = await Subscription.find({
      endDate: { $lte: today }, // includes today
      status: { $ne: 'Expired' }
    });

    // Mark them as expired
    const result = await Subscription.updateMany(
      { endDate: { $lte: today }, status: { $ne: 'Expired' } },
      { $set: { status: 'Expired' } }
    );
    console.log(`[${new Date().toLocaleString()}] Expired subscriptions updated: ${result.modifiedCount}`);

    // Send email notifications
    for (const sub of expiringSubs) {
      try {
      await transporter.sendMail({
          from: '"PathraVahak" <r363523@gmail.com>',
          to: sub.email,
          subject: 'Your Subscription Has Expired',
          text: `Dear ${sub.customerName},\n\nYour subscription (ID: ${sub.subscriptionId}) for ${sub.newspapers} has expired on ${sub.endDate}.\n\nPlease renew to continue enjoying our service.\n\n- PathraVahak`
        });
        console.log(`Expiry email sent to ${sub.email}`);
      } catch (mailErr) {
        console.error(`Failed to send expiry email to ${sub.email}:`, mailErr);
      }
    }
  } catch (err) {
    console.error(`[${new Date().toLocaleString()}] Error updating expired subscriptions:`, err);
  }
}

// Automatically check for expired subscriptions every 24 hours
setInterval(updateExpiredSubscriptions, 86400000);
// Also run once on server start
updateExpiredSubscriptions();


// Get all customers
app.get('/api/customers', requireLogin,async (req, res) => {
  try {
    const customers = await Customer.find();
    res.json(customers);
  } catch (err) {
    console.error('Error fetching customers:', err);
    res.status(500).send('Failed to fetch customers');
  }
});

// Find employee by employeeId (not _id)
app.get('/api/employees/by-employeeid/:employeeId',requireLogin, async (req, res) => {
  try {
    const employee = await Employee.findOne({ employeeId: req.params.employeeId });
    if (!employee) return res.status(404).send('Employee not found');
    res.json(employee);
  } catch (err) {
    res.status(500).send('Internal server error');
  }
});

// ==================== RECEIPT ROUTES ====================
app.post('/api/receipts', requireLogin,async (req, res) => {
  try {
    const { customerId, customerName, newspaper, price, receiptGeneratedOn } = req.body;
    const newReceipt = new Receipt({
      customerId,
      customerName,
      newspaper,
      price,
      receiptGeneratedOn
    });
    await newReceipt.save();
    res.status(201).json({ message: 'Receipt stored successfully!' });
  } catch (error) {
    console.error('Error storing receipt:', error);
    res.status(500).json({ message: 'Failed to store receipt.' });
  }
});

app.get('/api/receipts',requireLogin, async (req, res) => {
    try {
        const receipts = await Receipt.find().sort({ timestamp: -1 }); // Sort by timestamp, newest first
        res.json(receipts);
    } catch (error) {
        console.error('Error fetching receipts:', error);
        res.status(500).json({ message: 'Failed to fetch receipts.' });
    }
});

// API route to handle POST requests
app.post('/api/retailoutlets',requireLogin, async (req, res) => {
  try {
      const { outletName, newspaperName, quantitySold, unitPrice, saleDate } = req.body;
      
      // Optional: Add basic validation
      if (!outletName || !newspaperName || !quantitySold || !unitPrice || !saleDate) {
          return res.status(400).json({ message: 'All fields are required.' });
      }

      const newSale = new RetailSale({
          outletName,
          newspaperName,
          quantitySold,
          unitPrice,
          saleDate
      });

      await newSale.save();
      res.json({ message: 'Retail sale data stored successfully!' });
  } catch (err) {
      console.error('Error saving retail sale:', err);
      res.status(500).json({ message: 'Server error.' });
  }
});

// Fetch all retail sales
app.get('/api/retailsales',requireLogin, async (req, res) => {
  try {
    const sales = await RetailSale.find().sort({ saleDate: -1 }); // newest first
    res.json(sales);
  } catch (err) {
    console.error('Error fetching retail sales:', err);
    res.status(500).json({ message: 'Failed to fetch retail sales.' });
  }
});


// API endpoint to fetch customer by ID
app.get('/api/customers/by-id/:customerId',requireLogin, async (req, res) => {
  const customerId = req.params.customerId;
  try {
    const customer = await Customer.findOne({ customerId: customerId });
    if (!customer) {
      return res.status(404).json({ message: 'Customer not found' });
    }
    res.json({ customerName: customer.customerName });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});


// --- API: Get all complaints ---
app.get("/api/complaints",requireLogin, async (req, res) => {
  try {
    const complaints = await Complaint.find().sort({ createdAt: -1 });
    res.json(complaints);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch complaints" });
  }
});

/// --- API: Add a new complaint ---
app.post("/api/complaints", requireLogin,async (req, res) => {
  const { customerId, customerName, complaint, status } = req.body;
  console.log("Received complaint data:", { customerId, customerName, complaint, status }); // Debugging
  if (!customerId || !customerName || !complaint || !status) {
    return res.status(400).json({ error: "All fields are required" });
  }
  try {
    const newComplaint = new Complaint({ customerId, customerName, complaint, status });
    console.log("New complaint object:", newComplaint); // Debugging
    await newComplaint.save();
    console.log("Complaint saved successfully");  // Debugging
    res.status(201).json(newComplaint);
  } catch (err) {
    console.error("Error saving complaint:", err); // Debugging
    res.status(500).json({ error: "Failed to save complaint" });
  }
});


// ==================== COMPLAINTS ROUTES ====================

// Store a new complaint
app.post('/api/complaints',requireLogin, async (req, res) => {
  try {
    const { customerId, customerName, complaint, status } = req.body;
    if (!customerId || !customerName || !complaint) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
    const newComplaint = new Complaint({
      customerId,
      customerName,
      complaint,
      status: status || 'open'
    });
    await newComplaint.save();
    res.status(201).json({ message: 'Complaint stored successfully.' });
  } catch (err) {
    console.error('Error storing complaint:', err);
    res.status(500).json({ message: 'Server error while storing complaint.' });
  }
});

// Fetch all complaints
app.get('/api/complaints',requireLogin, async (req, res) => {
  try {
    const complaints = await Complaint.find().sort({ createdAt: -1 });
    res.json(complaints);
  } catch (err) {
    console.error('Error fetching complaints:', err);
    res.status(500).json({ message: 'Server error while fetching complaints.' });
  }
});

app.get('/api/subscriptions/count',requireLogin, async (req, res) => {
  try {
    const count = await Subscription.countDocuments();
    res.json({ count });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get subscription count' });
  }
});



// Start server
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));